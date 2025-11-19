use alloc::vec::Vec;
use core::{future::poll_fn, task::Poll};

use axerrno::{AxError, AxResult, LinuxError};
use axtask::{
    current,
    future::{block_on, interruptible},
};
use bitflags::bitflags;
use linux_raw_sys::general::{
    __WALL, __WCLONE, __WNOTHREAD, WCONTINUED, WEXITED, WNOHANG, WNOWAIT, WUNTRACED,
};
use starry_core::task::AsThread;
use starry_process::{Pid, Process};
use starry_vm::{VmMutPtr, VmPtr};

use crate::syscall::task::wait_status::WaitStatus;

bitflags! {
    #[derive(Debug)]
    struct WaitOptions: u32 {
        /// Do not block when there are no processes wishing to report status.
        const WNOHANG = WNOHANG;
        /// Report the status of selected processes which are stopped due to a
        /// `SIGTTIN`, `SIGTTOU`, `SIGTSTP`, or `SIGSTOP` signal.
        const WUNTRACED = WUNTRACED;
        /// Report the status of selected processes which have terminated.
        const WEXITED = WEXITED;
        /// Report the status of selected processes that have continued from a
        /// job control stop by receiving a `SIGCONT` signal.
        const WCONTINUED = WCONTINUED;
        /// Don't reap, just poll status.
        const WNOWAIT = WNOWAIT;

        /// Don't wait on children of other threads in this group
        const WNOTHREAD = __WNOTHREAD;
        /// Wait on all children, regardless of type
        const WALL = __WALL;
        /// Wait for "clone" children only.
        const WCLONE = __WCLONE;
    }
}

#[derive(Debug, Clone, Copy)]
enum WaitPid {
    /// Wait for any child process
    Any,
    /// Wait for the child whose process ID is equal to the value.
    Pid(Pid),
    /// Wait for any child process whose process group ID is equal to the value.
    Pgid(Pid),
}

impl WaitPid {
    fn apply(&self, child: &Process) -> bool {
        match self {
            WaitPid::Any => true,
            WaitPid::Pid(pid) => child.pid() == *pid,
            WaitPid::Pgid(pgid) => child.group().pgid() == *pgid,
        }
    }
}

/// Waits for a child process to change state.
///
/// This function implements the `wait4` and `waitpid` syscalls. It suspends the
/// execution of the current process until a child specified by `pid` has changed
/// state.
///
/// # Arguments
/// * `pid` - Specifies the set of child processes to wait for:
///   - `< -1`: Wait for any child process whose process group ID is equal to the
///     absolute value of `pid`.
///   - `-1`: Wait for any child process.
///   - `0`: Wait for any child process whose process group ID is equal to that of
///     the calling process.
///   - `> 0`: Wait for the child whose process ID is equal to `pid`.
/// * `exit_code` - A pointer to an integer where the status information of the
///   terminated child will be stored. The status can be inspected with macros
///   like `WIFEXITED`, `WIFSIGNALED`, etc.
/// * `options` - A bitmask of flags that modify the behavior of the call.
///
/// # State Changes
/// `sys_waitpid` waits for children that have:
/// - **Terminated (Zombie)**: The child has exited. Its PID and exit status are
///   returned. Unless `WNOWAIT` is set, the child process is reaped (its kernel
///   data structures are freed).
/// - **Stopped**: If `WUNTRACED` is set, it returns for children that have been
///   stopped by a signal. The status indicates the signal that caused the stop.
/// - **Continued**: If `WCONTINUED` is set, it returns for stopped children that
///   have been resumed by `SIGCONT`.
///
/// # Blocking Behavior
/// - By default, the call blocks until a child changes state.
/// - If `WNOHANG` is specified and no child has changed state, it returns `0`
///   immediately.
/// - The call can be interrupted by a signal, in which case it will return
///   `Err(AxError::Interrupted)`.
///
/// # Return Value
/// - On success, returns the process ID of the child that changed state.
/// - If `WNOHANG` was specified and no child has changed state, `0` is returned.
/// - On error, returns `Err(AxError)`. Common errors include:
///   - `ECHILD`: The process does not have any children to wait for.
///   - `EINTR`: The call was interrupted by a signal.
///   - `EINVAL`: Invalid options were provided.
pub fn sys_waitpid(pid: i32, exit_code: *mut i32, options: u32) -> AxResult<isize> {
    let options =
        WaitOptions::from_bits(options).ok_or(AxError::Other(LinuxError::EINVAL))?;
    info!("sys_waitpid <= pid: {pid:?}, options: {options:?}");

    // Currently, WNOTHREAD, WALL, and WCLONE are not supported.
    let unsupported = WaitOptions::WNOTHREAD | WaitOptions::WALL | WaitOptions::WCLONE;
    let requested_unsupported =
        WaitOptions::from_bits_truncate(options.bits() & unsupported.bits());
    if !requested_unsupported.is_empty() {
        warn!("waitpid: unsupported options {requested_unsupported:?}");
        return Err(AxError::Unsupported);
    }

    let curr = current();
    let proc_data = &curr.as_thread().proc_data;
    let proc = &proc_data.proc;

    let pid_value = pid; // Save original pid value for non-child check
    let pid = if pid == -1 {
        WaitPid::Any
    } else if pid == 0 {
        WaitPid::Pgid(proc.group().pgid())
    } else if pid > 0 {
        WaitPid::Pid(pid as _)
    } else {
        WaitPid::Pgid(-pid as _)
    };

    // EXPLICIT PID CHECK: Handle non-child tracees (strace -p)
    // When a specific PID is requested, check if we're tracing that process
    // even if it's not a child (needed for PTRACE_ATTACH / strace -p).
    #[cfg(feature = "ptrace")]
    if pid_value > 0 {
        use starry_core::task::get_process_by_pid;

        if let Ok(_target_proc) = get_process_by_pid(pid_value as _) {
            // Check if current process is the tracer of this target
            if starry_ptrace::is_tracer_of(proc.pid(), pid_value as _) {
                // We are tracing this process - check for ptrace stop
                if let Some(status) = starry_ptrace::check_ptrace_stop(pid_value as _) {
                    info!("sys_waitpid: found ptrace-stopped non-child tracee {} (status=0x{:x})",
                          pid_value, status);
                    if let Some(exit_code_ptr) = exit_code.nullable() {
                        let _ = exit_code_ptr.vm_write(status);
                    }
                    return Ok(pid_value as isize);
                }

                // No stop ready - handle WNOHANG or block
                if options.contains(WaitOptions::WNOHANG) {
                    info!("sys_waitpid: non-child tracee {} not stopped, WNOHANG returning 0", pid_value);
                    return Ok(0);
                }

                // Block until tracee has an event.
                // The ptrace subsystem wakes the *tracer's* event queue, so we
                // must listen on our own `child_exit_event`, not the target's.
                info!("sys_waitpid: blocking on non-child tracee {}", pid_value);
                let status = block_on(interruptible(poll_fn(|cx| {
                    // Register waker on the CURRENT process's event set.
                    proc_data.child_exit_event.register(cx.waker());

                    // Check again for ptrace stop. This is necessary to handle
                    // the race condition where the tracee stops *after* the initial
                    // check but *before* we start polling.
                    if let Some(status) = starry_ptrace::check_ptrace_stop(pid_value as _) {
                        info!("sys_waitpid: non-child tracee {} stopped while blocking (status=0x{:x})",
                                pid_value, status);
                        Poll::Ready(status)
                    } else {
                        // Also check if the tracee has exited.
                        // We need to get the process data again here because it might have changed.
                        if let Ok(target_proc) = starry_core::task::get_process_by_pid(pid_value as _) {
                            if target_proc.is_zombie() {
                                info!("sys_waitpid: non-child tracee {} exited while blocking", pid_value);
                                let zombie_info = target_proc.get_zombie_info().expect("Zombie process must have zombie info");
                                let wait_status = if let Some(signo) = zombie_info.signal {
                                    WaitStatus::signaled(signo, zombie_info.core_dumped)
                                } else {
                                    WaitStatus::exited(zombie_info.exit_code)
                                };
                                Poll::Ready(wait_status.as_raw())
                            } else {
                                Poll::Pending
                            }
                        } else {
                            // If get_process_by_pid fails, the process no longer exists.
                            // This implies it has exited.
                            // The SIGCHLD should have already woken us up, and the is_zombie() check
                            // above should have caught it. If we reach here, it's likely a race
                            // condition where the process exited and was reaped before we could check.
                            // For now, we'll treat this as pending and rely on SIGCHLD to eventually
                            // cause a successful return from waitpid in the main loop.
                            Poll::Pending
                        }
                    }
                })))?;

                if let Some(exit_code_ptr) = exit_code.nullable() {
                    let _ = exit_code_ptr.vm_write(status);
                }
                return Ok(pid_value as isize);
            }
        }
    }

    // FIXME: add back support for WALL & WCLONE, since ProcessData may drop before
    // Process now.

    // Check that we have children to wait for
    let initial_children = proc
        .children()
        .into_iter()
        .filter(|child| pid.apply(child))
        .collect::<Vec<_>>();
    if initial_children.is_empty() {
        return Err(AxError::Other(LinuxError::ECHILD));
    }

    let check_children = || -> AxResult<Option<isize>> {
        // Re-fetch children on each check to get current state
        let children = proc
            .children()
            .into_iter()
            .filter(|child| pid.apply(child))
            .collect::<Vec<_>>();

        info!("sys_waitpid: checking {} children", children.len());

        if children.is_empty() {
            // All children have been reaped
            info!("sys_waitpid: no children, returning ECHILD");
            return Err(AxError::Other(LinuxError::ECHILD));
        }
        // Priority 1: Check for continued children (WCONTINUED)
        // This must come before zombie check because a process can be in Continued state
        // briefly before becoming a zombie (e.g., stopped process receives SIGCONT then exits).
        if options.contains(WaitOptions::WCONTINUED)
            && let Some(continued_child) = children.iter().find(|child| child.is_continued())
        {
            info!("sys_waitpid: found continued child {}", continued_child.pid());
            let wait_status = WaitStatus::continued();
            if let Some(exit_code_ptr) = exit_code.nullable() {
                let _ = exit_code_ptr.vm_write(wait_status.as_raw());
            }
            // Acknowledge that parent has been notified
            continued_child.ack_continued();
            return Ok(Some(continued_child.pid() as isize));
        }

        // Priority 2: Check for ptrace-stopped children (BEFORE signal-stops)
        // Ptrace stops are NOT gated by WUNTRACED - they are always visible to the tracer.
        // The check_ptrace_stop() function handles tracer verification.
        #[cfg(feature = "ptrace")]
        {
            for child in children.iter() {
                // check_ptrace_stop() returns Some(status) only if:
                // 1. The child is in ptrace-stop state
                // 2. The child is being traced by the current process (caller)
                // 3. The stop hasn't been reported yet (stop_reported = false)
                // It also marks the stop as reported to prevent duplicates.
                if let Some(ptrace_status) = starry_ptrace::check_ptrace_stop(child.pid()) {
                    info!(
                        "sys_waitpid: found ptrace-stopped child {} (status=0x{:x})",
                        child.pid(),
                        ptrace_status
                    );
                    if let Some(exit_code_ptr) = exit_code.nullable() {
                        let _ = exit_code_ptr.vm_write(ptrace_status);
                    }
                    // check_ptrace_stop() already marked stop as reported
                    return Ok(Some(child.pid() as isize));
                }
            }
        }

        // Priority 3: Check for signal-stopped children (WUNTRACED)
        // Only report signal-stops (not ptrace-stops) when WUNTRACED is set.
        if options.contains(WaitOptions::WUNTRACED)
            && let Some(stopped_child) = children.iter().find(|child| {
                // Only report signal-stops, not ptrace-stops
                // is_signal_stopped() checks is_ptrace_stopped == false
                child.is_signal_stopped() && child.stopped_unacked()
            })
            && let Some(stopping_signal) = stopped_child.get_stop_signal()
        {
            info!("sys_waitpid: found signal-stopped child {} (signal {})", stopped_child.pid(), stopping_signal);
            let wait_status = WaitStatus::stopped(stopping_signal);
            if let Some(exit_code_ptr) = exit_code.nullable() {
                let _ = exit_code_ptr.vm_write(wait_status.as_raw());
            }
            // Acknowledge that parent has been notified of stop
            stopped_child.ack_stopped();
            return Ok(Some(stopped_child.pid() as isize));
        }

        // Check for any zombie children
        if let Some(child) = children.iter().find(|child| child.is_zombie()) {
            info!("sys_waitpid: found zombie child {}", child.pid());
            // Get zombie termination info before freeing
            let zombie_info = child.get_zombie_info().ok_or(AxError::Other(LinuxError::ECHILD))?;

            if !options.contains(WaitOptions::WNOWAIT) {
                child.free();
            }

            // Encode status based on how the process terminated
            let wait_status = if let Some(signo) = zombie_info.signal {
                WaitStatus::signaled(signo, zombie_info.core_dumped)
            } else {
                WaitStatus::exited(zombie_info.exit_code)
            };

            if let Some(exit_code_ptr) = exit_code.nullable() {
                let _ = exit_code_ptr.vm_write(wait_status.as_raw());
            }
            info!("sys_waitpid: returning pid {}", child.pid());
            return Ok(Some(child.pid() as isize));
        }

        // When WNOHANG is specified, return immediately if no children are ready
        if options.contains(WaitOptions::WNOHANG) {
            info!("sys_waitpid: WNOHANG set, no ready children, returning 0");
            return Ok(Some(0));
        }

        info!("sys_waitpid: no ready children, will block");
        Ok(None)
    };

    let result = block_on(interruptible(poll_fn(|cx| {
        // Register waker BEFORE checking to avoid lost wakeup race
        proc_data.child_exit_event.register(cx.waker());

        match check_children().transpose() {
            Some(res) => {
                info!("sys_waitpid: poll returning Ready");
                Poll::Ready(res)
            }
            None => {
                info!("sys_waitpid: poll returning Pending (will block)");
                Poll::Pending
            }
        }
    })))?;

    info!("sys_waitpid => {result:?}");
    result
}
