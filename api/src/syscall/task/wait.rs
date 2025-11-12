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

pub fn sys_waitpid(pid: i32, exit_code: *mut i32, options: u32) -> AxResult<isize> {
    let options = WaitOptions::from_bits_truncate(options);
    info!("sys_waitpid <= pid: {pid:?}, options: {options:?}");

    let curr = current();
    let proc_data = &curr.as_thread().proc_data;
    let proc = &proc_data.proc;

    let pid = if pid == -1 {
        WaitPid::Any
    } else if pid == 0 {
        WaitPid::Pgid(proc.group().pgid())
    } else if pid > 0 {
        WaitPid::Pid(pid as _)
    } else {
        WaitPid::Pgid(-pid as _)
    };

    // FIXME: add back support for WALL & WCLONE, since ProcessData may drop before
    // Process now.
    let children = proc
        .children()
        .into_iter()
        .filter(|child| pid.apply(child))
        .collect::<Vec<_>>();

    // Early return if no children and not waiting for a specific PID
    // (can't be waiting on a traced process if not waiting for specific PID)
    if children.is_empty() {
        #[cfg(feature = "ptrace")]
        {
            // Only check tracing if waiting for a SPECIFIC PID (not -1 or process group)
            if let WaitPid::Pid(target_pid) = pid {
                // Check if we're tracing this specific PID (for strace -p)
                if starry_ptrace::is_tracing(target_pid) {
                    // We're tracing this PID, allow waiting even though it's not a child
                    // (will be handled in the polling loop below)
                } else {
                    // Not a child and not tracing it
                    return Err(AxError::Other(LinuxError::ECHILD));
                }
            } else {
                // Waiting for any child (-1) or process group, but have no children
                return Err(AxError::Other(LinuxError::ECHILD));
            }
        }
        #[cfg(not(feature = "ptrace"))]
        {
            return Err(AxError::Other(LinuxError::ECHILD));
        }
    }

    // Determine if we're waiting on a traced non-child process
    let waiting_on_traced = children.is_empty();

    let check_children = || {
        // ptrace: Priority 1 - Check trace-stopped processes first (children or traced processes)
        // This ensures tracers receive ptrace events before parents see normal state changes
        #[cfg(feature = "ptrace")]
        {
            // Check children for ptrace stops (syscall-enter-stop, signal-delivery-stop, etc.)
            debug!("[PTRACE-DEBUG] waitpid checking {} children for ptrace stops", children.len());
            for child in &children {
                if let Some(status) = starry_ptrace::check_ptrace_stop(child.pid()) {
                    debug!("[PTRACE-DEBUG] waitpid: returning ptrace stop for pid={} status=0x{:x}", child.pid(), status);
                    if let Some(exit_code) = exit_code.nullable() {
                        exit_code.vm_write(status)?;
                    }
                    return Ok(Some(child.pid() as _));
                }
            }

            // If waiting on a traced (non-child) process, check for ptrace stop
            if waiting_on_traced {
                if let WaitPid::Pid(target_pid) = pid {
                    debug!("[PTRACE-DEBUG] waitpid: checking traced non-child pid={} for ptrace stop", target_pid);
                    if let Some(status) = starry_ptrace::check_ptrace_stop(target_pid) {
                        debug!("[PTRACE-DEBUG] waitpid: traced process pid={} in ptrace-stop, status=0x{:x}", target_pid, status);
                        if let Some(exit_code) = exit_code.nullable() {
                            exit_code.vm_write(status)?;
                        }
                        return Ok(Some(target_pid as _));
                    }

                    // Also check if the traced non-child process has exited (zombie state)
                    // A traced process exiting does not generate a ptrace-stop event; it just becomes a zombie.
                    // The tracer must handle it first (Stage 1: status reporting), then let the parent
                    // clean up resources (Stage 2: freeing). If we don't check here, the tracer would
                    // never be notified of the exit.
                    use starry_core::task::get_process_data;
                    if let Ok(proc_data) = get_process_data(target_pid) {
                        if proc_data.proc.is_zombie() {

                            // Stage 1: Tracer handles the exit notification and clears tracing state
                            // This allows the real parent to proceed with Stage 2 (resource cleanup)
                            debug!("[PTRACE-DEBUG] waitpid: traced non-child pid={} is zombie, exit_code=0x{:x}", target_pid, proc_data.proc.exit_code());
                            // clear the trace status
                            if let Ok(st) = starry_ptrace::ensure_state_for_pid(target_pid) {
                                st.with_mut(|s| {
                                    s.being_traced = false;
                                    s.tracer = None;
                                });
                                debug!("[PTRACE-DEBUG] waitpid: cleared tracing state for pid={}", target_pid);
                            }
                            // write back the exit code if not null
                            if let Some(exit_code) = exit_code.nullable() {
                                exit_code.vm_write(proc_data.proc.exit_code())?;
                            }

                            // Stage 2: Decide who frees resources
                            // - If parent exists: Wake parent to let it reap (free) the zombie
                            // - If no parent: Tracer must free to prevent resource leak
                            // WNOWAIT: Don't free, just peek at the status
                            if !options.contains(WaitOptions::WNOWAIT) {
                                if let Some(parent) = proc_data.proc.parent() {
                                    debug!("[PTRACE-DEBUG] waitpid: traced zombie pid={} has parent pid={}, waking parent", target_pid, parent.pid());
                                    // Wake the parent so it can reap the child
                                    if let Ok(parent_data) = get_process_data(parent.pid()) {
                                        parent_data.child_exit_event.wake();
                                    }
                                } else {
                                    // No parent, safe to free
                                    proc_data.proc.free();
                                }
                            }

                            return Ok(Some(target_pid as _));
                        }
                    }
                }
            }
        }

        if let Some(child) = children.iter().find(|child| {
            if !child.is_zombie() {
                return false;
            }
            // Priority 2 - Check for zombie children (after ptrace events handled above) when ptrace enabled
            // If child is traced by another process (not us), skip it for now
            // The tracer must handle it first (Stage 1: status reporting & clearing trace state)
            // before we can proceed with Stage 2 (resource cleanup)
            #[cfg(feature = "ptrace")]
            {
                let curr_pid = proc.pid();
                if let Ok(tracer_pid) = starry_ptrace::get_tracer(child.pid()) {
                    if tracer_pid != curr_pid {
                        debug!("waitpid: child pid={} is zombie but traced by pid={}, skipping for parent", child.pid(), tracer_pid);
                        return false;
                    }
                }
            }
            true
        }) {
            debug!("waitpid: child pid={} is zombie, exit_code=0x{:x}", child.pid(), child.exit_code());
            if !options.contains(WaitOptions::WNOWAIT) {
                child.free();
            }
            if let Some(exit_code) = exit_code.nullable() {
                exit_code.vm_write(child.exit_code())?;
            }
            Ok(Some(child.pid() as _))
        } else if options.contains(WaitOptions::WNOHANG) {
            Ok(Some(0))
        } else {
            Ok(None)
        }
    };

    block_on(interruptible(poll_fn(|cx| {
        match check_children().transpose() {
            Some(res) => Poll::Ready(res),
            None => {
                proc_data.child_exit_event.register(cx.waker());
                Poll::Pending
            }
        }
    })))?
}
