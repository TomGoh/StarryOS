use alloc::{sync::Arc, vec::Vec};
use core::{
    fmt::{Display, Formatter, Result},
    future::poll_fn,
    task::Poll,
};

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
use starry_signal::Signo;
use starry_vm::{VmMutPtr, VmPtr};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Eq, Ord)]
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

/// Wait Status
enum WaitStatus {
    /// Normal exit status, only exit code would be reported
    Exited(i32),
    /// Signal-terminated status, signal number and core dump flag would be
    /// reported
    Signaled { signal: Signo, core_dumped: bool },
    /// Stopped status, signal number would be reported
    Stopped(Signo),
    /// Cotinued status, `0xffff` would be reported
    Continued,
}

impl WaitStatus {
    /// Encodes the wait status into POSIX-compliant format for `waitpid`
    /// syscall.
    ///
    /// This function converts the semantic wait status into the integer
    /// encoding required by POSIX IEEE Std 1003.1-2024. The encoding
    /// follows the traditional UNIX implementation that ensures exactly one
    /// of the WIFEXITED, WIFSIGNALED, WIFSTOPPED, or WIFCONTINUED macros
    /// evaluates to true for any given status.
    ///
    /// # Encoding Format
    ///
    /// - **Normal Exit** (`Exited(code)`): ```text Format: (exit_code & 0xFF)
    ///   << 8 Decoded by: WIFEXITED(status) && WEXITSTATUS(status) == 5 ```
    ///
    /// - **Signal Termination** (`Signaled { signal, core_dumped: false }`):
    ///   ```text Format: signal_number Decoded by: WIFSIGNALED(status) &&
    ///   WTERMSIG(status) == 15 ```
    ///
    /// - **Signal Termination with Core Dump** (`Signaled { signal,
    ///   core_dumped: true }`): ```text Format: signal_number | 0x80 Decoded
    ///   by: WIFSIGNALED(status) && WTERMSIG(status) == 11 && WCOREDUMP(status)
    ///   ```
    ///
    /// - **Stopped by Signal** (`Stopped(signal)`): ```text Format:
    ///   (signal_number << 8) | 0x7F Decoded by: WIFSTOPPED(status) &&
    ///   WSTOPSIG(status) == 20 ```
    ///
    /// - **Continued by SIGCONT** (`Continued`): ```text Format: 0xFFFF Decoded
    ///   by: WIFCONTINUED(status) ```
    ///
    /// # POSIX Compliance
    ///
    /// The encoding guarantees that exactly one of the following predicates is
    /// true:
    /// - `(status & 0x7F) == 0` → Normal exit (WIFEXITED)
    /// - `(status & 0x7F) != 0 && (status & 0xFF) != 0x7F` → Signal termination
    ///   (WIFSIGNALED)
    /// - `(status & 0xFF) == 0x7F && status != 0xFFFF` → Stopped (WIFSTOPPED)
    /// - `status == 0xFFFF` → Continued (WIFCONTINUED)
    ///
    /// # Returns
    ///
    /// An `i32` status value that can be decoded by standard POSIX wait macros
    /// (WIFEXITED, WIFSIGNALED, WIFSTOPPED, WIFCONTINUED, etc.) in user space.
    fn encode(&self) -> i32 {
        match self {
            Self::Exited(code) => (*code & 0xff) << 8,
            Self::Signaled {
                signal,
                core_dumped,
            } => {
                let sig_num = *signal as i32;
                if *core_dumped {
                    sig_num | 0x80
                } else {
                    sig_num
                }
            }
            Self::Stopped(signal) => ((*signal as i32) << 8) | 0x7f,
            Self::Continued => 0xffff,
        }
    }
}

impl From<WaitStatus> for i32 {
    fn from(status: WaitStatus) -> i32 {
        status.encode()
    }
}

impl Display for WaitStatus {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result {
        match self {
            WaitStatus::Exited(code) => write!(f, "exited with code {}", code),
            WaitStatus::Signaled {
                signal,
                core_dumped,
            } => {
                write!(f, "killed by signal {:?}", signal)?;
                if *core_dumped {
                    write!(f, " (core dumped)")?;
                }
                Ok(())
            }
            WaitStatus::Stopped(signal) => write!(f, "stopped by signal {:?}", signal),
            WaitStatus::Continued => write!(f, "continued"),
        }
    }
}

pub fn sys_waitpid(pid: i32, exit_code: *mut i32, options: u32) -> AxResult<isize> {
    // Validate options argument - return EINVAL if contains unknown flags
    let options = WaitOptions::from_bits(options).ok_or_else(|| {
        warn!("sys_waitpid: invalid options 0x{:x}", options);
        AxError::from(LinuxError::EINVAL)
    })?;

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
    if children.is_empty() {
        return Err(AxError::from(LinuxError::ECHILD));
    }

    let check_children = || {
        for child in children.iter() {
            // For each waitable child, call the `wait_consider_task` function to execute
            // the exact wait logic.
            if let Some((child_pid, wait_status)) = wait_consider_task(child, options)? {
                if let Some(status_ptr) = exit_code.nullable() {
                    status_ptr.vm_write(wait_status)?;
                }
                return Ok(Some(child_pid as _));
            }
        }

        if options.contains(WaitOptions::WNOHANG) {
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

/// Considers a child process for wait status reporting.
///
/// This function implements the core wait logic by checking the child process
/// state and determining if it has waitable status information to report.
/// It follows the Linux kernel's `wait_consider_task()` pattern.
///
/// This function acts as the "centralized assembly" point in the distributed
/// storage design:
/// - Reads state and raw exit code from `Process` layer (zombie/stopped/running
///   state)
/// - Reads signal events from `ProcessSignalManager` layer (stop/continue
///   events)
/// - Assembles the final POSIX wait status using `WaitStatus::encode()` based
///   on infomation extracted in the previous two steps

/// # Priority Order
///
/// The function checks child states in the following priority order:
/// 1. **Stop/Continue events** - Check for unreported stop/continue events
///    first, even if the process has since become a zombie
/// 2. **Zombie** (terminated) - Report exit status only if no unreported
///    stop/continue events exist
///
/// This ordering ensures that all state transitions are reported in the order
/// they occurred, matching Linux semantics. A process that stops, continues,
/// then exits must report the continue event before the exit event.
///
/// # Arguments
///
/// * `child` - Reference to the child process to check
/// * `options` - Wait options controlling which states to report (WEXITED,
///   WUNTRACED, WCONTINUED)
///
/// # Returns
///
/// * `Ok(Some((pid, status)))` - Child has waitable status; returns PID and
///   encoded wait status
/// * `Ok(None)` - Child exists but has no waitable status matching the options
/// * `Err(_)` - Error occurred while checking child status
fn wait_consider_task(child: &Arc<Process>, options: WaitOptions) -> AxResult<Option<(Pid, i32)>> {
    // Check for unreported stop/continue events first, even if process is now
    // zombie. This matches Linux behavior where stop/continue events must be
    // reported before exit status if they occurred during the child's lifetime.

    if let Some(result) = wait_task_stopped(child, options)? {
        return Ok(Some(result));
    }

    if let Some(result) = wait_task_continued(child, options)? {
        return Ok(Some(result));
    }

    // Only report zombie status if there are no unreported stop/continue events
    if let Some(result) = wait_task_zombie(child, options)? {
        return Ok(Some(result));
    }

    Ok(None)
}

/// Checks if a zombie (terminated) child process has waitable status.
///
/// This function handles the wait logic for terminated child processes. It
/// reads the exit information from the process and encodes it into POSIX wait
/// status format, distinguishing between normal exits and signal-caused
/// terminations.
///
/// This check is mandatory no matter which option for waitpid is set or even
/// none of them is set.
///
/// If `WNOWAIT` is not set, the zombie process is reaped (freed) after reading
/// its status. With `WNOWAIT`, the zombie remains and can be waited on again.
///
/// # Arguments
///
/// * `child` - Reference to the child process to check
/// * `options` - Wait options; terminated children are always reported for
///   waitpid()
///
/// # Returns
///
/// * `Ok(Some((pid, status)))` - Child is zombie; returns PID and exit status
/// * `Ok(None)` - Child is not zombie, or has unknown signal number
/// * `Err(_)` - Should not occur in current implementation
fn wait_task_zombie(child: &Arc<Process>, options: WaitOptions) -> AxResult<Option<(Pid, i32)>> {
    if !child.is_zombie() {
        return Ok(None);
    }

    let pid = child.pid();
    let raw_exit_code = child.exit_code();

    // The exit_code uses a discriminated encoding to distinguish exit types:
    // - Normal exit:     (exit_code << 8)      → low 7 bits are 0
    // - Signal term:     signal_num            → low 7 bits contain signal number
    // - Signal + core:   signal_num | 0x80     → bit 7 set, low 7 bits contain
    //   signal
    //
    // This encoding allows simple discrimination via (value & 0x7F == 0) check.
    let status = if raw_exit_code & 0x7F == 0 {
        // Normal exit: extract the exit code from high bits
        let exit_code = (raw_exit_code >> 8) & 0xFF;
        WaitStatus::Exited(exit_code).encode()
    } else {
        // Signal termination: extract signal number and core dump flag
        let signal_num = (raw_exit_code & 0x7F) as u8;
        let core_dumped = (raw_exit_code & 0x80) != 0;

        if let Some(signal) = Signo::from_repr(signal_num) {
            WaitStatus::Signaled {
                signal,
                core_dumped,
            }
            .encode()
        } else {
            warn!(
                "Process {} has unknown signal {} when terminated",
                pid, signal_num
            );
            return Ok(None);
        }
    };

    if !options.contains(WaitOptions::WNOWAIT) {
        child.free();
    }

    Ok(Some((pid, status)))
}

/// Checks if a stopped child process has unreported stop event.
///
/// This function handles the wait logic for processes that have been stopped
/// by job control signals (SIGSTOP, SIGTSTP, SIGTTIN, SIGTTOU). It implements
/// the event-based reporting model where stop events are recorded when they
/// occur and consumed when reported via wait.
///
/// If `WNOWAIT` is not set, the stopped would be consumed(removed) after
/// reading its status. With `WNOWAIT`, the stoppage remains and can be waited
/// on again.
///
/// # Arguments
///
/// * `child` - Reference to the child process to check
/// * `options` - Wait options; requires `WUNTRACED` flag to report stopped
///   children
///
/// # Returns
///
/// * `Ok(Some((pid, status)))` - Child has unreported stop event
/// * `Ok(None)` - Child has no unreported stop event or `WUNTRACED` not set
/// * `Err(_)` - Failed to decode signal number
fn wait_task_stopped(child: &Arc<Process>, options: WaitOptions) -> AxResult<Option<(Pid, i32)>> {
    if !options.contains(WaitOptions::WUNTRACED) {
        return Ok(None);
    }

    let child_pid = child.pid();

    // Check for unreported stop event, regardless of current process state.
    // A process may have been stopped, then continued, then exited - but we still
    // need to report the stop event if it hasn't been consumed yet.
    //
    // Signal events are stored in the Process's ThreadGroup,
    // which persists until the zombie is reaped.
    if let Some(signal_num) = child.peek_pending_stop_event() {
        let signal = Signo::from_repr(signal_num).ok_or_else(|| {
            warn!(
                "Process {} has unknown stop signal {}",
                child_pid, signal_num
            );
            AxError::from(LinuxError::EINVAL)
        })?;
        let status_code = WaitStatus::Stopped(signal).encode();

        if !options.contains(WaitOptions::WNOWAIT) {
            child.consume_stop_event();
        }

        Ok(Some((child_pid, status_code)))
    } else {
        Ok(None)
    }
}

/// Checks if a continued child process has unreported continue event.
///
/// This function handles the wait logic for processes that have been continued
/// from a job control stop by receiving SIGCONT. Like stop events, continue
/// events follow an event-based reporting model.
///
/// If `WNOWAIT` is not set, the continuation would be consumed(removed) after
/// reading its status. With `WNOWAIT`, the continuation remains and can be
/// waited on again.
///
/// # Arguments
///
/// * `child` - Reference to the child process to check
/// * `options` - Wait options; requires `WCONTINUED` flag to report continued
///   children
///
/// # Returns
///
/// * `Ok(Some((pid, status)))` - Child has unreported continue event
/// * `Ok(None)` - Child has no unreported continue event or `WCONTINUED` not set
/// * `Err(_)` - Should not occur in current implementation
fn wait_task_continued(child: &Arc<Process>, options: WaitOptions) -> AxResult<Option<(Pid, i32)>> {
    if !options.contains(WaitOptions::WCONTINUED) {
        return Ok(None);
    }

    let child_pid = child.pid();

    // Check for unreported continue event, regardless of current process state.
    // A process may have been continued and then exited - but we still need to
    // report the continue event if it hasn't been consumed yet.
    //
    // Signal events are stored in the Process's ThreadGroup,
    // which persists until the zombie is reaped.
    if child.peek_pending_cont_event() {
        let status_code = WaitStatus::Continued.encode();

        if !options.contains(WaitOptions::WNOWAIT) {
            child.consume_cont_event();
        }

        Ok(Some((child_pid, status_code)))
    } else {
        Ok(None)
    }
}
