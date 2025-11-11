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
        // ptrace: check trace-stopped processes first (children or traced processes)
        #[cfg(feature = "ptrace")]
        {
            // Check children for ptrace stops
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
                }
            }
        }

        // Check for zombie children
        if let Some(child) = children.iter().find(|child| child.is_zombie()) {
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
