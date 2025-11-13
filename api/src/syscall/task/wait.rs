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

use crate::syscall::task::wait_status::*;

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
    let options =
        WaitOptions::from_bits(options).ok_or(AxError::Other(LinuxError::EINVAL))?;
    info!("sys_waitpid <= pid: {pid:?}, options: {options:?}");

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
        return Err(AxError::Other(LinuxError::ECHILD));
    }

    let check_children = || -> AxResult<Option<isize>> {
        // First, check for any zombie children
        if let Some(child) = children.iter().find(|child| child.is_zombie()) {
            // Get zombie termination info before freeing
            let zombie_info = child
                .zombie_info()
                .expect("zombie child must have zombie info");

            if !options.contains(WaitOptions::WNOWAIT) {
                child.free();
            }

            // Encode status based on how the process terminated
            let wait_status = match zombie_info {
                starry_process::ZombieInfo::Exited(code) => WaitStatus::exited(code),
                starry_process::ZombieInfo::Signaled {
                    signal,
                    core_dumped,
                } => WaitStatus::signaled(signal, core_dumped),
            };

            if let Some(exit_code_ptr) = exit_code.nullable() {
                let _ = exit_code_ptr.vm_write(wait_status.as_raw());
            }
            return Ok(Some(child.pid() as isize));
        }

        // When the WUNTRACED option is specified, also check for stopped children.
        // TODO: extend this to cover ptrace stop reporting once ptrace lands.
        if options.contains(WaitOptions::WUNTRACED)
            && let Some(stopped_child) = children.iter().find(|child| child.is_stopped())
            && let Some(stopping_signal) = stopped_child.stop_signal()
        {
            let wait_status = WaitStatus::stopped(stopping_signal);
            if let Some(exit_code_ptr) = exit_code.nullable() {
                let _ = exit_code_ptr.vm_write(wait_status.as_raw());
            }
            return Ok(Some(stopped_child.pid() as isize));
        }

        // When the WCONTINUED option is specified, check for continued children
        if options.contains(WaitOptions::WCONTINUED)
            && let Some(continued_child) = children.iter().find(|child| child.is_continued())
        {
            let wait_status = WaitStatus::continued();
            if let Some(exit_code_ptr) = exit_code.nullable() {
                let _ = exit_code_ptr.vm_write(wait_status.as_raw());
            }
            // Acknowledge that parent has been notified
            continued_child.ack_continued();
            return Ok(Some(continued_child.pid() as isize));
        }

        // When WNOHANG is specified, return immediately if no children are ready
        if options.contains(WaitOptions::WNOHANG) {
            return Ok(Some(0));
        }

        Ok(None)
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
