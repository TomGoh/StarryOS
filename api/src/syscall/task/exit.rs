use axerrno::AxResult;
use axhal::uspace::UserContext;
#[cfg(feature = "ptrace")]
use starry_ptrace::{StopReason, stop_current_and_wait};

use crate::task::do_exit;

pub fn sys_exit(uctx: &mut UserContext, exit_code: i32) -> AxResult<isize> {
    #[cfg(feature = "ptrace")]
    {
        // Deliver PTRACE_EVENT_EXIT before actually exiting if requested.
        stop_current_and_wait(StopReason::Exit(exit_code), uctx);
    }
    do_exit(exit_code, false, None, false);
    Ok(0)
}

pub fn sys_exit_group(uctx: &mut UserContext, exit_code: i32) -> AxResult<isize> {
    #[cfg(feature = "ptrace")]
    {
        stop_current_and_wait(StopReason::Exit(exit_code), uctx);
    }
    do_exit(exit_code, true, None, false);
    Ok(0)
}
