use axerrno::AxResult;

use crate::task::do_exit;

pub fn sys_exit(exit_code: i32) -> AxResult<isize> {
    do_exit(exit_code, false, None, false);
    Ok(0)
}

pub fn sys_exit_group(exit_code: i32) -> AxResult<isize> {
    do_exit(exit_code, true, None, false);
    Ok(0)
}
