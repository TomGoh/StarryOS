use axerrno::AxResult;

use crate::task::do_exit;

pub fn sys_exit(exit_code: i32) -> AxResult<isize> {
    do_exit(exit_code, false);
    Ok(0)
}

pub fn sys_exit_group(exit_code: i32) -> AxResult<isize> {
    do_exit(exit_code, true);
    Ok(0)
}
