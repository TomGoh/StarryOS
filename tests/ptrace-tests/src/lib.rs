/// Test result type
pub type TestResult = Result<(), String>;

/// ANSI color codes for test output
pub const COLOR_GREEN: &str = "\x1b[32m";
pub const COLOR_RED: &str = "\x1b[31m";
pub const COLOR_YELLOW: &str = "\x1b[33m";
pub const COLOR_BLUE: &str = "\x1b[34m";
pub const COLOR_RESET: &str = "\x1b[0m";

/// Print a colored test header
pub fn print_test_header(name: &str) {
    println!("\n{}=== Testing: {} ==={}", COLOR_BLUE, name, COLOR_RESET);
}

/// Print test success
pub fn print_success(msg: &str) {
    println!("{}✓ PASS:{} {}", COLOR_GREEN, COLOR_RESET, msg);
}

/// Print test failure
pub fn print_failure(msg: &str) {
    eprintln!("{}✗ FAIL:{} {}", COLOR_RED, COLOR_RESET, msg);
}

/// Print test skip
pub fn print_skip(msg: &str) {
    println!("{}⊘ SKIP:{} {}", COLOR_YELLOW, COLOR_RESET, msg);
}

/// Safe wrapper for ptrace operations
pub mod ptrace {
    use std::io;

    pub const PTRACE_TRACEME: u32 = 0;
    pub const PTRACE_PEEKDATA: u32 = 2;
    pub const PTRACE_CONT: u32 = 7;
    pub const PTRACE_GETREGS: u32 = 12;
    pub const PTRACE_ATTACH: u32 = 16;
    pub const PTRACE_DETACH: u32 = 17;
    pub const PTRACE_SYSCALL: u32 = 24;
    pub const PTRACE_SETOPTIONS: u32 = 0x4200;
    pub const PTRACE_GETEVENTMSG: u32 = 0x4201;
    pub const PTRACE_GETREGSET: u32 = 0x4204;

    pub const NT_PRSTATUS: usize = 1;

    // Ptrace options
    pub const PTRACE_O_TRACESYSGOOD: u32 = 0x00000001;
    pub const PTRACE_O_TRACEFORK: u32 = 0x00000002;
    pub const PTRACE_O_TRACEVFORK: u32 = 0x00000004;
    pub const PTRACE_O_TRACECLONE: u32 = 0x00000008;
    pub const PTRACE_O_TRACEEXEC: u32 = 0x00000010;
    pub const PTRACE_O_TRACEVFORKDONE: u32 = 0x00000020;
    pub const PTRACE_O_TRACEEXIT: u32 = 0x00000040;

    // Ptrace events
    pub const PTRACE_EVENT_FORK: i32 = 1;
    pub const PTRACE_EVENT_VFORK: i32 = 2;
    pub const PTRACE_EVENT_CLONE: i32 = 3;
    pub const PTRACE_EVENT_EXEC: i32 = 4;
    pub const PTRACE_EVENT_VFORK_DONE: i32 = 5;
    pub const PTRACE_EVENT_EXIT: i32 = 6;

    pub fn traceme() -> io::Result<()> {
        unsafe {
            if libc::ptrace(PTRACE_TRACEME as i32, 0, 0, 0) == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    pub fn attach(pid: i32) -> io::Result<()> {
        unsafe {
            if libc::ptrace(PTRACE_ATTACH as i32, pid, 0, 0) == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    pub fn cont(pid: i32, sig: i32) -> io::Result<()> {
        unsafe {
            if libc::ptrace(PTRACE_CONT as i32, pid, 0, sig) == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    pub fn syscall(pid: i32, sig: i32) -> io::Result<()> {
        unsafe {
            if libc::ptrace(PTRACE_SYSCALL as i32, pid, 0, sig) == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    pub fn detach(pid: i32) -> io::Result<()> {
        unsafe {
            if libc::ptrace(PTRACE_DETACH as i32, pid, 0, 0) == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    pub fn getregs(pid: i32) -> io::Result<libc::user_regs_struct> {
        unsafe {
            let mut regs: libc::user_regs_struct = std::mem::zeroed();
            if libc::ptrace(
                PTRACE_GETREGS as i32,
                pid,
                0,
                &mut regs as *mut _ as *mut libc::c_void,
            ) == -1
            {
                Err(io::Error::last_os_error())
            } else {
                Ok(regs)
            }
        }
    }

    pub fn getregset(pid: i32, note_type: usize, iov: &mut libc::iovec) -> io::Result<()> {
        unsafe {
            if libc::ptrace(
                PTRACE_GETREGSET as i32,
                pid,
                note_type,
                iov as *mut _ as *mut libc::c_void,
            ) == -1
            {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    pub fn peekdata(pid: i32, addr: usize) -> io::Result<i64> {
        unsafe {
            // ptrace returns -1 on error, but -1 could also be valid data
            // So we need to clear errno first and check it after
            *libc::__errno_location() = 0;
            let result = libc::ptrace(PTRACE_PEEKDATA as i32, pid, addr, 0);
            let errno = *libc::__errno_location();
            if result == -1 && errno != 0 {
                Err(io::Error::from_raw_os_error(errno))
            } else {
                Ok(result)
            }
        }
    }

    pub fn setoptions(pid: i32, options: u32) -> io::Result<()> {
        unsafe {
            if libc::ptrace(PTRACE_SETOPTIONS as i32, pid, 0, options as i64) == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    pub fn geteventmsg(pid: i32) -> io::Result<u64> {
        unsafe {
            let mut msg: u64 = 0;
            if libc::ptrace(
                PTRACE_GETEVENTMSG as i32,
                pid,
                0,
                &mut msg as *mut _ as *mut libc::c_void,
            ) == -1
            {
                Err(io::Error::last_os_error())
            } else {
                Ok(msg)
            }
        }
    }
}

/// Process control utilities
pub mod process {
    use std::io;

    pub fn fork() -> io::Result<libc::pid_t> {
        unsafe {
            let pid = libc::fork();
            if pid == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(pid)
            }
        }
    }

    pub fn waitpid(pid: i32, status: &mut i32, options: i32) -> io::Result<i32> {
        unsafe {
            let result = libc::waitpid(pid, status as *mut i32, options);
            if result == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(result)
            }
        }
    }

    pub fn kill(pid: i32, sig: i32) -> io::Result<()> {
        unsafe {
            if libc::kill(pid, sig) == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }

    pub fn exit(code: i32) -> ! {
        unsafe {
            libc::exit(code);
        }
    }

    pub fn raise(sig: i32) -> io::Result<()> {
        unsafe {
            if libc::raise(sig) == -1 {
                Err(io::Error::last_os_error())
            } else {
                Ok(())
            }
        }
    }
}

/// Check if status indicates process stopped
pub fn wifstopped(status: i32) -> bool {
    libc::WIFSTOPPED(status)
}

/// Check if status indicates process exited
pub fn wifexited(status: i32) -> bool {
    libc::WIFEXITED(status)
}

/// Get exit status
pub fn wexitstatus(status: i32) -> i32 {
    libc::WEXITSTATUS(status)
}

/// Get stop signal
pub fn wstopsig(status: i32) -> i32 {
    libc::WSTOPSIG(status)
}

/// Check if status indicates process was signaled
pub fn wifsignaled(status: i32) -> bool {
    libc::WIFSIGNALED(status)
}

/// Extract ptrace event code from wait status
/// Returns the event number (e.g., PTRACE_EVENT_FORK) if this is an event stop
pub fn get_ptrace_event(status: i32) -> Option<i32> {
    if wifstopped(status) && wstopsig(status) == libc::SIGTRAP {
        let event = (status >> 16) & 0xff;
        if event != 0 {
            Some(event)
        } else {
            None
        }
    } else {
        None
    }
}

/// Check if status indicates a ptrace event stop
pub fn is_ptrace_event(status: i32, event: i32) -> bool {
    get_ptrace_event(status) == Some(event)
}
