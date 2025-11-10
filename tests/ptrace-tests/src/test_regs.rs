use crate::*;

/// Test register reading - basic functionality (using GETREGSET on aarch64)
pub fn test_getregs_basic() -> TestResult {
    print_test_header("Register Reading - Basic");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            // Child process
            if let Err(e) = ptrace::traceme() {
                eprintln!("Child: PTRACE_TRACEME failed: {}", e);
                process::exit(1);
            }

            // Raise SIGSTOP
            if let Err(e) = process::raise(libc::SIGSTOP) {
                eprintln!("Child: raise(SIGSTOP) failed: {}", e);
                process::exit(1);
            }

            process::exit(0);
        }
        Ok(child_pid) => {
            // Parent process
            let mut status = 0;

            // Wait for child to stop
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid failed: {}", e));
            }

            if !wifstopped(status) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("Child not stopped, status: 0x{:x}", status));
            }

            // Get registers using GETREGSET (works on aarch64)
            let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
            let mut iov = libc::iovec {
                iov_base: &mut regs as *mut _ as *mut libc::c_void,
                iov_len: std::mem::size_of::<libc::user_regs_struct>(),
            };

            if let Err(e) = ptrace::getregset(child_pid, ptrace::NT_PRSTATUS, &mut iov) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_GETREGSET failed: {}", e));
            }

            // Basic sanity checks
            print_success(&format!("Successfully read registers"));
            print_success(&format!("  PC (ELR): 0x{:016x}", regs.pc));
            print_success(&format!("  SP: 0x{:016x}", regs.sp));
            print_success(&format!("  X0: 0x{:016x}", regs.regs[0]));

            // PC should be non-zero and look like a valid address
            if regs.pc == 0 {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err("PC is zero, likely invalid".to_string());
            }

            // SP should be non-zero and aligned
            if regs.sp == 0 {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err("SP is zero, likely invalid".to_string());
            }

            if regs.sp % 16 != 0 {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("SP not 16-byte aligned: 0x{:x}", regs.sp));
            }

            print_success("Register values look reasonable");

            // Cleanup
            let _ = ptrace::cont(child_pid, 0);
            let _ = process::waitpid(child_pid, &mut status, 0);

            Ok(())
        }
    }
}

/// Test register reading during syscall (using GETREGSET on aarch64)
pub fn test_getregs_during_syscall() -> TestResult {
    print_test_header("Register Reading - During Syscall");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            // Child process
            if let Err(e) = ptrace::traceme() {
                eprintln!("Child: PTRACE_TRACEME failed: {}", e);
                process::exit(1);
            }

            // Raise SIGSTOP
            if let Err(e) = process::raise(libc::SIGSTOP) {
                eprintln!("Child: raise(SIGSTOP) failed: {}", e);
                process::exit(1);
            }

            // Make a syscall with known arguments
            unsafe { libc::getpid() };

            process::exit(0);
        }
        Ok(child_pid) => {
            // Parent process
            let mut status = 0;

            // Wait for child to stop
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid failed: {}", e));
            }

            // Start syscall tracing
            if let Err(e) = ptrace::syscall(child_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_SYSCALL failed: {}", e));
            }

            // Wait for syscall entry
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid (syscall entry) failed: {}", e));
            }

            if !wifstopped(status) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("Expected stop at syscall, got: 0x{:x}", status));
            }

            // Get registers at syscall entry using GETREGSET (works on aarch64)
            let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
            let mut iov = libc::iovec {
                iov_base: &mut regs as *mut _ as *mut libc::c_void,
                iov_len: std::mem::size_of::<libc::user_regs_struct>(),
            };

            if let Err(e) = ptrace::getregset(child_pid, ptrace::NT_PRSTATUS, &mut iov) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_GETREGSET at syscall entry failed: {}", e));
            }

            // On AArch64, x8 contains the syscall number
            let syscall_nr = regs.regs[8] as i64;
            print_success(&format!("Syscall number (x8): {}", syscall_nr));

            // Print syscall name if available
            if let Some(name) = syscall_numbers::aarch64::sys_call_name(syscall_nr) {
                print_success(&format!("Syscall name: {}", name));
            }

            print_success("Successfully read registers at syscall entry");

            // Continue to syscall exit
            if let Err(e) = ptrace::syscall(child_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_SYSCALL (to exit) failed: {}", e));
            }

            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid (syscall exit) failed: {}", e));
            }

            // Get registers at syscall exit using GETREGSET (works on aarch64)
            let mut regs_exit: libc::user_regs_struct = unsafe { std::mem::zeroed() };
            let mut iov_exit = libc::iovec {
                iov_base: &mut regs_exit as *mut _ as *mut libc::c_void,
                iov_len: std::mem::size_of::<libc::user_regs_struct>(),
            };

            if let Err(e) = ptrace::getregset(child_pid, ptrace::NT_PRSTATUS, &mut iov_exit) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_GETREGSET at syscall exit failed: {}", e));
            }

            // On AArch64, x0 contains the return value
            let retval = regs_exit.regs[0] as i64;
            print_success(&format!("Syscall return value (x0): {}", retval));

            print_success("Successfully read registers at syscall entry and exit");

            // Cleanup
            let _ = ptrace::cont(child_pid, 0);
            let _ = process::waitpid(child_pid, &mut status, 0);

            Ok(())
        }
    }
}

/// Test PTRACE_GETREGSET with NT_PRSTATUS
pub fn test_getregset_basic() -> TestResult {
    print_test_header("PTRACE_GETREGSET - Basic (NT_PRSTATUS)");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            // Child process
            if let Err(e) = ptrace::traceme() {
                eprintln!("Child: PTRACE_TRACEME failed: {}", e);
                process::exit(1);
            }

            if let Err(e) = process::raise(libc::SIGSTOP) {
                eprintln!("Child: raise(SIGSTOP) failed: {}", e);
                process::exit(1);
            }

            process::exit(0);
        }
        Ok(child_pid) => {
            // Parent process
            let mut status = 0;

            // Wait for child to stop
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid failed: {}", e));
            }

            if !wifstopped(status) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("Child not stopped, status: 0x{:x}", status));
            }

            // Prepare buffer for registers
            let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
            let mut iov = libc::iovec {
                iov_base: &mut regs as *mut _ as *mut libc::c_void,
                iov_len: std::mem::size_of::<libc::user_regs_struct>(),
            };

            // Get registers using GETREGSET
            if let Err(e) = ptrace::getregset(child_pid, ptrace::NT_PRSTATUS, &mut iov) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_GETREGSET failed: {}", e));
            }

            print_success("PTRACE_GETREGSET succeeded");
            print_success(&format!("  iov_len after call: {}", iov.iov_len));
            print_success(&format!("  PC: 0x{:016x}", regs.pc));
            print_success(&format!("  SP: 0x{:016x}", regs.sp));

            // Basic sanity checks
            if regs.pc == 0 || regs.sp == 0 {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err("Register values look invalid (PC or SP is zero)".to_string());
            }

            print_success("Register values look reasonable");

            // Cleanup
            let _ = ptrace::cont(child_pid, 0);
            let _ = process::waitpid(child_pid, &mut status, 0);

            Ok(())
        }
    }
}

pub fn run_all_tests() -> (usize, usize) {
    let tests: Vec<(&str, fn() -> TestResult)> = vec![
        ("Register Reading - Basic", test_getregs_basic),
        ("Register Reading - During Syscall", test_getregs_during_syscall),
        ("PTRACE_GETREGSET - Basic", test_getregset_basic),
    ];

    let mut passed = 0;
    let mut failed = 0;

    for (name, test_fn) in tests {
        match test_fn() {
            Ok(()) => {
                passed += 1;
            }
            Err(e) => {
                print_failure(&format!("{}: {}", name, e));
                failed += 1;
            }
        }
    }

    (passed, failed)
}
