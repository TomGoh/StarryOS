use crate::*;

/// Test PTRACE_ATTACH - basic attach and detach
pub fn test_attach_basic() -> TestResult {
    print_test_header("PTRACE_ATTACH - Basic");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            // Child process - just loop until killed
            loop {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
        Ok(child_pid) => {
            // Parent process
            let mut status = 0;

            // Give the child a moment to start running
            std::thread::sleep(std::time::Duration::from_millis(10));

            // Attach to the child
            if let Err(e) = ptrace::attach(child_pid) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_ATTACH failed: {}", e));
            }

            print_success("PTRACE_ATTACH issued");

            // Wait for the child to stop (it will be sent SIGSTOP)
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid failed: {}", e));
            }

            if !wifstopped(status) || wstopsig(status) != libc::SIGSTOP {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("Expected SIGSTOP, got status: 0x{:x}", status));
            }

            print_success("Child stopped with SIGSTOP after attach");

            // Detach from the child
            if let Err(e) = ptrace::detach(child_pid) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_DETACH failed: {}", e));
            }

            print_success("PTRACE_DETACH succeeded");

            // Clean up by killing the child
            if let Err(e) = process::kill(child_pid, libc::SIGKILL) {
                return Err(format!("kill failed: {}", e));
            }

            print_success("Child process cleaned up");
            Ok(())
        }
    }
}

/// Test PTRACE_ATTACH and then PTRACE_CONT
pub fn test_attach_and_cont() -> TestResult {
    print_test_header("PTRACE_ATTACH & PTRACE_CONT");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            // Child process
            process::exit(55);
        }
        Ok(child_pid) => {
            // Parent process
            let mut status = 0;

            // Attach to the child
            if let Err(e) = ptrace::attach(child_pid) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_ATTACH failed: {}", e));
            }

            print_success("PTRACE_ATTACH issued");

            // Wait for the child to stop
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid for attach stop failed: {}", e));
            }

            if !wifstopped(status) || wstopsig(status) != libc::SIGSTOP {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("Expected SIGSTOP, got status: 0x{:x}", status));
            }

            print_success("Child stopped with SIGSTOP");

            // Continue the child
            if let Err(e) = ptrace::cont(child_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT failed: {}", e));
            }

            print_success("PTRACE_CONT issued");

            // Wait for the child to exit
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                return Err(format!("waitpid for exit failed: {}", e));
            }

            if !wifexited(status) {
                return Err(format!(
                    "Expected child to exit, got status: 0x{:x}",
                    status
                ));
            }

            let exit_code = wexitstatus(status);
            if exit_code != 55 {
                return Err(format!("Expected exit code 55, got: {}", exit_code));
            }

            print_success("Child exited with expected code 55");
            Ok(())
        }
    }
}

/// Test PTRACE_ATTACH, do something, and then PTRACE_DETACH
pub fn test_attach_getregs_detach() -> TestResult {
    print_test_header("PTRACE_ATTACH, GETREGS, and DETACH");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            // Child process
            process::exit(66);
        }
        Ok(child_pid) => {
            // Parent process
            let mut status = 0;

            // Attach to the child
            if let Err(e) = ptrace::attach(child_pid) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_ATTACH failed: {}", e));
            }

            print_success("PTRACE_ATTACH issued");

            // Wait for the child to stop
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid for attach stop failed: {}", e));
            }

            if !wifstopped(status) || wstopsig(status) != libc::SIGSTOP {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("Expected SIGSTOP, got status: 0x{:x}", status));
            }

            print_success("Child stopped with SIGSTOP");

            // Get registers using getregset
            let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
            let mut iov = libc::iovec {
                iov_base: &mut regs as *mut _ as *mut libc::c_void,
                iov_len: std::mem::size_of::<libc::user_regs_struct>(),
            };

            match ptrace::getregset(child_pid, ptrace::NT_PRSTATUS, &mut iov) {
                Ok(_) => {
                    print_success("PTRACE_GETREGSET succeeded");
                    if iov.iov_len != std::mem::size_of::<libc::user_regs_struct>() {
                        return Err(format!(
                            "PTRACE_GETREGSET returned unexpected size: {}",
                            iov.iov_len
                        ));
                    }
                }
                Err(e) => {
                    let _ = process::kill(child_pid, libc::SIGKILL);
                    return Err(format!("PTRACE_GETREGSET failed: {}", e));
                }
            }

            // Detach from the child, which should resume it
            if let Err(e) = ptrace::detach(child_pid) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_DETACH failed: {}", e));
            }

            print_success("PTRACE_DETACH issued");

            // Wait for the child to exit
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                return Err(format!("waitpid for exit failed: {}", e));
            }

            if !wifexited(status) {
                return Err(format!(
                    "Expected child to exit, got status: 0x{:x}",
                    status
                ));
            }

            let exit_code = wexitstatus(status);
            if exit_code != 66 {
                return Err(format!("Expected exit code 66, got: {}", exit_code));
            }

            print_success("Child exited with expected code 66 after detach");
            Ok(())
        }
    }
}

pub fn run_all_tests() -> (usize, usize) {
    let tests: Vec<(&str, fn() -> TestResult)> = vec![
        ("PTRACE_ATTACH - Basic", test_attach_basic),
        ("PTRACE_ATTACH & CONT", test_attach_and_cont),
        ("PTRACE_ATTACH, GETREGS, DETACH", test_attach_getregs_detach),
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
