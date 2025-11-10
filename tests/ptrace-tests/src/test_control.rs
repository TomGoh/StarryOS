use crate::*;

/// Test PTRACE_CONT - basic continuation
pub fn test_cont_basic() -> TestResult {
    print_test_header("PTRACE_CONT - Basic");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            // Child process
            if let Err(e) = ptrace::traceme() {
                eprintln!("Child: PTRACE_TRACEME failed: {}", e);
                process::exit(1);
            }

            if let Err(e) = process::kill(0, libc::SIGSTOP) {
                eprintln!("Child: kill(SIGSTOP) failed: {}", e);
                process::exit(1);
            }

            process::exit(42);
        }
        Ok(child_pid) => {
            // Parent process
            let mut status = 0;

            // Wait for child to stop
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid failed: {}", e));
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

            // Wait for child to exit
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                return Err(format!("waitpid (exit) failed: {}", e));
            }

            if !wifexited(status) {
                return Err(format!("Expected child to exit, got status: 0x{:x}", status));
            }

            let exit_code = wexitstatus(status);
            if exit_code != 42 {
                return Err(format!("Expected exit code 42, got: {}", exit_code));
            }

            print_success("Child exited with expected code 42");
            Ok(())
        }
    }
}

/// Test PTRACE_DETACH - detach from traced process
pub fn test_detach_basic() -> TestResult {
    print_test_header("PTRACE_DETACH - Basic");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            // Child process
            if let Err(e) = ptrace::traceme() {
                eprintln!("Child: PTRACE_TRACEME failed: {}", e);
                process::exit(1);
            }

            if let Err(e) = process::kill(0, libc::SIGSTOP) {
                eprintln!("Child: kill(SIGSTOP) failed: {}", e);
                process::exit(1);
            }

            // After detach, this should run without tracer intervention
            process::exit(99);
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

            print_success("Child stopped");

            // Detach from the child
            if let Err(e) = ptrace::detach(child_pid) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_DETACH failed: {}", e));
            }

            print_success("PTRACE_DETACH succeeded");

            // Wait for child to exit
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                return Err(format!("waitpid (after detach) failed: {}", e));
            }

            if !wifexited(status) {
                return Err(format!(
                    "Expected child to exit after detach, got status: 0x{:x}",
                    status
                ));
            }

            let exit_code = wexitstatus(status);
            if exit_code != 99 {
                return Err(format!("Expected exit code 99, got: {}", exit_code));
            }

            print_success("Child exited correctly after detach with code 99");
            Ok(())
        }
    }
}

/// Test PTRACE_CONT with signal delivery
pub fn test_cont_with_signal() -> TestResult {
    print_test_header("PTRACE_CONT - With Signal Delivery");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            // Child process - set up signal handler
            unsafe {
                let mut sa: libc::sigaction = std::mem::zeroed();
                sa.sa_sigaction = handle_sigusr1 as usize;
                sa.sa_flags = libc::SA_SIGINFO;
                libc::sigemptyset(&mut sa.sa_mask);

                if libc::sigaction(libc::SIGUSR1, &sa, std::ptr::null_mut()) == -1 {
                    eprintln!("Child: sigaction failed");
                    process::exit(1);
                }
            }

            if let Err(e) = ptrace::traceme() {
                eprintln!("Child: PTRACE_TRACEME failed: {}", e);
                process::exit(1);
            }

            if let Err(e) = process::kill(0, libc::SIGSTOP) {
                eprintln!("Child: kill(SIGSTOP) failed: {}", e);
                process::exit(1);
            }

            // If we got SIGUSR1, exit with code 77
            if SIGNAL_RECEIVED.load(std::sync::atomic::Ordering::SeqCst) {
                process::exit(77);
            }

            process::exit(1); // Should not reach here
        }
        Ok(child_pid) => {
            // Parent process
            let mut status = 0;

            // Wait for child to stop
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid failed: {}", e));
            }

            print_success("Child stopped");

            // Continue with SIGUSR1 delivery
            if let Err(e) = ptrace::cont(child_pid, libc::SIGUSR1) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT with signal failed: {}", e));
            }

            print_success("PTRACE_CONT with SIGUSR1 issued");

            // Give child time to handle signal and exit
            std::thread::sleep(std::time::Duration::from_millis(100));

            // Wait for child to exit
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                return Err(format!("waitpid (exit) failed: {}", e));
            }

            if !wifexited(status) {
                return Err(format!("Expected child to exit, got status: 0x{:x}", status));
            }

            let exit_code = wexitstatus(status);
            if exit_code != 77 {
                return Err(format!(
                    "Expected exit code 77 (signal received), got: {}",
                    exit_code
                ));
            }

            print_success("Signal was delivered and handled correctly");
            Ok(())
        }
    }
}

// Signal handler for SIGUSR1
static SIGNAL_RECEIVED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

extern "C" fn handle_sigusr1(_sig: i32, _info: *mut libc::siginfo_t, _ctx: *mut libc::c_void) {
    SIGNAL_RECEIVED.store(true, std::sync::atomic::Ordering::SeqCst);
}

pub fn run_all_tests() -> (usize, usize) {
    let tests: Vec<(&str, fn() -> TestResult)> = vec![
        ("PTRACE_CONT - Basic", test_cont_basic),
        ("PTRACE_DETACH - Basic", test_detach_basic),
        ("PTRACE_CONT - With Signal", test_cont_with_signal),
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
