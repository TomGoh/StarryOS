use crate::*;

/// Test PTRACE_TRACEME basic functionality
pub fn test_traceme_basic() -> TestResult {
    print_test_header("PTRACE_TRACEME - Basic");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            // Child process
            if let Err(e) = ptrace::traceme() {
                eprintln!("Child: PTRACE_TRACEME failed: {}", e);
                process::exit(1);
            }

            // Raise SIGSTOP to notify parent we're ready
            if let Err(e) = process::raise(libc::SIGSTOP) {
                eprintln!("Child: raise(SIGSTOP) failed: {}", e);
                process::exit(1);
            }

            // Exit successfully
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

            if !wifstopped(status) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!(
                    "Expected child to be stopped, got status: 0x{:x}",
                    status
                ));
            }

            let sig = wstopsig(status);
            if sig != libc::SIGSTOP {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("Expected SIGSTOP, got signal: {}", sig));
            }

            print_success("Child successfully stopped with SIGSTOP");

            // Continue the child
            if let Err(e) = ptrace::cont(child_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT failed: {}", e));
            }

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

/// Test that PTRACE_TRACEME marks the process as traced
pub fn test_traceme_marks_traced() -> TestResult {
    print_test_header("PTRACE_TRACEME - Marks Process as Traced");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            // Child process
            if let Err(e) = ptrace::traceme() {
                eprintln!("Child: PTRACE_TRACEME failed: {}", e);
                process::exit(1);
            }

            // Try to call PTRACE_TRACEME again - should fail
            match ptrace::traceme() {
                Ok(_) => {
                    eprintln!("Child: Second PTRACE_TRACEME should have failed");
                    process::exit(1);
                }
                Err(_) => {
                    // Expected - process is already traced
                    process::exit(0);
                }
            }
        }
        Ok(child_pid) => {
            // Parent process
            let mut status = 0;

            // Wait for child to exit
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid failed: {}", e));
            }

            if !wifexited(status) {
                return Err(format!("Expected child to exit, got status: 0x{:x}", status));
            }

            let exit_code = wexitstatus(status);
            if exit_code != 0 {
                return Err(format!(
                    "Expected exit code 0 (duplicate traceme should fail), got: {}",
                    exit_code
                ));
            }

            print_success("Duplicate PTRACE_TRACEME correctly failed");
            Ok(())
        }
    }
}

pub fn run_all_tests() -> (usize, usize) {
    let tests: Vec<(&str, fn() -> TestResult)> = vec![
        ("PTRACE_TRACEME - Basic", test_traceme_basic),
        (
            "PTRACE_TRACEME - Marks Traced",
            test_traceme_marks_traced,
        ),
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
