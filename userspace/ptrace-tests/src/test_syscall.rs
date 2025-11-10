use crate::*;

/// Test PTRACE_SYSCALL - basic syscall tracing
pub fn test_syscall_basic() -> TestResult {
    print_test_header("PTRACE_SYSCALL - Basic Tracing");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            // Child process
            if let Err(e) = ptrace::traceme() {
                eprintln!("Child: PTRACE_TRACEME failed: {}", e);
                process::exit(1);
            }

            // Raise SIGSTOP to sync with parent
            if let Err(e) = process::kill(0, libc::SIGSTOP) {
                eprintln!("Child: kill(SIGSTOP) failed: {}", e);
                process::exit(1);
            }

            // Make a simple syscall - getpid
            unsafe { libc::getpid() };

            process::exit(0);
        }
        Ok(child_pid) => {
            // Parent process
            let mut status = 0;

            // Wait for child to stop
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid (initial) failed: {}", e));
            }

            if !wifstopped(status) || wstopsig(status) != libc::SIGSTOP {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("Expected SIGSTOP, got status: 0x{:x}", status));
            }

            print_success("Child stopped at initial SIGSTOP");

            // Start syscall tracing
            if let Err(e) = ptrace::syscall(child_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_SYSCALL failed: {}", e));
            }

            // Count syscall entries and exits
            let mut syscall_stops = 0;
            let max_stops = 20; // Prevent infinite loops

            loop {
                if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                    return Err(format!("waitpid (syscall loop) failed: {}", e));
                }

                if wifexited(status) {
                    print_success(&format!(
                        "Child exited after {} syscall stops",
                        syscall_stops
                    ));
                    break;
                }

                if !wifstopped(status) {
                    return Err(format!("Expected stop, got status: 0x{:x}", status));
                }

                // Check if this is a syscall stop (SIGTRAP with bit 7 potentially set)
                let sig = wstopsig(status);
                if sig == libc::SIGTRAP || sig == (libc::SIGTRAP | 0x80) {
                    syscall_stops += 1;
                    if syscall_stops == 1 {
                        print_success("First syscall stop detected");
                    }
                }

                if syscall_stops >= max_stops {
                    let _ = process::kill(child_pid, libc::SIGKILL);
                    return Err(format!("Too many syscall stops ({}), aborting", max_stops));
                }

                // Continue to next syscall
                if let Err(e) = ptrace::syscall(child_pid, 0) {
                    let _ = process::kill(child_pid, libc::SIGKILL);
                    return Err(format!("PTRACE_SYSCALL continuation failed: {}", e));
                }
            }

            if syscall_stops < 2 {
                return Err(format!(
                    "Expected at least 2 syscall stops (entry+exit), got {}",
                    syscall_stops
                ));
            }

            print_success(&format!("Detected {} syscall stops total", syscall_stops));
            Ok(())
        }
    }
}

/// Test PTRACE_SYSCALL with TRACESYSGOOD option
pub fn test_syscall_tracesysgood() -> TestResult {
    print_test_header("PTRACE_SYSCALL - TRACESYSGOOD Option");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            // Child process
            if let Err(e) = ptrace::traceme() {
                eprintln!("Child: PTRACE_TRACEME failed: {}", e);
                process::exit(1);
            }

            // Raise SIGSTOP to sync with parent
            if let Err(e) = process::kill(0, libc::SIGSTOP) {
                eprintln!("Child: kill(SIGSTOP) failed: {}", e);
                process::exit(1);
            }

            // Make a syscall
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

            // Set TRACESYSGOOD option
            if let Err(e) = ptrace::setoptions(child_pid, ptrace::PTRACE_O_TRACESYSGOOD) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_SETOPTIONS failed: {}", e));
            }

            print_success("PTRACE_O_TRACESYSGOOD option set");

            // Start syscall tracing
            if let Err(e) = ptrace::syscall(child_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_SYSCALL failed: {}", e));
            }

            let mut found_tracesysgood = false;

            for _ in 0..20 {
                if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                    return Err(format!("waitpid failed: {}", e));
                }

                if wifexited(status) {
                    break;
                }

                if wifstopped(status) {
                    let sig = wstopsig(status);
                    // TRACESYSGOOD should set bit 7: SIGTRAP | 0x80
                    if sig == (libc::SIGTRAP | 0x80) {
                        found_tracesysgood = true;
                        print_success(&format!(
                            "Syscall stop with TRACESYSGOOD marker detected (sig=0x{:x})",
                            sig
                        ));
                    }

                    if let Err(e) = ptrace::syscall(child_pid, 0) {
                        let _ = process::kill(child_pid, libc::SIGKILL);
                        return Err(format!("PTRACE_SYSCALL failed: {}", e));
                    }
                }
            }

            if found_tracesysgood {
                print_success("TRACESYSGOOD correctly marks syscall stops");
                Ok(())
            } else {
                Err("Did not observe TRACESYSGOOD marker (0x80 bit)".to_string())
            }
        }
    }
}

pub fn run_all_tests() -> (usize, usize) {
    let tests: Vec<(&str, fn() -> TestResult)> = vec![
        ("PTRACE_SYSCALL - Basic", test_syscall_basic),
        ("PTRACE_SYSCALL - TRACESYSGOOD", test_syscall_tracesysgood),
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
