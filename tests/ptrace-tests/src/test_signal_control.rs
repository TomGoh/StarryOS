use crate::*;

/// Test signal suppression - tracer passes data=0 to suppress signal
pub fn test_signal_suppression() -> TestResult {
    print_test_header("Signal Suppression - Suppress SIGTERM");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            // Child process
            if let Err(e) = ptrace::traceme() {
                eprintln!("Child: PTRACE_TRACEME failed: {}", e);
                process::exit(1);
            }

            // Stop to synchronize with parent
            if let Err(e) = process::raise(libc::SIGSTOP) {
                eprintln!("Child: raise(SIGSTOP) failed: {}", e);
                process::exit(1);
            }

            // Raise SIGTERM - this should be suppressed by the tracer
            if let Err(e) = process::raise(libc::SIGTERM) {
                eprintln!("Child: raise(SIGTERM) failed: {}", e);
                process::exit(1);
            }

            // If we reach here, signal was suppressed successfully
            process::exit(42);
        }
        Ok(child_pid) => {
            // Parent process
            let mut status = 0;

            // Wait for initial SIGSTOP
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid (SIGSTOP) failed: {}", e));
            }

            if !wifstopped(status) || wstopsig(status) != libc::SIGSTOP {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("Expected SIGSTOP, got status: 0x{:x}", status));
            }

            print_success("Child stopped with SIGSTOP");

            // Continue child so it raises SIGTERM
            if let Err(e) = ptrace::cont(child_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT (1) failed: {}", e));
            }

            // Wait for child to stop at SIGTERM signal-delivery-stop
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid (SIGTERM) failed: {}", e));
            }

            if !wifstopped(status) || wstopsig(status) != libc::SIGTERM {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("Expected SIGTERM stop, got status: 0x{:x}", status));
            }

            print_success("Child stopped at SIGTERM signal-delivery-stop");

            // CRITICAL: Pass data=0 to suppress the signal
            if let Err(e) = ptrace::cont(child_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT (suppress) failed: {}", e));
            }

            print_success("PTRACE_CONT with data=0 to suppress signal");

            // Wait for child to exit
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                return Err(format!("waitpid (exit) failed: {}", e));
            }

            // Child should exit normally (not killed by SIGTERM)
            if !wifexited(status) {
                return Err(format!(
                    "Expected child to exit normally, got status: 0x{:x}",
                    status
                ));
            }

            let exit_code = wexitstatus(status);
            if exit_code != 42 {
                return Err(format!(
                    "Expected exit code 42 (signal suppressed), got: {}",
                    exit_code
                ));
            }

            print_success("Signal was successfully suppressed - child exited normally");
            Ok(())
        }
    }
}

/// Test signal modification - tracer changes which signal gets delivered
pub fn test_signal_modification() -> TestResult {
    print_test_header("Signal Modification - Change SIGUSR1 to SIGUSR2");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            // Child process - set up signal handlers
            unsafe {
                // Handler for SIGUSR1
                let mut sa1: libc::sigaction = std::mem::zeroed();
                sa1.sa_sigaction = handle_sigusr1_modify as usize;
                sa1.sa_flags = libc::SA_SIGINFO;
                libc::sigemptyset(&mut sa1.sa_mask);
                if libc::sigaction(libc::SIGUSR1, &sa1, std::ptr::null_mut()) == -1 {
                    eprintln!("Child: sigaction(SIGUSR1) failed");
                    process::exit(1);
                }

                // Handler for SIGUSR2
                let mut sa2: libc::sigaction = std::mem::zeroed();
                sa2.sa_sigaction = handle_sigusr2_modify as usize;
                sa2.sa_flags = libc::SA_SIGINFO;
                libc::sigemptyset(&mut sa2.sa_mask);
                if libc::sigaction(libc::SIGUSR2, &sa2, std::ptr::null_mut()) == -1 {
                    eprintln!("Child: sigaction(SIGUSR2) failed");
                    process::exit(1);
                }
            }

            if let Err(e) = ptrace::traceme() {
                eprintln!("Child: PTRACE_TRACEME failed: {}", e);
                process::exit(1);
            }

            if let Err(e) = process::raise(libc::SIGSTOP) {
                eprintln!("Child: raise(SIGSTOP) failed: {}", e);
                process::exit(1);
            }

            // Raise SIGUSR1 - tracer will change it to SIGUSR2
            if let Err(e) = process::raise(libc::SIGUSR1) {
                eprintln!("Child: raise(SIGUSR1) failed: {}", e);
                process::exit(1);
            }

            // Check which signal was received
            let usr1 = SIGUSR1_RECEIVED.load(std::sync::atomic::Ordering::SeqCst);
            let usr2 = SIGUSR2_RECEIVED.load(std::sync::atomic::Ordering::SeqCst);

            if usr2 && !usr1 {
                process::exit(88); // Success: SIGUSR2 received
            } else if usr1 {
                process::exit(11); // Error: SIGUSR1 received (not modified)
            } else {
                process::exit(22); // Error: No signal received
            }
        }
        Ok(child_pid) => {
            // Parent process
            let mut status = 0;

            // Wait for initial SIGSTOP
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid (SIGSTOP) failed: {}", e));
            }

            print_success("Child stopped with SIGSTOP");

            // Continue child so it raises SIGUSR1
            if let Err(e) = ptrace::cont(child_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT (1) failed: {}", e));
            }

            // Wait for child to stop at SIGUSR1
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid (SIGUSR1) failed: {}", e));
            }

            if !wifstopped(status) || wstopsig(status) != libc::SIGUSR1 {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("Expected SIGUSR1 stop, got status: 0x{:x}", status));
            }

            print_success("Child stopped at SIGUSR1 signal-delivery-stop");

            // CRITICAL: Pass SIGUSR2 to modify the signal
            if let Err(e) = ptrace::cont(child_pid, libc::SIGUSR2) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT (modify) failed: {}", e));
            }

            print_success("PTRACE_CONT with SIGUSR2 to modify signal");

            // Child should stop again at the modified signal (SIGUSR2)
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid (SIGUSR2) failed: {}", e));
            }

            if !wifstopped(status) || wstopsig(status) != libc::SIGUSR2 {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("Expected SIGUSR2 stop, got status: 0x{:x}", status));
            }

            print_success("Child stopped at SIGUSR2 (modified signal)");

            // Continue to deliver SIGUSR2 to handler
            if let Err(e) = ptrace::cont(child_pid, libc::SIGUSR2) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT (deliver) failed: {}", e));
            }

            // Wait for child to exit
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                return Err(format!("waitpid (exit) failed: {}", e));
            }

            if !wifexited(status) {
                return Err(format!("Expected child to exit, got status: 0x{:x}", status));
            }

            let exit_code = wexitstatus(status);
            if exit_code != 88 {
                return Err(format!(
                    "Expected exit code 88 (SIGUSR2 received), got: {}",
                    exit_code
                ));
            }

            print_success("Signal was successfully modified from SIGUSR1 to SIGUSR2");
            Ok(())
        }
    }
}

// Signal handlers for modification test
static SIGUSR1_RECEIVED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
static SIGUSR2_RECEIVED: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

extern "C" fn handle_sigusr1_modify(
    _sig: i32,
    _info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    SIGUSR1_RECEIVED.store(true, std::sync::atomic::Ordering::SeqCst);
}

extern "C" fn handle_sigusr2_modify(
    _sig: i32,
    _info: *mut libc::siginfo_t,
    _ctx: *mut libc::c_void,
) {
    SIGUSR2_RECEIVED.store(true, std::sync::atomic::Ordering::SeqCst);
}

pub fn run_all_tests() -> (usize, usize) {
    let tests: Vec<(&str, fn() -> TestResult)> = vec![
        ("Signal Suppression", test_signal_suppression),
        ("Signal Modification", test_signal_modification),
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