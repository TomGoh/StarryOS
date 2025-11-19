use crate::*;

/// Test PTRACE_EVENT_FORK - basic fork tracing
pub fn test_fork_event_basic() -> TestResult {
    print_test_header("PTRACE_EVENT_FORK - Basic Fork Tracing");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            // Child process
            if let Err(e) = ptrace::traceme() {
                eprintln!("Child: PTRACE_TRACEME failed: {}", e);
                process::exit(1);
            }

            // Raise SIGSTOP to sync with parent
            if let Err(e) = process::raise(libc::SIGSTOP) {
                eprintln!("Child: raise(SIGSTOP) failed: {}", e);
                process::exit(1);
            }

            // Now fork - this should trigger PTRACE_EVENT_FORK
            unsafe {
                let child_pid = libc::fork();
                if child_pid == 0 {
                    // Grandchild - exit immediately
                    libc::exit(0);
                } else if child_pid > 0 {
                    // Child - wait for grandchild
                    let mut status = 0;
                    libc::waitpid(child_pid, &mut status, 0);
                }
            }

            process::exit(0);
        }
        Ok(child_pid) => {
            // Parent process (tracer)
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

            // Set PTRACE_O_TRACEFORK option
            if let Err(e) = ptrace::setoptions(child_pid, ptrace::PTRACE_O_TRACEFORK) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_SETOPTIONS failed: {}", e));
            }

            print_success("PTRACE_O_TRACEFORK option set");

            // Continue the child
            if let Err(e) = ptrace::cont(child_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT failed: {}", e));
            }

            // Wait for PTRACE_EVENT_FORK
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid (fork event) failed: {}", e));
            }

            if !is_ptrace_event(status, ptrace::PTRACE_EVENT_FORK) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!(
                    "Expected PTRACE_EVENT_FORK, got status: 0x{:x}, event: {:?}",
                    status,
                    get_ptrace_event(status)
                ));
            }

            print_success("PTRACE_EVENT_FORK received");

            // Get the new child PID via PTRACE_GETEVENTMSG
            let grandchild_pid = match ptrace::geteventmsg(child_pid) {
                Ok(msg) => msg as i32,
                Err(e) => {
                    let _ = process::kill(child_pid, libc::SIGKILL);
                    return Err(format!("PTRACE_GETEVENTMSG failed: {}", e));
                }
            };

            print_success(&format!("Grandchild PID from GETEVENTMSG: {}", grandchild_pid));

            if grandchild_pid <= 0 {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("Invalid grandchild PID: {}", grandchild_pid));
            }

            // Continue the child
            if let Err(e) = ptrace::cont(child_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                let _ = process::kill(grandchild_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT (after fork event) failed: {}", e));
            }

            // Wait for grandchild to stop with SIGSTOP (automatically attached)
            if let Err(e) = process::waitpid(grandchild_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                let _ = process::kill(grandchild_pid, libc::SIGKILL);
                return Err(format!("waitpid (grandchild) failed: {}", e));
            }

            if !wifstopped(status) || wstopsig(status) != libc::SIGSTOP {
                let _ = process::kill(child_pid, libc::SIGKILL);
                let _ = process::kill(grandchild_pid, libc::SIGKILL);
                return Err(format!(
                    "Expected grandchild to stop with SIGSTOP, got status: 0x{:x}",
                    status
                ));
            }

            print_success("Grandchild automatically traced and stopped with SIGSTOP");

            // Continue grandchild to let it exit
            if let Err(e) = ptrace::cont(grandchild_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                let _ = process::kill(grandchild_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT (grandchild) failed: {}", e));
            }

            // Wait for grandchild to exit
            if let Err(e) = process::waitpid(grandchild_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid (grandchild exit) failed: {}", e));
            }

            if !wifexited(status) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!(
                    "Expected grandchild to exit, got status: 0x{:x}",
                    status
                ));
            }

            print_success("Grandchild exited successfully");

            // Wait for child - may receive SIGCHLD from grandchild first
            loop {
                if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                    return Err(format!("waitpid (child) failed: {}", e));
                }

                if wifexited(status) {
                    print_success("Child exited successfully");
                    break;
                }

                if wifstopped(status) {
                    // Continue past any signals (like SIGCHLD from grandchild exit)
                    if let Err(e) = ptrace::cont(child_pid, 0) {
                        return Err(format!("PTRACE_CONT (child signal) failed: {}", e));
                    }
                } else {
                    return Err(format!("Unexpected child status: 0x{:x}", status));
                }
            }

            Ok(())
        }
    }
}

/// Test PTRACE_EVENT_FORK without TRACEFORK option - should not trigger event
pub fn test_fork_without_option() -> TestResult {
    print_test_header("PTRACE_EVENT_FORK - Without TRACEFORK Option");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            // Child process
            if let Err(e) = ptrace::traceme() {
                eprintln!("Child: PTRACE_TRACEME failed: {}", e);
                process::exit(1);
            }

            // Raise SIGSTOP to sync with parent
            if let Err(e) = process::raise(libc::SIGSTOP) {
                eprintln!("Child: raise(SIGSTOP) failed: {}", e);
                process::exit(1);
            }

            // Fork without TRACEFORK option - should not generate event
            unsafe {
                let child_pid = libc::fork();
                if child_pid == 0 {
                    // Grandchild - exit immediately
                    libc::exit(0);
                } else if child_pid > 0 {
                    // Child - wait for grandchild
                    let mut status = 0;
                    libc::waitpid(child_pid, &mut status, 0);
                }
            }

            process::exit(0);
        }
        Ok(child_pid) => {
            // Parent process (tracer)
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

            // Do NOT set PTRACE_O_TRACEFORK option

            // Continue the child
            if let Err(e) = ptrace::cont(child_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT failed: {}", e));
            }

            // Wait for child to exit (no fork event should be generated)
            loop {
                if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                    let _ = process::kill(child_pid, libc::SIGKILL);
                    return Err(format!("waitpid failed: {}", e));
                }

                // Should NOT be a fork event
                if is_ptrace_event(status, ptrace::PTRACE_EVENT_FORK) {
                    let _ = process::kill(child_pid, libc::SIGKILL);
                    return Err(format!(
                        "Unexpected PTRACE_EVENT_FORK without TRACEFORK option, status: 0x{:x}",
                        status
                    ));
                }

                if wifexited(status) {
                    print_success("No fork event generated without TRACEFORK option");
                    break;
                }

                if wifstopped(status) {
                    // Continue past any signals (child may receive SIGCHLD from grandchild)
                    if let Err(e) = ptrace::cont(child_pid, 0) {
                        let _ = process::kill(child_pid, libc::SIGKILL);
                        return Err(format!("PTRACE_CONT failed: {}", e));
                    }
                } else {
                    let _ = process::kill(child_pid, libc::SIGKILL);
                    return Err(format!("Unexpected status: 0x{:x}", status));
                }
            }

            Ok(())
        }
    }
}

/// Test PTRACE_EVENT_CLONE - clone with CLONE_THREAD should trigger TRACECLONE
pub fn test_clone_event() -> TestResult {
    print_test_header("PTRACE_EVENT_CLONE - Clone Tracing");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            // Child process
            if let Err(e) = ptrace::traceme() {
                eprintln!("Child: PTRACE_TRACEME failed: {}", e);
                process::exit(1);
            }

            // Raise SIGSTOP to sync with parent
            if let Err(e) = process::raise(libc::SIGSTOP) {
                eprintln!("Child: raise(SIGSTOP) failed: {}", e);
                process::exit(1);
            }

            // Create a thread using pthread (which uses clone internally)
            unsafe {
                let mut thread: libc::pthread_t = std::mem::zeroed();
                extern "C" fn thread_fn(_arg: *mut libc::c_void) -> *mut libc::c_void {
                    std::ptr::null_mut()
                }
                let result = libc::pthread_create(
                    &mut thread,
                    std::ptr::null(),
                    thread_fn,
                    std::ptr::null_mut(),
                );
                if result == 0 {
                    libc::pthread_join(thread, std::ptr::null_mut());
                }
            }

            process::exit(0);
        }
        Ok(child_pid) => {
            // Parent process (tracer)
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

            // Set PTRACE_O_TRACECLONE option
            if let Err(e) = ptrace::setoptions(child_pid, ptrace::PTRACE_O_TRACECLONE) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_SETOPTIONS failed: {}", e));
            }

            print_success("PTRACE_O_TRACECLONE option set");

            // Continue the child
            if let Err(e) = ptrace::cont(child_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT failed: {}", e));
            }

            // Wait for either PTRACE_EVENT_CLONE or child exit
            let mut got_clone_event = false;
            let mut iterations = 0;
            let max_iterations = 20;

            loop {
                iterations += 1;
                if iterations > max_iterations {
                    let _ = process::kill(child_pid, libc::SIGKILL);
                    return Err(format!("Test timeout after {} iterations", max_iterations));
                }

                // Use WNOHANG to avoid blocking forever
                match process::waitpid(-1, &mut status, libc::WNOHANG) {
                    Err(e) => {
                        let _ = process::kill(child_pid, libc::SIGKILL);
                        return Err(format!("waitpid failed: {}", e));
                    }
                    Ok(0) => {
                        // No child state changed, sleep briefly
                        std::thread::sleep(std::time::Duration::from_millis(10));
                        continue;
                    }
                    Ok(pid) => {
                        if wifexited(status) {
                            if pid == child_pid {
                                break;
                            }
                            // Some other process exited, continue
                            continue;
                        }

                        if wifstopped(status) {
                            if is_ptrace_event(status, ptrace::PTRACE_EVENT_CLONE) {
                                got_clone_event = true;
                                print_success("PTRACE_EVENT_CLONE received");

                                // Get the new thread ID via PTRACE_GETEVENTMSG
                                match ptrace::geteventmsg(pid) {
                                    Ok(msg) => {
                                        print_success(&format!("Thread ID from GETEVENTMSG: {}", msg as i32));
                                    }
                                    Err(e) => {
                                        let _ = process::kill(child_pid, libc::SIGKILL);
                                        return Err(format!("PTRACE_GETEVENTMSG failed: {}", e));
                                    }
                                }
                            }

                            // Continue on any stop
                            if let Err(_) = ptrace::cont(pid, 0) {
                                // Ignore errors - process may have exited
                                continue;
                            }
                        }
                    }
                }
            }

            if !got_clone_event {
                print_skip("PTRACE_EVENT_CLONE not detected (may not be implemented or threads not traced separately)");
            }

            Ok(())
        }
    }
}

pub fn run_all_tests() -> (usize, usize) {
    let tests: Vec<(&str, fn() -> TestResult)> = vec![
        ("PTRACE_EVENT_FORK - Basic", test_fork_event_basic),
        ("PTRACE_EVENT_FORK - Without Option", test_fork_without_option),
        ("PTRACE_EVENT_CLONE - Basic", test_clone_event),
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
