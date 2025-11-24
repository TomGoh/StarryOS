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
                    // Child skips waiting so the tracer handles the grandchild
                    // lifecycle
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

            print_success(&format!(
                "Grandchild PID from GETEVENTMSG: {}",
                grandchild_pid
            ));

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
                    // Child does not wait; tracer suppresses SIGCHLD so waiting
                    // can hang
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

            // Wait specifically for child_pid to generate clone event
            // This avoids confusion with zombie children from previous tests
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid (clone event) failed: {}", e));
            }

            if !is_ptrace_event(status, ptrace::PTRACE_EVENT_CLONE) {
                // Child might have exited or stopped for another reason
                if wifexited(status) || wifsignaled(status) {
                    let _ = process::kill(child_pid, libc::SIGKILL);
                    return Err(format!(
                        "Child exited before clone event, status: 0x{:x}",
                        status
                    ));
                }
                // Not clone event, might be a signal stop - continue and try again
                if wifstopped(status) {
                    let _ = ptrace::cont(child_pid, 0);
                    if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                        let _ = process::kill(child_pid, libc::SIGKILL);
                        return Err(format!("waitpid (retry clone event) failed: {}", e));
                    }
                    if !is_ptrace_event(status, ptrace::PTRACE_EVENT_CLONE) {
                        let _ = process::kill(child_pid, libc::SIGKILL);
                        return Err(format!(
                            "Expected PTRACE_EVENT_CLONE, got status: 0x{:x}",
                            status
                        ));
                    }
                }
            }

            print_success("PTRACE_EVENT_CLONE received");

            let new_tid = match ptrace::geteventmsg(child_pid) {
                Ok(msg) => msg as i32,
                Err(e) => {
                    let _ = process::kill(child_pid, libc::SIGKILL);
                    return Err(format!("PTRACE_GETEVENTMSG failed: {}", e));
                }
            };
            print_success(&format!("Thread ID from GETEVENTMSG: {}", new_tid));

            // Wait for new thread to stop with SIGSTOP
            let mut thread_status = 0;
            match process::waitpid(new_tid, &mut thread_status, 0) {
                Ok(_) => {
                    if !wifstopped(thread_status) || wstopsig(thread_status) != libc::SIGSTOP {
                        let _ = process::kill(child_pid, libc::SIGKILL);
                        let _ = process::kill(new_tid, libc::SIGKILL);
                        return Err(format!(
                            "New thread {} did not stop with SIGSTOP, status: 0x{:x}",
                            new_tid, thread_status
                        ));
                    }
                    print_success(&format!(
                        "New thread {} confirmed stopped with SIGSTOP",
                        new_tid
                    ));
                    let _ = ptrace::cont(new_tid, 0);
                }
                Err(e) => {
                    let _ = process::kill(child_pid, libc::SIGKILL);
                    return Err(format!("Failed to wait for new thread {}: {}", new_tid, e));
                }
            }

            // Continue parent and wait for exit
            let _ = ptrace::cont(child_pid, 0);
            loop {
                if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                    return Err(format!("waitpid (child exit) failed: {}", e));
                }
                if wifexited(status) || wifsignaled(status) {
                    print_success("Child exited successfully");
                    break;
                }
                // Handle any intermediate stops
                if wifstopped(status) {
                    let _ = ptrace::cont(child_pid, 0);
                }
            }

            Ok(())
        }
    }
}

/// Test PTRACE_EVENT_EXEC - exec tracing
pub fn test_exec_event() -> TestResult {
    print_test_header("PTRACE_EVENT_EXEC - Exec Tracing");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            if let Err(e) = ptrace::traceme() {
                eprintln!("Child: PTRACE_TRACEME failed: {}", e);
                process::exit(1);
            }
            if let Err(e) = process::raise(libc::SIGSTOP) {
                eprintln!("Child: raise(SIGSTOP) failed: {}", e);
                process::exit(1);
            }

            let path = std::ffi::CString::new("/bin/true").unwrap();
            let arg0 = std::ffi::CString::new("true").unwrap();
            unsafe {
                libc::execl(
                    path.as_ptr(),
                    arg0.as_ptr(),
                    std::ptr::null::<libc::c_char>(),
                );
            }
            process::exit(1);
        }
        Ok(child_pid) => {
            let mut status = 0;
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid (initial) failed: {}", e));
            }

            if let Err(e) = ptrace::setoptions(child_pid, ptrace::PTRACE_O_TRACEEXEC) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_SETOPTIONS failed: {}", e));
            }
            print_success("PTRACE_O_TRACEEXEC option set");

            if let Err(e) = ptrace::cont(child_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT failed: {}", e));
            }

            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid (exec event) failed: {}", e));
            }

            if !is_ptrace_event(status, ptrace::PTRACE_EVENT_EXEC) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!(
                    "Expected PTRACE_EVENT_EXEC, got status: 0x{:x}",
                    status
                ));
            }
            print_success("PTRACE_EVENT_EXEC received");

            if let Err(e) = ptrace::cont(child_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT (post exec) failed: {}", e));
            }

            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                return Err(format!("waitpid (child exit) failed: {}", e));
            }

            if !wifexited(status) {
                return Err(format!(
                    "Child did not exit normally, status: 0x{:x}",
                    status
                ));
            }

            print_success("Child exited after exec");
            Ok(())
        }
    }
}

/// Test PTRACE_EVENT_EXIT - exit tracing
pub fn test_exit_event() -> TestResult {
    print_test_header("PTRACE_EVENT_EXIT - Exit Tracing");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            if let Err(e) = ptrace::traceme() {
                eprintln!("Child: PTRACE_TRACEME failed: {}", e);
                process::exit(1);
            }
            if let Err(e) = process::raise(libc::SIGSTOP) {
                eprintln!("Child: raise(SIGSTOP) failed: {}", e);
                process::exit(1);
            }
            process::exit(42);
        }
        Ok(child_pid) => {
            let mut status = 0;
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid (initial) failed: {}", e));
            }

            if let Err(e) = ptrace::setoptions(child_pid, ptrace::PTRACE_O_TRACEEXIT) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_SETOPTIONS failed: {}", e));
            }
            print_success("PTRACE_O_TRACEEXIT option set");

            if let Err(e) = ptrace::cont(child_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT failed: {}", e));
            }

            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid (exit event) failed: {}", e));
            }

            if !is_ptrace_event(status, ptrace::PTRACE_EVENT_EXIT) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!(
                    "Expected PTRACE_EVENT_EXIT, got status: 0x{:x}",
                    status
                ));
            }
            print_success("PTRACE_EVENT_EXIT received");

            let event_msg = match ptrace::geteventmsg(child_pid) {
                Ok(msg) => msg as i32,
                Err(e) => {
                    let _ = process::kill(child_pid, libc::SIGKILL);
                    return Err(format!("PTRACE_GETEVENTMSG failed: {}", e));
                }
            };
            print_success(&format!("Exit status from GETEVENTMSG: {}", event_msg));

            if let Err(e) = ptrace::cont(child_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT (post exit event) failed: {}", e));
            }

            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                return Err(format!("waitpid (final) failed: {}", e));
            }

            if !wifexited(status) || wexitstatus(status) != 42 {
                return Err(format!(
                    "Child exited with unexpected status: 0x{:x}",
                    status
                ));
            }

            print_success("Child exited with expected status 42");
            Ok(())
        }
    }
}

/// Test PTRACE_EVENT_VFORK and VFORK_DONE
pub fn test_vfork_event() -> TestResult {
    print_test_header("PTRACE_EVENT_VFORK - Vfork Tracing");

    match process::fork() {
        Err(e) => return Err(format!("fork failed: {}", e)),
        Ok(0) => {
            if let Err(e) = ptrace::traceme() {
                eprintln!("Child: PTRACE_TRACEME failed: {}", e);
                process::exit(1);
            }
            if let Err(e) = process::raise(libc::SIGSTOP) {
                eprintln!("Child: raise(SIGSTOP) failed: {}", e);
                process::exit(1);
            }

            #[allow(deprecated)]
            unsafe {
                let pid = libc::vfork();
                if pid == 0 {
                    libc::_exit(0);
                }
            }

            process::exit(0);
        }
        Ok(child_pid) => {
            let mut status = 0;
            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid (initial) failed: {}", e));
            }

            if let Err(e) = ptrace::setoptions(
                child_pid,
                ptrace::PTRACE_O_TRACEVFORK | ptrace::PTRACE_O_TRACEVFORKDONE,
            ) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                // If vfork tracing is not supported, skip the test
                if e.kind() == std::io::ErrorKind::Unsupported {
                    print_skip("PTRACE_O_TRACEVFORK not supported");
                    // We need to wait for the child to exit since we killed it
                    let _ = process::waitpid(child_pid, &mut status, 0);
                    return Ok(());
                }
                return Err(format!("PTRACE_SETOPTIONS failed: {}", e));
            }
            print_success("PTRACE_O_TRACEVFORK and PTRACE_O_TRACEVFORKDONE options set");

            if let Err(e) = ptrace::cont(child_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT failed: {}", e));
            }

            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid (vfork event) failed: {}", e));
            }

            if !is_ptrace_event(status, ptrace::PTRACE_EVENT_VFORK) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!(
                    "Expected PTRACE_EVENT_VFORK, got status: 0x{:x}",
                    status
                ));
            }
            print_success("PTRACE_EVENT_VFORK received");

            let grandchild_pid = match ptrace::geteventmsg(child_pid) {
                Ok(msg) => msg as i32,
                Err(e) => {
                    let _ = process::kill(child_pid, libc::SIGKILL);
                    return Err(format!("PTRACE_GETEVENTMSG failed: {}", e));
                }
            };
            print_success(&format!("Vfork child PID: {}", grandchild_pid));

            let mut gc_status = 0;
            if let Err(e) = process::waitpid(grandchild_pid, &mut gc_status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                let _ = process::kill(grandchild_pid, libc::SIGKILL);
                return Err(format!("waitpid (vfork child) failed: {}", e));
            }

            if !wifstopped(gc_status) || wstopsig(gc_status) != libc::SIGSTOP {
                let _ = process::kill(child_pid, libc::SIGKILL);
                let _ = process::kill(grandchild_pid, libc::SIGKILL);
                return Err(format!(
                    "Expected vfork child {} to stop with SIGSTOP, got status: 0x{:x}",
                    grandchild_pid, gc_status
                ));
            }
            print_success("Vfork child stopped with SIGSTOP");

            if let Err(e) = ptrace::cont(grandchild_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                let _ = process::kill(grandchild_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT (vfork child) failed: {}", e));
            }
            print_success("Vfork child resumed");

            if let Err(e) = ptrace::cont(child_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT (post VFORK) failed: {}", e));
            }

            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("waitpid (vfork done) failed: {}", e));
            }

            if !is_ptrace_event(status, ptrace::PTRACE_EVENT_VFORK_DONE) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!(
                    "Expected PTRACE_EVENT_VFORK_DONE, got status: 0x{:x}",
                    status
                ));
            }
            print_success("PTRACE_EVENT_VFORK_DONE received");

            if let Err(e) = ptrace::cont(child_pid, 0) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_CONT (post VFORK_DONE) failed: {}", e));
            }

            if let Err(e) = process::waitpid(child_pid, &mut status, 0) {
                return Err(format!("waitpid (final) failed: {}", e));
            }

            let _ = process::waitpid(grandchild_pid, &mut gc_status, 0);
            Ok(())
        }
    }
}

pub fn run_all_tests() -> (usize, usize) {
    let tests: Vec<(&str, fn() -> TestResult)> = vec![
        ("PTRACE_EVENT_FORK - Basic", test_fork_event_basic),
        (
            "PTRACE_EVENT_FORK - Without Option",
            test_fork_without_option,
        ),
        ("PTRACE_EVENT_CLONE - Basic", test_clone_event),
        ("PTRACE_EVENT_EXEC - Basic", test_exec_event),
        ("PTRACE_EVENT_EXIT - Basic", test_exit_event),
        ("PTRACE_EVENT_VFORK - Basic", test_vfork_event),
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
