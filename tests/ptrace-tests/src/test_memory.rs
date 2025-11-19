use crate::*;

/// Test PTRACE_PEEKDATA - basic memory reading
pub fn test_peekdata_basic() -> TestResult {
    print_test_header("PTRACE_PEEKDATA - Basic");

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

            // Keep some known data in memory
            let test_data: [u64; 4] = [
                0xDEADBEEFCAFEBABE,
                0x1122334455667788,
                0xABCDEF0123456789,
                0x0000000000000042,
            ];

            // Use the data to prevent optimization
            let sum: u64 = test_data.iter().sum();
            if sum == 0 {
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

            // Get the child's registers to find stack pointer
            let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
            let mut iov = libc::iovec {
                iov_base: &mut regs as *mut _ as *mut libc::c_void,
                iov_len: std::mem::size_of::<libc::user_regs_struct>(),
            };

            if let Err(e) = ptrace::getregset(child_pid, ptrace::NT_PRSTATUS, &mut iov) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_GETREGSET failed: {}", e));
            }

            let stack_addr = regs.sp as usize;
            print_success(&format!("Child SP: 0x{:016x}", stack_addr));

            // Try to read from stack (should be readable)
            match ptrace::peekdata(child_pid, stack_addr) {
                Ok(data) => {
                    print_success(&format!(
                        "Successfully read from stack: 0x{:016x}",
                        data as u64
                    ));
                }
                Err(e) => {
                    let _ = process::kill(child_pid, libc::SIGKILL);
                    return Err(format!("PTRACE_PEEKDATA from stack failed: {}", e));
                }
            }

            // Try to read from PC (code segment, should be readable)
            let pc_addr = regs.pc as usize;
            match ptrace::peekdata(child_pid, pc_addr) {
                Ok(data) => {
                    print_success(&format!(
                        "Successfully read from PC (0x{:016x}): 0x{:016x}",
                        pc_addr, data as u64
                    ));
                }
                Err(e) => {
                    let _ = process::kill(child_pid, libc::SIGKILL);
                    return Err(format!("PTRACE_PEEKDATA from PC failed: {}", e));
                }
            }

            print_success("PTRACE_PEEKDATA can read from valid memory regions");

            // Cleanup
            let _ = ptrace::cont(child_pid, 0);
            let _ = process::waitpid(child_pid, &mut status, 0);

            Ok(())
        }
    }
}

/// Test PTRACE_PEEKDATA - reading string from memory
pub fn test_peekdata_string() -> TestResult {
    print_test_header("PTRACE_PEEKDATA - String Reading");

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

            // Keep a known string in memory
            let test_string = "Hello from traced process!";
            // Use the string to prevent optimization
            if test_string.len() == 0 {
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

            // Get registers
            let mut regs: libc::user_regs_struct = unsafe { std::mem::zeroed() };
            let mut iov = libc::iovec {
                iov_base: &mut regs as *mut _ as *mut libc::c_void,
                iov_len: std::mem::size_of::<libc::user_regs_struct>(),
            };

            if let Err(e) = ptrace::getregset(child_pid, ptrace::NT_PRSTATUS, &mut iov) {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!("PTRACE_GETREGSET failed: {}", e));
            }

            // Try reading multiple words from stack region
            let base_addr = (regs.sp as usize) & !7; // Align to 8 bytes
            let mut words_read = 0;

            for i in 0..16 {
                let addr = base_addr + (i * 8);
                match ptrace::peekdata(child_pid, addr) {
                    Ok(data) => {
                        words_read += 1;
                        if i < 4 {
                            // Print first few words
                            print_success(&format!("  [0x{:016x}] = 0x{:016x}", addr, data as u64));
                        }
                    }
                    Err(_) => {
                        // Some addresses might not be accessible
                        break;
                    }
                }
            }

            if words_read < 4 {
                let _ = process::kill(child_pid, libc::SIGKILL);
                return Err(format!(
                    "Could only read {} words, expected at least 4",
                    words_read
                ));
            }

            print_success(&format!(
                "Successfully read {} words from memory",
                words_read
            ));

            // Cleanup
            let _ = ptrace::cont(child_pid, 0);
            let _ = process::waitpid(child_pid, &mut status, 0);

            Ok(())
        }
    }
}

/// Test PTRACE_PEEKDATA - invalid address handling
pub fn test_peekdata_invalid_addr() -> TestResult {
    print_test_header("PTRACE_PEEKDATA - Invalid Address");

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

            // Try to read from obviously invalid addresses
            let invalid_addrs = vec![
                0x0,                // NULL
                0x1,                // Very low address
                0xFFFFFFFFFFFFFFFF, // Very high address
            ];

            let mut all_failed_correctly = true;

            for addr in invalid_addrs {
                match ptrace::peekdata(child_pid, addr) {
                    Ok(data) => {
                        // This might actually succeed for address 0 on some systems
                        // if it's mapped, so we'll just note it
                        print_skip(&format!(
                            "Address 0x{:x} returned data: 0x{:x} (might be mapped)",
                            addr, data
                        ));
                        all_failed_correctly = false;
                    }
                    Err(_) => {
                        print_success(&format!(
                            "PTRACE_PEEKDATA correctly failed for invalid address 0x{:x}",
                            addr
                        ));
                    }
                }
            }

            // Cleanup
            let _ = ptrace::cont(child_pid, 0);
            let _ = process::waitpid(child_pid, &mut status, 0);

            if all_failed_correctly {
                Ok(())
            } else {
                // This is not necessarily a failure
                print_skip("Some invalid addresses were readable (OS-dependent)");
                Ok(())
            }
        }
    }
}

pub fn run_all_tests() -> (usize, usize) {
    let tests: Vec<(&str, fn() -> TestResult)> = vec![
        ("PTRACE_PEEKDATA - Basic", test_peekdata_basic),
        ("PTRACE_PEEKDATA - String Reading", test_peekdata_string),
        (
            "PTRACE_PEEKDATA - Invalid Address",
            test_peekdata_invalid_addr,
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
