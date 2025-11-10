# Ptrace Testing Guide

This document describes the testing infrastructure for StarryOS's ptrace implementation.

## Overview

The ptrace test suite is a comprehensive set of tests designed to validate all implemented ptrace operations. It runs in userspace within QEMU and tests the kernel's ptrace implementation through the syscall interface.

## Test Architecture

### Test Structure

```
userspace/ptrace-tests/
├── src/
│   ├── main.rs             # Test runner and CLI
│   ├── lib.rs              # Common utilities and wrappers
│   ├── test_traceme.rs     # PTRACE_TRACEME tests
│   ├── test_syscall.rs     # PTRACE_SYSCALL tests
│   ├── test_regs.rs        # Register access tests
│   ├── test_memory.rs      # Memory access tests
│   └── test_control.rs     # Control operation tests
├── Cargo.toml
├── .cargo/config.toml
└── README.md
```

### Test Categories

1. **PTRACE_TRACEME** - Process tracing setup
2. **PTRACE_SYSCALL** - System call tracing
3. **PTRACE_GETREGS/GETREGSET** - Register access
4. **PTRACE_PEEKDATA** - Memory reading
5. **PTRACE_CONT/DETACH** - Process control

## Running Tests

### Quick Start

To run all tests automatically:

```bash
make test-ptrace
```

This will:
1. Build the ptrace test suite for AArch64
2. Create a disk image with the test binary
3. Boot StarryOS in QEMU
4. Automatically run all tests
5. Display colored test results
6. Exit with appropriate code (0 = all passed, 1 = some failed)

### Manual Testing

For interactive testing and debugging:

```bash
# Build and run StarryOS normally
make run

# Inside the StarryOS shell, run:
/usr/bin/ptrace-tests

# Or run specific test suites:
/usr/bin/ptrace-tests --test=traceme
/usr/bin/ptrace-tests --test=syscall
/usr/bin/ptrace-tests --test=regs
/usr/bin/ptrace-tests --test=memory
/usr/bin/ptrace-tests --test=control

# For verbose output:
/usr/bin/ptrace-tests -v
```

### Building Tests Only

To build the test binary without running:

```bash
make ptrace-tests
```

To build the disk image with tests:

```bash
make ptrace-tests-disk
```

## Test Details

### 1. PTRACE_TRACEME Tests

**File**: `test_traceme.rs`

Tests basic tracing setup where a child process marks itself as traced by its parent.

- **test_traceme_basic**: Verifies that PTRACE_TRACEME allows parent to trace child
- **test_traceme_marks_traced**: Ensures duplicate TRACEME calls fail

**What's Tested**:
- Child can successfully call PTRACE_TRACEME
- Child stops on SIGSTOP and parent is notified
- Parent can read child's state after stop
- Duplicate TRACEME calls are rejected

### 2. PTRACE_SYSCALL Tests

**File**: `test_syscall.rs`

Tests system call entry/exit tracing.

- **test_syscall_basic**: Verifies syscall stops at entry and exit
- **test_syscall_tracesysgood**: Tests TRACESYSGOOD option marks syscall stops

**What's Tested**:
- Child stops at syscall entry
- Child stops at syscall exit
- Multiple syscalls are traced correctly
- TRACESYSGOOD option sets bit 7 in stop signal (SIGTRAP | 0x80)

### 3. Register Access Tests

**File**: `test_regs.rs`

Tests reading CPU registers from traced process.

- **test_getregs_basic**: Reads registers from stopped process
- **test_getregs_during_syscall**: Reads registers at syscall entry/exit
- **test_getregset_basic**: Uses GETREGSET with NT_PRSTATUS

**What's Tested**:
- Can read PC, SP, and general-purpose registers
- Register values are sane (non-zero, aligned)
- Can read syscall number (x8) and arguments (x0-x7)
- Can read return value (x0) at syscall exit
- GETREGSET works with iovec interface

### 4. Memory Access Tests

**File**: `test_memory.rs`

Tests reading memory from traced process.

- **test_peekdata_basic**: Reads from stack and code segments
- **test_peekdata_string**: Reads multiple words from memory
- **test_peekdata_invalid_addr**: Tests error handling for invalid addresses

**What's Tested**:
- Can read 8-byte words from stack
- Can read from code segment (PC address)
- Can read multiple consecutive words
- Invalid addresses return errors (or are handled gracefully)

### 5. Control Operation Tests

**File**: `test_control.rs`

Tests process control operations.

- **test_cont_basic**: Continues stopped process with PTRACE_CONT
- **test_detach_basic**: Detaches from traced process
- **test_cont_with_signal**: Delivers signal during continuation

**What's Tested**:
- PTRACE_CONT resumes execution
- Child can exit normally after CONT
- PTRACE_DETACH removes tracing and resumes process
- Signals can be injected via CONT's sig parameter
- Signal handlers are invoked correctly

## Test Utilities (lib.rs)

The test library provides:

### Ptrace Wrappers
- `ptrace::traceme()` - PTRACE_TRACEME
- `ptrace::cont()` - PTRACE_CONT
- `ptrace::syscall()` - PTRACE_SYSCALL
- `ptrace::detach()` - PTRACE_DETACH
- `ptrace::getregs()` - PTRACE_GETREGS
- `ptrace::getregset()` - PTRACE_GETREGSET
- `ptrace::peekdata()` - PTRACE_PEEKDATA
- `ptrace::setoptions()` - PTRACE_SETOPTIONS

### Process Control
- `process::fork()` - Fork wrapper
- `process::waitpid()` - Wait wrapper
- `process::kill()` - Signal wrapper
- `process::exit()` - Exit wrapper

### Wait Status Helpers
- `wifstopped()` - Check if stopped
- `wifexited()` - Check if exited
- `wexitstatus()` - Get exit code
- `wstopsig()` - Get stop signal

### Output Helpers
- `print_test_header()` - Colored test section header
- `print_success()` - Green success message
- `print_failure()` - Red failure message
- `print_skip()` - Yellow skip message

## Writing New Tests

To add a new test:

1. Create a new file `src/test_<feature>.rs`
2. Import common utilities: `use crate::*;`
3. Write test functions returning `TestResult`
4. Create a `run_all_tests()` function
5. Add to `main.rs` test suite list

Example:

```rust
use crate::*;

pub fn test_new_feature() -> TestResult {
    print_test_header("NEW_FEATURE - Description");

    match process::fork() {
        Ok(0) => {
            // Child process
            // ... setup ...
            process::exit(0);
        }
        Ok(child_pid) => {
            // Parent process
            // ... test logic ...
            print_success("Test passed");
            Ok(())
        }
        Err(e) => Err(format!("fork failed: {}", e))
    }
}

pub fn run_all_tests() -> (usize, usize) {
    let tests = vec![
        ("NEW_FEATURE", test_new_feature),
    ];

    let mut passed = 0;
    let mut failed = 0;

    for (name, test_fn) in tests {
        match test_fn() {
            Ok(()) => passed += 1,
            Err(e) => {
                print_failure(&format!("{}: {}", name, e));
                failed += 1;
            }
        }
    }

    (passed, failed)
}
```

Then add to `main.rs`:

```rust
mod test_new_feature;

// In test_suites vector:
("newfeature", test_new_feature::run_all_tests),
```

## Debugging Failed Tests

### Enable Verbose Logging

1. Run with verbose flag: `/usr/bin/ptrace-tests -v`
2. Increase kernel log level in Makefile: `LOG := debug`
3. Enable ptrace-specific debug logs in kernel

### Common Issues

**Test hangs**:
- Check if child process is killed on timeout
- Verify waitpid is not blocking indefinitely
- Check for missing SIGSTOP or resume operations

**Register values wrong**:
- Ensure process is stopped before reading
- Check timing (syscall entry vs exit)
- Verify AArch64 register layout matches expectations

**Memory access fails**:
- Verify address is in valid range
- Check process is stopped
- Ensure memory region is mapped

**Syscall stops not detected**:
- Verify PTRACE_SYSCALL was called
- Check TRACESYSGOOD option if distinguishing stops
- Ensure syscall hooks are registered in kernel

### Kernel Debug Messages

The kernel ptrace implementation logs debug messages. Look for:

```
ptrace: TRACEME pid=X tracer=Y
ptrace: pid=X stopped for reason=SyscallEntry
ptrace: GETREGS pid=X returning registers
ptrace: encode stop status pid=X sig=Y status=0xZ
```

## Test Output Format

Tests produce colored output:

```
============================================================
  StarryOS Ptrace Test Suite
============================================================

Running traceme tests...

=== Testing: PTRACE_TRACEME - Basic ===
✓ PASS: Child successfully stopped with SIGSTOP
✓ PASS: Child exited with expected code 42

=== Testing: PTRACE_SYSCALL - Basic Tracing ===
✓ PASS: Child stopped at initial SIGSTOP
✓ PASS: First syscall stop detected
✓ PASS: Detected 8 syscall stops total

============================================================
Test Summary:
  Passed: 15
  Failed: 0
  Total:  15
============================================================

All tests passed!
```

## Continuous Integration

For CI/CD pipelines:

```bash
# Run tests and capture exit code
make test-ptrace
TEST_EXIT=$?

if [ $TEST_EXIT -ne 0 ]; then
    echo "Ptrace tests failed!"
    exit 1
fi
```

## Future Test Coverage

Planned tests for upcoming features:

- [ ] PTRACE_SETREGS - Modifying registers
- [ ] PTRACE_POKEDATA - Writing memory
- [ ] PTRACE_SINGLESTEP - Single-step execution
- [ ] PTRACE_ATTACH - Attach to running process
- [ ] Multi-threaded tracing
- [ ] Fork/exec event tracing (PTRACE_O_TRACEFORK, etc.)
- [ ] Signal-delivery stops (comprehensive)
- [ ] Performance benchmarks

## Troubleshooting Build Issues

### Missing musl target

```bash
rustup target add aarch64-unknown-linux-musl
```

### Build script permission denied

```bash
chmod +x scripts/build-ptrace-tests-disk.sh
```

### Disk image creation fails

Ensure you have:
- `dd`, `mkfs.ext4`, `mount` commands available
- Sudo access for mount operations
- At least 1GB free disk space

## References

- Linux ptrace(2) man page: https://man7.org/linux/man-pages/man2/ptrace.2.html
- StarryOS ptrace implementation: `local_crates/starry-ptrace/`
- Test suite: `userspace/ptrace-tests/`
