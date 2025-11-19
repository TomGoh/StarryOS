# StarryOS Ptrace Test Suite

This is a comprehensive test suite for the StarryOS ptrace implementation. It tests all currently implemented ptrace operations to ensure they work correctly.

## Test Coverage

### Currently Tested Operations

1. **PTRACE_TRACEME** (`test_traceme.rs`)
   - Basic functionality
   - Marks process as traced
   - Prevents duplicate TRACEME calls

2. **PTRACE_SYSCALL** (`test_syscall.rs`)
   - Basic syscall tracing
   - Syscall entry/exit detection
   - TRACESYSGOOD option support

3. **PTRACE_GETREGS / PTRACE_GETREGSET** (`test_regs.rs`)
   - Reading registers from stopped process
   - Register access during syscall entry/exit
   - GETREGSET with NT_PRSTATUS

4. **PTRACE_PEEKDATA** (`test_memory.rs`)
   - Reading memory from tracee
   - String reading from memory
   - Invalid address handling

5. **PTRACE_CONT / PTRACE_DETACH** (`test_control.rs`)
   - Basic process continuation
   - Detaching from traced process
   - Signal delivery via CONT

## Building

The test suite is built for AArch64 using musl libc:

```bash
# From the project root
cd userspace/ptrace-tests
cargo build --release --target aarch64-unknown-linux-musl
```

Or use the provided build script:

```bash
# From the project root
make ptrace-tests
```

## Running Tests

### Automatic Mode (Recommended)

Run tests automatically during kernel boot:

```bash
# From the project root
make test-ptrace
```

This will:
1. Build the test suite
2. Include it in the disk image
3. Boot StarryOS in QEMU
4. Automatically run tests
5. Display results

### Manual Mode

Run tests manually from the StarryOS shell:

```bash
# Boot StarryOS normally
make run

# Inside StarryOS shell
/usr/bin/ptrace-tests

# Or run specific test suite
/usr/bin/ptrace-tests --test=traceme
/usr/bin/ptrace-tests --test=syscall
/usr/bin/ptrace-tests --test=regs
/usr/bin/ptrace-tests --test=memory
/usr/bin/ptrace-tests --test=control

# Verbose output
/usr/bin/ptrace-tests -v
```

## Test Output

Tests produce colored output:
- ✓ PASS (green) - Test passed successfully
- ✗ FAIL (red) - Test failed with error
- ⊘ SKIP (yellow) - Test was skipped

Example output:
```
=== Testing: PTRACE_TRACEME - Basic ===
✓ PASS: Child successfully stopped with SIGSTOP
✓ PASS: Child exited with expected code 42

=== Testing: PTRACE_SYSCALL - Basic Tracing ===
✓ PASS: Child stopped at initial SIGSTOP
✓ PASS: First syscall stop detected
✓ PASS: Detected 8 syscall stops total
```

## Adding New Tests

To add a new test:

1. Create a new test file in `src/test_*.rs`
2. Follow the pattern of existing tests
3. Add the module to `src/main.rs`
4. Add the test suite to the `test_suites` vector

Example test structure:
```rust
use crate::*;

pub fn test_new_feature() -> TestResult {
    print_test_header("FEATURE_NAME - Description");

    // Test implementation

    print_success("Test passed");
    Ok(())
}

pub fn run_all_tests() -> (usize, usize) {
    let tests: Vec<(&str, fn() -> TestResult)> = vec![
        ("Feature Test", test_new_feature),
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

## Known Limitations

1. **Single-threaded only**: Tests currently only work with single-threaded processes
2. **No ATTACH tests**: PTRACE_ATTACH is not yet implemented
3. **No SETREGS tests**: PTRACE_SETREGS is not yet implemented
4. **No POKEDATA tests**: PTRACE_POKEDATA is not yet implemented

These tests will be added as the features are implemented.

## Troubleshooting

### Test hangs or doesn't complete

- Check if the child process is properly killed on error
- Verify SIGSTOP is being raised correctly
- Check waitpid return values

### Register values look wrong

- Ensure the process is actually stopped before reading registers
- Check that you're reading at the right time (syscall entry vs exit)
- Verify register layout matches AArch64 user_regs_struct

### Memory reads fail

- Check that the address is within the tracee's address space
- Verify the process is stopped
- Ensure the memory region is mapped

## Future Work

- [ ] Add tests for PTRACE_SETREGS when implemented
- [ ] Add tests for PTRACE_POKEDATA when implemented
- [ ] Add tests for PTRACE_ATTACH when implemented
- [ ] Add tests for PTRACE_SINGLESTEP when implemented
- [ ] Add multi-threaded process tests
- [ ] Add tests for fork/exec event tracing
- [ ] Add stress tests with many syscalls
- [ ] Add performance benchmarks

## License

Part of the StarryOS project.
