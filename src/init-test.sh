#!/bin/sh

export HOME=/root

echo -e "Welcome to \e[96m\e[1mStarry OS\e[0m - Ptrace Test Mode!"
echo
echo "Running ptrace test suite..."
echo

# Run the ptrace tests
if [ -x /usr/bin/ptrace-tests ]; then
    /usr/bin/ptrace-tests
    TEST_EXIT_CODE=$?

    echo
    echo "=========================================="
    if [ $TEST_EXIT_CODE -eq 0 ]; then
        echo -e "\e[32m✓ All ptrace tests passed!\e[0m"
    else
        echo -e "\e[31m✗ Some ptrace tests failed (exit code: $TEST_EXIT_CODE)\e[0m"
    fi
    echo "=========================================="
    echo

    # Optionally drop to shell for debugging
    # Uncomment the line below to get a shell after tests
    # sh --login

    # Exit with test result
    exit $TEST_EXIT_CODE
else
    echo "Error: ptrace-tests binary not found at /usr/bin/ptrace-tests"
    echo "Please build the test disk image first:"
    echo "  make test-ptrace-disk"
    exit 1
fi
