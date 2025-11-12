use ptrace_tests::*;
use std::env;

mod test_attach;
mod test_control;
mod test_fork_events;
mod test_memory;
mod test_regs;
mod test_syscall;
mod test_traceme;

fn print_banner() {
    println!("\n{}", "=".repeat(60));
    println!(
        "{}  StarryOS Ptrace Test Suite  {}",
        COLOR_BLUE, COLOR_RESET
    );
    println!("{}", "=".repeat(60));
}

fn print_summary(total_passed: usize, total_failed: usize) {
    println!("\n{}", "=".repeat(60));
    println!("{}Test Summary:{}", COLOR_BLUE, COLOR_RESET);
    println!("  {}Passed: {}{}", COLOR_GREEN, total_passed, COLOR_RESET);
    if total_failed > 0 {
        println!("  {}Failed: {}{}", COLOR_RED, total_failed, COLOR_RESET);
    } else {
        println!("  {}Failed: {}{}", COLOR_GREEN, total_failed, COLOR_RESET);
    }
    println!("  Total:  {}", total_passed + total_failed);
    println!("{}", "=".repeat(60));

    if total_failed == 0 {
        println!("\n{}All tests passed!{}", COLOR_GREEN, COLOR_RESET);
    } else {
        println!("\n{}Some tests failed.{}", COLOR_RED, COLOR_RESET);
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();

    // Parse command line arguments
    let mut run_specific = None;
    let mut verbose = false;

    for arg in args.iter().skip(1) {
        match arg.as_str() {
            "-v" | "--verbose" => verbose = true,
            "-h" | "--help" => {
                print_usage(&args[0]);
                return;
            }
            s if s.starts_with("--test=") => {
                run_specific = Some(s.trim_start_matches("--test=").to_string());
            }
            _ => {
                eprintln!("Unknown argument: {}", arg);
                print_usage(&args[0]);
                std::process::exit(1);
            }
        }
    }

    print_banner();

    let mut total_passed = 0;
    let mut total_failed = 0;

    // Define test suites
    let test_suites: Vec<(&str, fn() -> (usize, usize))> = vec![
        ("traceme", test_traceme::run_all_tests),
        ("syscall", test_syscall::run_all_tests),
        ("regs", test_regs::run_all_tests),
        ("memory", test_memory::run_all_tests),
        ("control", test_control::run_all_tests),
        ("attach", test_attach::run_all_tests),
        ("fork_events", test_fork_events::run_all_tests),
    ];

    // Run tests
    for (suite_name, run_suite) in test_suites {
        // Skip if running specific suite and this isn't it
        if let Some(ref specific) = run_specific {
            if suite_name != specific {
                continue;
            }
        }

        println!(
            "\n{}Running {} tests...{}",
            COLOR_BLUE, suite_name, COLOR_RESET
        );

        let (passed, failed) = run_suite();
        total_passed += passed;
        total_failed += failed;

        if verbose {
            println!(
                "  {} tests: {} passed, {} failed",
                suite_name, passed, failed
            );
        }
    }

    // Print summary
    print_summary(total_passed, total_failed);

    // Exit with appropriate code
    if total_failed > 0 {
        std::process::exit(1);
    }
}

fn print_usage(program: &str) {
    println!("Usage: {} [OPTIONS]", program);
    println!("\nOptions:");
    println!("  -v, --verbose       Enable verbose output");
    println!(
        "  --test=<suite>      Run specific test suite (traceme, syscall, regs, memory, control, attach, fork_events)"
    );
    println!("  -h, --help          Print this help message");
    println!("\nExamples:");
    println!("  {}                  Run all tests", program);
    println!("  {} --test=traceme   Run only traceme tests", program);
    println!(
        "  {} -v               Run all tests with verbose output",
        program
    );
}
