use core::sync::atomic::{AtomicBool, Ordering};

use axerrno::AxResult;
use axhal::uspace::UserContext;
use axtask::current;
use starry_core::task::{AsThread, Thread};
use starry_signal::{SignalOSAction, SignalSet};
use axlog::debug;

use crate::task::do_exit;

pub fn check_signals(
    thr: &Thread,
    uctx: &mut UserContext,
    restore_blocked: Option<SignalSet>,
) -> bool {
    let Some((sig, os_action)) = thr.signal.check_signals(uctx, restore_blocked) else {
        return false;
    };

    let signo = sig.signo();
    debug!("[PTRACE-DEBUG] check_signals: pid={} got signal {:?} action={:?}",
           thr.proc_data.proc.pid(), signo, os_action);

    // If under ptrace, ALL signal deliveries should stop the tracee first
    // (not just stop signals). This allows the tracer to intercept, modify, or suppress signals.
    #[cfg(feature = "ptrace")]
    {
        if starry_ptrace::is_being_traced() {
            let curr = current();
            let pid = curr.as_thread().proc_data.proc.pid();
            debug!("[PTRACE-DEBUG] check_signals: traced process, entering signal-delivery-stop for {:?} pid={}", signo, pid);
            // Enter ptrace signal stop; tracer will resume the tracee later.
            starry_ptrace::signal_stop(signo as i32, uctx);
            debug!("[PTRACE-DEBUG] check_signals: returned from signal-delivery-stop for {:?} pid={}", signo, pid);
            // After resuming, the tracer has decided what to do with the signal.
            // If we reach here, proceed with the original action (handler will execute, etc.)
        }
    }

    match os_action {
        SignalOSAction::Terminate => {
            do_exit(signo as i32, true);
        }
        SignalOSAction::CoreDump => {
            // TODO: implement core dump
            do_exit(128 + signo as i32, true);
        }
        SignalOSAction::Stop => {
            // Stop signals need special handling even without ptrace
            #[cfg(not(feature = "ptrace"))]
            {
                // Fallback (no ptrace support): exit with SIGHUP-equivalent code for now.
                // TODO: implement proper job control stop (WIFSTOPPED) semantics.
                do_exit(1, true);
            }
        }
        SignalOSAction::Continue => {
            // TODO: implement continue
        }
        SignalOSAction::Handler => {
            // do nothing - handler will execute
        }
    }
    true
}

static BLOCK_NEXT_SIGNAL_CHECK: AtomicBool = AtomicBool::new(false);

pub fn block_next_signal() {
    BLOCK_NEXT_SIGNAL_CHECK.store(true, Ordering::SeqCst);
}

pub fn unblock_next_signal() -> bool {
    BLOCK_NEXT_SIGNAL_CHECK.swap(false, Ordering::SeqCst)
}

pub fn with_replacen_blocked<R>(
    blocked: Option<SignalSet>,
    f: impl FnOnce() -> AxResult<R>,
) -> AxResult<R> {
    let curr = current();
    let sig = &curr.as_thread().signal;

    let old_blocked = blocked.map(|set| sig.set_blocked(set));
    f().inspect(|_| {
        if let Some(old) = old_blocked {
            sig.set_blocked(old);
        }
    })
}
