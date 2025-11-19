use core::sync::atomic::{AtomicBool, Ordering};

use axerrno::AxResult;
use axhal::uspace::UserContext;
use axtask::current;
use starry_core::task::{AsThread, Thread};
use starry_signal::{SignalOSAction, SignalSet};
use axlog::info;

use crate::task::{do_continue, do_exit, do_stop};

pub fn check_signals(
    thr: &Thread,
    uctx: &mut UserContext,
    restore_blocked: Option<SignalSet>,
) -> bool {
    let Some((sig, os_action)) = thr.signal.check_signals(uctx, restore_blocked) else {
        return false;
    };

    let signo = sig.signo();

    // Stage 0: Ptrace signal-delivery-stop integration
    // If the process is being traced, stop and let the tracer decide what to do with the signal
    #[cfg(feature = "ptrace")]
    {
        // SIGKILL cannot be intercepted by ptrace
        if starry_ptrace::is_being_traced() && signo != starry_signal::Signo::SIGKILL {
            let action = starry_ptrace::signal_stop(signo as i32, uctx);

            match action {
                starry_ptrace::SignalAction::Suppress => {
                    // Tracer wants to suppress the signal - don't execute the signal handler
                    return true;
                }
                starry_ptrace::SignalAction::DeliverOriginal => {
                    // Tracer wants to deliver the original signal - fall through to match os_action
                }
                starry_ptrace::SignalAction::DeliverModified(new_sig) => {
                    // Tracer changed the signal - re-inject the new signal and return
                    // This will be processed on the next signal check
                    if let Some(new_signo) = starry_signal::Signo::from_repr(new_sig as u8) {
                        let sig_info = starry_signal::SignalInfo::new_kernel(new_signo);
                        let _ = starry_core::task::send_signal_to_process(
                            thr.proc_data.proc.pid(),
                            Some(sig_info),
                        );
                    }
                    return true;
                }
            }
        }
    }

    // Original signal handling logic
    match os_action {
        SignalOSAction::Terminate => {
            info!("{:?} terminated by signal {:?}", thr.proc_data.proc, signo);
            do_exit(128 + signo as i32, true, Some(signo), false);
        }
        SignalOSAction::CoreDump => {
            // TODO: implement core dump,
            // now the core_dumped is set to true as a indication without actual core dump
            info!("{:?} core dumped by signal {:?}", thr.proc_data.proc, signo);
            do_exit(128 + signo as i32, true, Some(signo), true);
        }
        SignalOSAction::Stop => {
            info!("{:?} stopped by signal {:?}", thr.proc_data.proc, signo);
            do_stop(signo as i32);
        }
        SignalOSAction::Continue => {
            info!("{:?} continued by signal {:?}", thr.proc_data.proc, signo);
            do_continue();
        }
        SignalOSAction::Handler => {
            // do nothing
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
