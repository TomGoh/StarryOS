use core::sync::atomic::{AtomicBool, Ordering};

use axerrno::AxResult;
use axhal::uspace::UserContext;
use axtask::current;
use starry_core::task::{AsThread, Thread};
use starry_signal::{SignalOSAction, SignalSet};

use crate::task::{do_continue, do_exit_signal, do_stop};

pub fn check_signals(
    thr: &Thread,
    uctx: &mut UserContext,
    restore_blocked: Option<SignalSet>,
) -> bool {
    let Some((sig, os_action)) = thr.signal.check_signals(uctx, restore_blocked) else {
        return false;
    };

    let signo = sig.signo();
    match os_action {
        SignalOSAction::Terminate => {
            do_exit_signal(signo as i32, false, true);
        }
        SignalOSAction::CoreDump => {
            // TODO: implement actual core dump
            do_exit_signal(signo as i32, true, true);
        }
        SignalOSAction::Stop => {
            do_stop(signo as i32);
        }
        SignalOSAction::Continue => {
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