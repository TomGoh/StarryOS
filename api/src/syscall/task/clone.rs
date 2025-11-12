use alloc::sync::Arc;

use axerrno::{AxError, AxResult};
use axfs_ng::FS_CONTEXT;
use axhal::uspace::UserContext;
use axtask::{TaskExtProxy, current, spawn_task};
use bitflags::bitflags;
use kspin::SpinNoIrq;
use linux_raw_sys::general::*;
use starry_core::{
    mm::copy_from_kernel,
    task::{AsThread, ProcessData, Thread, add_task_to_table},
};
use starry_process::Pid;
use starry_signal::Signo;

use crate::{
    file::{FD_TABLE, FileLike, PidFd},
    mm::UserPtr,
    task::new_user_task,
};

bitflags! {
    /// Options for use with [`sys_clone`].
    #[derive(Debug, Clone, Copy, Default)]
    struct CloneFlags: u32 {
        /// The calling process and the child process run in the same
        /// memory space.
        const VM = CLONE_VM;
        /// The caller and the child process share the same  filesystem
        /// information.
        const FS = CLONE_FS;
        /// The calling process and the child process share the same file
        /// descriptor table.
        const FILES = CLONE_FILES;
        /// The calling process and the child process share the same table
        /// of signal handlers.
        const SIGHAND = CLONE_SIGHAND;
        /// Sets pidfd to the child process's PID file descriptor.
        const PIDFD = CLONE_PIDFD;
        /// If the calling process is being traced, then trace the child
        /// also.
        const PTRACE = CLONE_PTRACE;
        /// The execution of the calling process is suspended until the
        /// child releases its virtual memory resources via a call to
        /// execve(2) or _exit(2) (as with vfork(2)).
        const VFORK = CLONE_VFORK;
        /// The parent of the new child  (as returned by getppid(2))
        /// will be the same as that of the calling process.
        const PARENT = CLONE_PARENT;
        /// The child is placed in the same thread group as the calling
        /// process.
        const THREAD = CLONE_THREAD;
        /// The cloned child is started in a new mount namespace.
        const NEWNS = CLONE_NEWNS;
        /// The child and the calling process share a single list of System
        /// V semaphore adjustment values
        const SYSVSEM = CLONE_SYSVSEM;
        /// The TLS (Thread Local Storage) descriptor is set to tls.
        const SETTLS = CLONE_SETTLS;
        /// Store the child thread ID in the parent's memory.
        const PARENT_SETTID = CLONE_PARENT_SETTID;
        /// Clear (zero) the child thread ID in child memory when the child
        /// exits, and do a wakeup on the futex at that address.
        const CHILD_CLEARTID = CLONE_CHILD_CLEARTID;
        /// A tracing process cannot force `CLONE_PTRACE` on this child
        /// process.
        const UNTRACED = CLONE_UNTRACED;
        /// Store the child thread ID in the child's memory.
        const CHILD_SETTID = CLONE_CHILD_SETTID;
        /// Create the process in a new cgroup namespace.
        const NEWCGROUP = CLONE_NEWCGROUP;
        /// Create the process in a new UTS namespace.
        const NEWUTS = CLONE_NEWUTS;
        /// Create the process in a new IPC namespace.
        const NEWIPC = CLONE_NEWIPC;
        /// Create the process in a new user namespace.
        const NEWUSER = CLONE_NEWUSER;
        /// Create the process in a new PID namespace.
        const NEWPID = CLONE_NEWPID;
        /// Create the process in a new network namespace.
        const NEWNET = CLONE_NEWNET;
        /// The new process shares an I/O context with the calling process.
        const IO = CLONE_IO;
    }
}

pub fn sys_clone(
    uctx: &UserContext,
    flags: u32,
    stack: usize,
    parent_tid: usize,
    #[cfg(any(target_arch = "x86_64", target_arch = "loongarch64"))] child_tid: usize,
    tls: usize,
    #[cfg(not(any(target_arch = "x86_64", target_arch = "loongarch64")))] child_tid: usize,
) -> AxResult<isize> {
    const FLAG_MASK: u32 = 0xff;
    let exit_signal = flags & FLAG_MASK;
    let mut flags = CloneFlags::from_bits_truncate(flags & !FLAG_MASK);
    if flags.contains(CloneFlags::VFORK) {
        debug!("sys_clone: CLONE_VFORK slow path");
        flags.remove(CloneFlags::VM);
    }

    debug!(
        "sys_clone <= flags: {flags:?}, exit_signal: {exit_signal}, stack: {stack:#x}, ptid: \
         {parent_tid:#x}, ctid: {child_tid:#x}, tls: {tls:#x}"
    );

    if exit_signal != 0 && flags.contains(CloneFlags::THREAD | CloneFlags::PARENT) {
        return Err(AxError::InvalidInput);
    }
    if flags.contains(CloneFlags::THREAD) && !flags.contains(CloneFlags::VM | CloneFlags::SIGHAND) {
        return Err(AxError::InvalidInput);
    }
    if flags.contains(CloneFlags::PIDFD | CloneFlags::PARENT_SETTID) {
        return Err(AxError::InvalidInput);
    }
    let exit_signal = Signo::from_repr(exit_signal as u8);

    let mut new_uctx = *uctx;
    if stack != 0 {
        new_uctx.set_sp(stack);
    }
    if flags.contains(CloneFlags::SETTLS) {
        new_uctx.set_tls(tls);
    }
    new_uctx.set_retval(0);

    let set_child_tid = if flags.contains(CloneFlags::CHILD_SETTID) {
        Some(UserPtr::<u32>::from(child_tid).get_as_mut()?)
    } else {
        None
    };

    let curr = current();
    let old_proc_data = &curr.as_thread().proc_data;

    let mut new_task = new_user_task(&curr.name(), new_uctx, set_child_tid);

    let tid = new_task.id().as_u64() as Pid;
    if flags.contains(CloneFlags::PARENT_SETTID) {
        *UserPtr::<Pid>::from(parent_tid).get_as_mut()? = tid;
    }

    let new_proc_data = if flags.contains(CloneFlags::THREAD) {
        new_task
            .ctx_mut()
            .set_page_table_root(old_proc_data.aspace.lock().page_table_root());
        old_proc_data.clone()
    } else {
        let proc = if flags.contains(CloneFlags::PARENT) {
            old_proc_data.proc.parent().ok_or(AxError::InvalidInput)?
        } else {
            old_proc_data.proc.clone()
        }
        .fork(tid);

        let aspace = if flags.contains(CloneFlags::VM) {
            old_proc_data.aspace.clone()
        } else {
            let mut aspace = old_proc_data.aspace.lock();
            let aspace = aspace.try_clone()?;
            copy_from_kernel(&mut aspace.lock())?;
            aspace
        };
        new_task
            .ctx_mut()
            .set_page_table_root(aspace.lock().page_table_root());

        let signal_actions = if flags.contains(CloneFlags::SIGHAND) {
            old_proc_data.signal.actions.clone()
        } else {
            Arc::new(SpinNoIrq::new(old_proc_data.signal.actions.lock().clone()))
        };
        let proc_data = ProcessData::new(
            proc,
            old_proc_data.exe_path.read().clone(),
            old_proc_data.cmdline.read().clone(),
            aspace,
            signal_actions,
            exit_signal,
        );
        proc_data.set_umask(old_proc_data.umask());

        {
            let mut scope = proc_data.scope.write();
            if flags.contains(CloneFlags::FILES) {
                FD_TABLE.scope_mut(&mut scope).clone_from(&FD_TABLE);
            } else {
                FD_TABLE
                    .scope_mut(&mut scope)
                    .write()
                    .clone_from(&FD_TABLE.read());
            }

            if flags.contains(CloneFlags::FS) {
                FS_CONTEXT.scope_mut(&mut scope).clone_from(&FS_CONTEXT);
            } else {
                FS_CONTEXT
                    .scope_mut(&mut scope)
                    .lock()
                    .clone_from(&FS_CONTEXT.lock());
            }
        }

        proc_data
    };

    new_proc_data.proc.add_thread(tid);

    if flags.contains(CloneFlags::PIDFD) {
        let pidfd = PidFd::new(&new_proc_data);
        *UserPtr::<i32>::from(parent_tid).get_as_mut()? = pidfd.add_to_fd_table(true)?;
    }

    let thr = Thread::new(tid, new_proc_data);
    if flags.contains(CloneFlags::CHILD_CLEARTID) {
        thr.set_clear_child_tid(child_tid);
    }
    *new_task.task_ext_mut() = Some(unsafe { TaskExtProxy::from_impl(thr) });

    let task = spawn_task(new_task);
    add_task_to_table(&task);

    #[cfg(feature = "ptrace")]
    {
        // Only when ptrace feature is enabled
        // We report fork/clone events to the tracer if needed
        let child_pid = tid;
        // We exclude THREAD clones from ptrace fork events since they are not new processes
        if !flags.contains(CloneFlags::THREAD) {
            notify_ptrace_fork_event(&curr, child_pid, flags, uctx)?;
        }
    }

    Ok(tid as _)
}

/// Notify the ptrace tracer, if any, of a fork/vfork/clone event happend to the current tracee.
/// 
/// TODO: We may refactor this into a more general ptrace notification system later, not just place it here.
/// 
/// What this function does here is:
/// 1. Check if the parent process is being traced, and if so, whether the ptrace options indicate
///   that we should generate a fork/vfork/clone event.
/// 2. If so, set up the child process to be traced by the same tracer (if CLONE_PTRACE is set or event is generated).
/// 3. Then, stop the child process with a SIGSTOP if it is being traced.
/// 4. Finally, stop the parent process with the appropriate ptrace event (Fork/Vfork/Clone).
/// 5. The function returns Ok(()) if everything goes well, or an AxError if any error occurs.
/// 
/// Arguments:
/// - `parent_task`: The parent task that is forking.
/// - `child_pid`: The PID of the newly created child process.
/// - `clone_flags`: The clone flags used during the fork.
/// - `uctx`: The user context of the current parent tracee process
#[cfg(feature = "ptrace")]
fn notify_ptrace_fork_event(
    parent_task: &axtask::AxTaskRef,
    child_pid: Pid,
    clone_flags: CloneFlags,
    uctx: &UserContext,
) -> AxResult<()> {
    use starry_ptrace::{PtraceOptions, StopReason, stop_current_and_wait};

    let parent_pid = parent_task.as_thread().proc_data.proc.pid();
    let parent_state = starry_ptrace::ensure_state_for_pid(parent_pid)?;

    // Step 1&2: Check if parent is being traced and determine if we should generate a ptrace event
    let parent_info = parent_state.with(|pst| {
        if !pst.being_traced {
            return (None, None); // Not traced, nothing to do
        }

        // Step 2: Determine if we should generate a ptrace event (and stop parent)
        // Based on clone_flags combined with the ptrace options
        let event = if clone_flags.contains(CloneFlags::VFORK)
            && pst.options.contains(PtraceOptions::TRACEVFORK)
        {
            Some(StopReason::Vfork(child_pid))
        } else if clone_flags.contains(CloneFlags::THREAD)
            && pst.options.contains(PtraceOptions::TRACECLONE)
        {
            Some(StopReason::Clone(child_pid))
        } else if !clone_flags.contains(CloneFlags::VFORK)
            && !clone_flags.contains(CloneFlags::THREAD)
            && pst.options.contains(PtraceOptions::TRACEFORK)
        {
            // Regular fork (not vfork, not thread)
            Some(StopReason::Fork(child_pid))
        } else {
            None // No ptrace event, but might still inherit tracing via CLONE_PTRACE
        };

        (pst.tracer, event)
    });

    let (tracer, event) = parent_info;

    // Step 3: Set up child tracing inheritance FIRST (before stopping parent)
    // This prevents a race condition where the tracer might try to wait for the child
    // before it's marked as traced, and this race condition can potential lead to a hang.
    // 
    // Child should be traced if:
    // - Parent stopped with a fork/vfork/clone event (TRACEFORK/VFORK/CLONE options), OR
    // - CLONE_PTRACE flag is set and parent is being traced
    let should_trace_child =
        event.is_some() || (clone_flags.contains(CloneFlags::PTRACE) && tracer.is_some());

    if should_trace_child {
        debug!(
            "[PTRACE-DEBUG] About to set up tracing for child pid={} by tracer={:?}",
            child_pid, tracer
        );
        // ensure the new child process has a ptrace state by updating its being_traced and tracer fields
        let child_state = starry_ptrace::ensure_state_for_pid(child_pid)?;
        child_state.with_mut(|cst| {
            cst.being_traced = true;
            cst.tracer = tracer;
            debug!(
                "[PTRACE-DEBUG] Set child pid={} being_traced=true, tracer={:?}",
                child_pid, tracer
            );
        });
        debug!(
            "[PTRACE-DEBUG] Child pid={} will be traced by {:?}",
            child_pid, tracer
        );

        // Step 4: Child should start stopped (with SIGSTOP) if this was a ptrace event
        // From ptrace(2): "children...are automatically attached to the same tracer...
        // and will start with a SIGSTOP"
        if event.is_some() {
            use starry_core::task::send_signal_to_process;

            let sig_stop = starry_signal::SignalInfo::new_kernel(Signo::SIGSTOP);
            if let Err(e) = send_signal_to_process(child_pid, Some(sig_stop)) {
                debug!(
                    "[PTRACE-DEBUG] Failed to send SIGSTOP to child pid={}: {:?}",
                    child_pid, e
                );
                // Don't fail the whole operation if we can't send SIGSTOP
                // The child can still be traced, just not initially stopped
                // So, nothing to rollback here, no previous modified states would be changed
            } else {
                debug!(
                    "[PTRACE-DEBUG] Child pid={} will start with SIGSTOP",
                    child_pid
                );
            }
        }
    }

    // Step 5: Now stop the parent tracee with the fork/vfork/clone event
    // The child is already set up as traced, so the tracer can immediately wait for it
    if let Some(stop_reason) = event {
        debug!(
            "[PTRACE-DEBUG] Stopping parent pid={} for {:?}",
            parent_pid, stop_reason
        );
        stop_current_and_wait(stop_reason, uctx);
        debug!(
            "[PTRACE-DEBUG] Parent pid={} resumed from {:?}",
            parent_pid, stop_reason
        );
    }

    Ok(())
}

#[cfg(target_arch = "x86_64")]
pub fn sys_fork(uctx: &UserContext) -> AxResult<isize> {
    sys_clone(uctx, SIGCHLD, 0, 0, 0, 0)
}
