//! Process-lifetime protection for the one-shot, trusted-worker executable.
//! This module is the sole exception to the library's unsafe-code denial.
//! It does not provide a sandbox and does not enable arbitrary tool adapters.

use std::path::Path;
use std::process::{Child, Command};

/// Wall-clock headroom, in milliseconds, kept between the request timeout and
/// the OS backstop that terminates a worker the supervisor failed to reap.
const BACKSTOP_MARGIN_MS: u64 = 60_000;

/// OS lifetime controls bound to one supervised worker.
pub(super) struct Guard {
    mode: &'static str,
    #[cfg(windows)]
    backstop_ms: u64,
    #[cfg(windows)]
    tree: Option<windows::Tree>,
    #[cfg(target_os = "linux")]
    group: Option<i32>,
}

impl Guard {
    /// Identity of the OS containment in force, reported in the receipt.
    pub(super) fn mode(&self) -> &'static str {
        self.mode
    }

    /// Binds the spawned worker to the container that owns its descendants.
    /// Failure is closed: the caller must never run an uncontained worker.
    pub(super) fn contain(&mut self, child: &Child) -> Result<(), &'static str> {
        #[cfg(windows)]
        {
            self.tree = Some(windows::Tree::new(child, self.backstop_ms)?);
            Ok(())
        }
        #[cfg(target_os = "linux")]
        {
            self.group = Some(linux::bind_group(child));
            Ok(())
        }
        #[cfg(not(any(windows, target_os = "linux")))]
        {
            let _ = child;
            Err("unsupported_platform")
        }
    }

    /// Kills the worker and every descendant still inside the container.
    /// Safe to call repeatedly: a terminated or empty container is not an error.
    pub(super) fn terminate_tree(&mut self) {
        #[cfg(windows)]
        {
            if let Some(tree) = &self.tree {
                tree.terminate();
            }
        }
        #[cfg(target_os = "linux")]
        {
            if let Some(group) = self.group {
                linux::terminate_group(group);
            }
        }
    }
}

/// Arms the OS lifetime controls before the worker is spawned.
pub(super) fn prepare(
    command: &mut Command,
    python: &Path,
    timeout_ms: u64,
) -> Result<Guard, &'static str> {
    #[cfg(windows)]
    {
        // The worker inherits this job; the tree job is created after spawn.
        let _ = (command, python);
        let backstop_ms = timeout_ms.saturating_add(BACKSTOP_MARGIN_MS);
        windows::ensure_supervisor_job()?;
        Ok(Guard {
            mode: "windows_job_tree",
            backstop_ms,
            tree: None,
        })
    }
    #[cfg(target_os = "linux")]
    {
        let backstop_ms = timeout_ms.saturating_add(BACKSTOP_MARGIN_MS);
        linux::prepare(command, python, backstop_ms)?;
        Ok(Guard {
            mode: "linux_process_group",
            group: None,
        })
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        let _ = (command, python, timeout_ms);
        Err("unsupported_platform")
    }
}

#[cfg(windows)]
mod windows {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle};
    use std::process::Child;
    use std::sync::OnceLock;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_JOB_MEMORY, JOB_OBJECT_LIMIT_JOB_TIME, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    /// Ceiling for the memory committed by the worker tree.
    const TREE_MEMORY_LIMIT: u64 = 512 * 1024 * 1024;
    /// Ceiling for processes alive at once inside the worker tree.
    const TREE_PROCESS_LIMIT: u32 = 64;
    /// Exit code recorded for processes killed by the worker tree.
    const TREE_EXIT_CODE: u32 = 1;

    static SUPERVISOR_JOB: OnceLock<Result<(), &'static str>> = OnceLock::new();

    /// Job that owns the worker tree and can be terminated on demand.
    pub(super) struct Tree {
        job: OwnedHandle,
    }

    impl Tree {
        /// Creates the worker tree and adopts the spawned worker into it.
        pub(super) fn new(child: &Child, backstop_ms: u64) -> Result<Self, &'static str> {
            let job = create_job(
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
                    | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
                    | JOB_OBJECT_LIMIT_JOB_MEMORY
                    | JOB_OBJECT_LIMIT_JOB_TIME,
                TREE_PROCESS_LIMIT,
                TREE_MEMORY_LIMIT,
                backstop_ms.saturating_mul(10_000),
            )?;
            // SAFETY: the job is empty and configured, and the worker handle is
            // live and owned by the caller. The worker already inherited the
            // supervisor job, so this assignment nests a job inside it
            // (Windows 8 and later, proven on the deployment host). No breakaway
            // flag is set, so descendants created later stay inside the tree.
            if unsafe { AssignProcessToJobObject(job.as_raw_handle(), child.as_raw_handle()) } == 0
            {
                return Err("containment_unavailable");
            }
            Ok(Self { job })
        }

        /// Kills every process still inside the tree.
        pub(super) fn terminate(&self) {
            // SAFETY: the handle refers to a live job owned by this tree; the
            // call only terminates members and never closes the handle.
            unsafe { TerminateJobObject(self.job.as_raw_handle(), TREE_EXIT_CODE) };
        }
    }

    /// Places this supervisor inside an unnamed job that owns every worker
    /// descendant. Closing the job (normal exit or forced death) kills them.
    pub(super) fn ensure_supervisor_job() -> Result<(), &'static str> {
        let result = SUPERVISOR_JOB.get_or_init(|| {
            let job = create_job(JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, 0, 0, 0)?;
            // SAFETY: the job is empty and configured. The current-process pseudo
            // handle is valid and must not be closed. Assignment precedes child
            // spawn, so there is no uncontained child-start interval.
            if unsafe { AssignProcessToJobObject(job.as_raw_handle(), GetCurrentProcess()) } == 0 {
                return Err("containment_unavailable");
            }
            // Intentional process-lifetime handle: dropping it here would
            // terminate this process before it can emit a receipt. OnceLock
            // bounds this to one handle per process. The OS closes it on normal
            // exit or forced death; the handle is unnamed and non-inheritable,
            // so children cannot keep it alive.
            let _process_lifetime_handle = job.into_raw_handle();
            Ok(())
        });
        *result
    }

    fn create_job(
        flags: u32,
        active_processes: u32,
        job_memory: u64,
        job_time_100ns: u64,
    ) -> Result<OwnedHandle, &'static str> {
        // SAFETY: null attributes and name create an unnamed, non-inheritable job.
        // A non-null result is a unique owned handle, released on each error path.
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err("containment_unavailable");
        }
        // SAFETY: successful creation transfers this unique, valid handle to us.
        let job = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = flags;
        limits.BasicLimitInformation.ActiveProcessLimit = active_processes;
        limits.JobMemoryLimit = job_memory as usize;
        limits.BasicLimitInformation.PerJobUserTimeLimit = job_time_100ns as i64;
        // SAFETY: the initialized repr(C) buffer is live for this synchronous
        // call, its exact byte length matches the information class, and the job
        // handle is owned by this scope.
        if unsafe {
            SetInformationJobObject(
                job.as_raw_handle(),
                JobObjectExtendedLimitInformation,
                (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
                std::mem::size_of_val(&limits) as u32,
            )
        } == 0
        {
            return Err("containment_unavailable");
        }
        Ok(job)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;
    use std::path::Path;
    use std::process::{Child, Command};

    /// Ceiling for the data segment held by the worker tree.
    const TREE_MEMORY_LIMIT: u64 = 1024 * 1024 * 1024;
    /// Ceiling for bytes written by the worker tree.
    const TREE_FILE_LIMIT: u64 = 64 * 1024 * 1024;
    /// Ceiling for descriptors held by the worker tree.
    const TREE_DESCRIPTOR_LIMIT: u64 = 256;

    /// Arms the worker process group and the OS resource backstops before exec.
    pub(super) fn prepare(
        command: &mut Command,
        python: &Path,
        backstop_ms: u64,
    ) -> Result<(), &'static str> {
        // Privileged executables can clear PDEATHSIG on exec. The only supported
        // interpreter is deployment-owned Python without set-ID bits or capabilities.
        if python
            .metadata()
            .map_err(|_| "invalid_configuration")?
            .permissions()
            .mode()
            & 0o6000
            != 0
        {
            return Err("privileged_interpreter");
        }
        let path =
            CString::new(python.as_os_str().as_bytes()).map_err(|_| "invalid_configuration")?;
        // SAFETY: both strings are NUL-terminated and live; a null buffer with
        // size zero queries metadata size without reading capability contents.
        let capability = unsafe {
            libc::getxattr(
                path.as_ptr(),
                c"security.capability".as_ptr(),
                std::ptr::null_mut(),
                0,
            )
        };
        if capability >= 0 {
            return Err("privileged_interpreter");
        }
        let errno = io::Error::last_os_error().raw_os_error();
        if errno != Some(libc::ENODATA) && errno != Some(libc::EOPNOTSUPP) {
            return Err("containment_unavailable");
        }
        let parent = std::process::id() as libc::pid_t;
        let cpu_soft = (backstop_ms / 1000).max(1) as libc::rlim_t;
        let cpu_hard = cpu_soft.saturating_add(60) as libc::rlim_t;
        // SAFETY: after fork this closure only calls allocation-free Linux
        // syscalls and constructs raw OS errors. No locks, logging, heap buffers
        // or environment access. Check the parent after arming the signal to
        // close the death-before-prctl race. The spawning thread stays alive.
        unsafe {
            command.pre_exec(move || {
                if libc::prctl(
                    libc::PR_SET_NO_NEW_PRIVS,
                    1_usize,
                    0_usize,
                    0_usize,
                    0_usize,
                ) != 0
                    || libc::prctl(
                        libc::PR_SET_PDEATHSIG,
                        libc::SIGKILL as usize,
                        0_usize,
                        0_usize,
                        0_usize,
                    ) != 0
                {
                    return Err(io::Error::last_os_error());
                }
                if libc::getppid() != parent {
                    return Err(io::Error::from_raw_os_error(libc::ECANCELED));
                }
                // The worker becomes its own process group leader, so the
                // supervisor can terminate the whole tree on cancellation.
                if libc::setpgid(0, 0) != 0 {
                    return Err(io::Error::last_os_error());
                }
                set_limit(libc::RLIMIT_CPU, cpu_soft, cpu_hard)?;
                set_limit(libc::RLIMIT_DATA, TREE_MEMORY_LIMIT, TREE_MEMORY_LIMIT)?;
                set_limit(libc::RLIMIT_FSIZE, TREE_FILE_LIMIT, TREE_FILE_LIMIT)?;
                set_limit(
                    libc::RLIMIT_NOFILE,
                    TREE_DESCRIPTOR_LIMIT,
                    TREE_DESCRIPTOR_LIMIT,
                )?;
                Ok(())
            });
        }
        Ok(())
    }

    /// Confirms the worker group so a group signal cannot miss the worker.
    pub(super) fn bind_group(child: &Child) -> i32 {
        let group = child.id() as i32;
        // SAFETY: the supervisor may only move its own child into a group, and
        // the worker already called setpgid before exec. A failure here only
        // means the group was established first, so the error is not actionable.
        unsafe { libc::setpgid(group, group) };
        group
    }

    /// Kills every process still inside the worker group.
    pub(super) fn terminate_group(group: i32) {
        if group <= 1 {
            return;
        }
        // SAFETY: a negative pid targets the whole process group. The
        // supervisor is never a member of the worker group, so this cannot
        // reach the supervisor itself.
        unsafe { libc::kill(-group, libc::SIGKILL) };
    }

    fn set_limit(
        resource: libc::__rlimit_resource_t,
        soft: u64,
        hard: u64,
    ) -> Result<(), io::Error> {
        let limit = libc::rlimit {
            rlim_cur: soft as libc::rlim_t,
            rlim_max: hard as libc::rlim_t,
        };
        // SAFETY: the limit structure is initialized and describes this
        // process; setrlimit only records the new soft and hard bounds.
        if unsafe { libc::setrlimit(resource, &limit) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}
