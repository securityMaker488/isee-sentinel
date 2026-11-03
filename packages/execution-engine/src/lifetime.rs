//! Process-lifetime protection for the one-shot, trusted-worker executable.
//! This module is the sole exception to the library's unsafe-code denial.
//! It does not provide a sandbox or enable arbitrary tool adapters.

use std::path::Path;
use std::process::Command;

#[cfg(windows)]
pub(super) fn configure(_: &mut Command, _: &Path) -> Result<&'static str, &'static str> {
    use std::os::windows::io::{AsRawHandle, FromRawHandle, IntoRawHandle, OwnedHandle};
    use std::sync::OnceLock;
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
        SetInformationJobObject,
    };
    use windows_sys::Win32::System::Threading::GetCurrentProcess;

    static INITIALIZED: OnceLock<Result<(), &'static str>> = OnceLock::new();
    let result = INITIALIZED.get_or_init(|| {
        // SAFETY: null attributes/name create an unnamed, non-inheritable job.
        // A non-null result is a unique owned handle, released on each error path.
        let raw = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
        if raw.is_null() {
            return Err("containment_unavailable");
        }
        // SAFETY: successful creation transfers this unique, valid handle to us.
        let job = unsafe { OwnedHandle::from_raw_handle(raw) };
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        // SAFETY: the initialized repr(C) buffer is live for this synchronous call,
        // its exact byte length matches the information class, and job is owned.
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
        // SAFETY: the job is empty and configured. The current-process pseudo
        // handle is valid and must not be closed. Assignment precedes child spawn,
        // so there is no uncontained child-start interval. No breakaway is enabled.
        if unsafe { AssignProcessToJobObject(job.as_raw_handle(), GetCurrentProcess()) } == 0 {
            return Err("containment_unavailable");
        }
        // Intentional process-lifetime handle: dropping it here would terminate
        // this process before it can emit a receipt. OnceLock bounds this to one
        // handle per process. The OS closes it on normal exit or forced death;
        // the handle is unnamed/non-inheritable, so children cannot keep it alive.
        let _process_lifetime_handle = job.into_raw_handle();
        Ok(())
    });
    (*result)?;
    Ok("windows_job")
}

#[cfg(target_os = "linux")]
pub(super) fn configure(
    command: &mut Command,
    python: &Path,
) -> Result<&'static str, &'static str> {
    use std::ffi::CString;
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::process::CommandExt;

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
    let path = CString::new(python.as_os_str().as_bytes()).map_err(|_| "invalid_configuration")?;
    // SAFETY: both strings are NUL-terminated/live; a null buffer with size zero
    // queries metadata size without reading capability contents.
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
    // SAFETY: after fork this closure only calls allocation-free Linux syscalls
    // and constructs raw OS errors. No locks, logging, heap buffers or environment
    // access. Check the parent after arming the signal to close the death-before-
    // prctl race. The spawning thread stays alive throughout supervision.
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
            Ok(())
        });
    }
    // Linux PDEATHSIG protects this direct child, not a descendant tree.
    Ok("linux_parent_death")
}

#[cfg(not(any(windows, target_os = "linux")))]
pub(super) fn configure(_: &mut Command, _: &Path) -> Result<&'static str, &'static str> {
    Err("unsupported_platform")
}
