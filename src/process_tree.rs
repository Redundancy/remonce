//! Stopping a command together with everything it started.
//!
//! Killing only the process the agent spawned leaves its children running:
//! a shell script's `sleep`, a wrapper's real worker. Each command is
//! therefore started at the head of its own process group (Unix) or inside
//! its own Job Object (Windows), and a timeout or shutdown stops the whole
//! of it.
//!
//! Only the agent stopping a command does this. A command that exits by
//! itself and leaves something running on purpose keeps it.

/// The processes a spawned command heads.
pub struct ProcessTree {
    inner: imp::Tree,
}

/// Make `command` start at the head of a tree of its own. Call before
/// spawning it.
pub fn isolate(command: &mut tokio::process::Command) {
    imp::isolate(command);
}

impl ProcessTree {
    /// The tree `child` heads. Call right after spawning it. If the tree
    /// can't be set up, `kill` reaches only what the platform lets it, and
    /// the caller should still kill `child` itself.
    pub fn of(child: &tokio::process::Child) -> Self {
        ProcessTree {
            inner: imp::Tree::of(child),
        }
    }

    /// Kill every process in the tree. The caller still reaps the child.
    pub fn kill(&self) {
        self.inner.kill();
    }
}

#[cfg(unix)]
mod imp {
    pub fn isolate(command: &mut tokio::process::Command) {
        // Process group 0: a new group led by the child, so its pid is the
        // group's id.
        command.process_group(0);
    }

    pub struct Tree {
        /// The child's pid, which is also its process group's id.
        pgid: Option<i32>,
    }

    impl Tree {
        pub fn of(child: &tokio::process::Child) -> Self {
            Tree {
                pgid: child.id().and_then(|pid| i32::try_from(pid).ok()),
            }
        }

        pub fn kill(&self) {
            if let Some(pgid) = self.pgid {
                // SAFETY: killpg takes plain integers. The group exists at
                // least as long as the child is unreaped, which is when
                // this is called; a group that is already empty is ESRCH.
                unsafe {
                    libc::killpg(pgid, libc::SIGKILL);
                }
            }
        }
    }
}

#[cfg(windows)]
mod imp {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{AssignProcessToJobObject, CreateJobObjectW, TerminateJobObject};

    pub fn isolate(_command: &mut tokio::process::Command) {
        // Nothing to set before spawning: the child joins a job right after.
    }

    pub struct Tree {
        /// The job holding the child and whatever it starts, or `None` if
        /// one couldn't be set up.
        job: Option<Job>,
    }

    struct Job(HANDLE);

    // SAFETY: a job handle is a kernel object reference that any thread may
    // use; nothing about it is tied to the thread that created it.
    unsafe impl Send for Job {}
    unsafe impl Sync for Job {}

    impl Drop for Job {
        fn drop(&mut self) {
            // SAFETY: the handle came from CreateJobObjectW and is closed
            // once. Closing it leaves the job's processes running.
            unsafe {
                CloseHandle(self.0);
            }
        }
    }

    impl Tree {
        pub fn of(child: &tokio::process::Child) -> Self {
            let Some(process) = child.raw_handle() else {
                return Tree { job: None };
            };
            // SAFETY: null attributes and name ask for an unnamed job with
            // default security; the result is checked before use.
            let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            if handle.is_null() {
                tracing::warn!(
                    "Could not create a job for the command ({}); a timeout will stop only its first process",
                    std::io::Error::last_os_error()
                );
                return Tree { job: None };
            }
            let job = Job(handle);
            // Processes the child starts from here on join the job with it.
            // One it started in the instant before this would not; a command
            // can't usefully do that before it has run.
            //
            // SAFETY: both handles are valid for the duration of the call.
            if unsafe { AssignProcessToJobObject(job.0, process as HANDLE) } == 0 {
                tracing::warn!(
                    "Could not put the command in a job ({}); a timeout will stop only its first process",
                    std::io::Error::last_os_error()
                );
                return Tree { job: None };
            }
            Tree { job: Some(job) }
        }

        pub fn kill(&self) {
            if let Some(job) = &self.job {
                // SAFETY: the handle is valid while `job` is alive.
                unsafe {
                    TerminateJobObject(job.0, 1);
                }
            }
        }
    }
}
