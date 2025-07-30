use std::ffi::OsString;
use std::os::windows::ffi::OsStringExt;
use winapi::shared::minwindef::{DWORD, FALSE, MAX_PATH, ULONG};
use winapi::shared::ntdef::PUNICODE_STRING;
use winapi::shared::ntdef::{NTSTATUS, NULL, PVOID, USHORT, VOID};
use winapi::um::processthreadsapi::{
    GetThreadId, OpenProcess, OpenThread, ResumeThread, SuspendThread,
};
use winapi::um::winbase::QueryFullProcessImageNameW;
use winapi::um::winnt::{
    ACCESS_MASK, HANDLE, MAXIMUM_ALLOWED, PROCESS_QUERY_INFORMATION, PROCESS_SUSPEND_RESUME,
    PROCESS_VM_READ, THREAD_ALL_ACCESS, THREAD_GET_CONTEXT, THREAD_QUERY_INFORMATION, WCHAR,
};

pub use read_process_memory::{CopyAddress, Pid, ProcessHandle};

pub type Tid = Pid;

use super::Error;

#[cfg(feature = "unwind")]
mod symbolication;
#[cfg(feature = "unwind")]
mod unwinder;

#[cfg(feature = "unwind")]
pub use self::symbolication::Symbolicator;
#[cfg(feature = "unwind")]
pub use self::unwinder::Unwinder;

pub struct Process {
    pub pid: Pid,
    pub handle: ProcessHandle,
}

#[link(name = "ntdll")]
extern "system" {
    // using these undocumented api's seems to be the best way to suspend/resume a process
    // on windows (using the toolhelp32snapshot api to get threads doesn't seem practical tbh)
    // https://j00ru.vexillium.org/2009/08/suspending-processes-in-windows/
    fn RtlNtStatusToDosError(status: NTSTATUS) -> ULONG;
    fn NtSuspendProcess(process: HANDLE) -> NTSTATUS;
    fn NtResumeProcess(process: HANDLE) -> NTSTATUS;

    fn NtQueryInformationThread(
        thread: HANDLE,
        info_class: u32,
        info: PVOID,
        info_len: ULONG,
        ret_len: *mut ULONG,
    ) -> NTSTATUS;
    fn NtQueryInformationProcess(
        process: HANDLE,
        info_class: u32,
        info: PVOID,
        info_len: ULONG,
        ret_len: *mut ULONG,
    ) -> NTSTATUS;

    fn NtGetNextThread(
        process: HANDLE,
        thread: HANDLE,
        access: ACCESS_MASK,
        attributes: ULONG,
        flags: ULONG,
        new_thread: *mut HANDLE,
    ) -> NTSTATUS;
    fn NtGetNextProcess(
        process: HANDLE,
        access: ACCESS_MASK,
        attributes: ULONG,
        flags: ULONG,
        new_process: *mut HANDLE,
    ) -> NTSTATUS;

}

impl Process {
    pub fn new(pid: Pid) -> Result<Process, Error> {
        // we can't just use try_into_process_handle here because we need some additional permissions
        unsafe {
            let handle = OpenProcess(
                PROCESS_VM_READ
                    | PROCESS_SUSPEND_RESUME
                    | PROCESS_QUERY_INFORMATION
                    | THREAD_QUERY_INFORMATION
                    | THREAD_GET_CONTEXT,
                FALSE,
                pid,
            );
            if handle == (0 as std::os::windows::io::RawHandle) {
                return Err(Error::from(std::io::Error::last_os_error()));
            }
            Ok(Process {
                pid,
                handle: handle.into(),
            })
        }
    }

    pub fn handle(&self) -> ProcessHandle {
        self.handle.clone()
    }

    pub fn exe(&self) -> Result<String, Error> {
        unsafe {
            let mut size = MAX_PATH as DWORD;
            let mut filename: [WCHAR; MAX_PATH] = std::mem::zeroed();
            let ret = QueryFullProcessImageNameW(*self.handle, 0, filename.as_mut_ptr(), &mut size);
            if ret == 0 {
                return Err(std::io::Error::last_os_error().into());
            }
            Ok(OsString::from_wide(&filename[0..size as usize])
                .to_string_lossy()
                .into_owned())
        }
    }

    pub fn lock(&self) -> Result<Lock, Error> {
        Ok(Lock::new(self.handle.clone())?)
    }

    pub fn cwd(&self) -> Result<String, Error> {
        // TODO: get the CWD.
        // seems a little involved: http://wj32.org/wp/2009/01/24/howto-get-the-command-line-of-processes/
        // steps:
        //      1) NtQueryInformationProcess to get PebBaseAddress, which ProcessParameters
        //          is at some constant offset (+10 on 32 bit etc)
        //      2) ReadProcessMemory to get RTL_USER_PROCESS_PARAMETERS struct
        //      3) get CWD from the struct (has UNICODE_DATA object with ptr + length to CWD)
        unimplemented!("cwd is unimplemented on windows")
    }

    pub fn cmdline(&self) -> Result<Vec<String>, Error> {
        unsafe {
            // figure how much storage we need to allocate for cmdline.
            let mut size: ULONG = 0;
            NtQueryInformationProcess(
                *self.handle,
                60,
                std::ptr::null_mut(),
                0,
                &size as *const _ as *mut _,
            );
            if size == 0 {
                // the above call always fails (with an error like 'The program issued a command but the
                // command length is incorrect.'). It should set the size to how many chars we need to allocate
                // . If the size is still 0 though, default to some decently sized number
                size = 65536;
            }

            //  Get the commandline
            let storage = vec![0_u16; size as usize];
            let ret = NtQueryInformationProcess(
                *self.handle,
                60,
                (&storage as &[u16]) as *const _ as *mut _,
                size,
                &size as *const _ as *mut _,
            );

            if ret != 0 {
                return Err(Error::from(std::io::Error::from_raw_os_error(
                    RtlNtStatusToDosError(ret) as i32,
                )));
            }

            let unicode: PUNICODE_STRING = (&storage as &[u16]) as *const _ as *mut _;
            let chars =
                std::slice::from_raw_parts((*unicode).Buffer, (*unicode).Length as usize / 2);
            let mut ret = Vec::new();
            ret.push(String::from_utf16_lossy(chars));
            Ok(ret)
        }
    }

    pub fn threads(&self) -> Result<Vec<Thread>, Error> {
        let mut ret = Vec::new();
        unsafe {
            let mut thread: HANDLE = std::mem::zeroed();
            while NtGetNextThread(
                *self.handle,
                thread,
                MAXIMUM_ALLOWED,
                0,
                0,
                &mut thread as *mut HANDLE,
            ) == 0
            {
                ret.push(Thread {
                    thread: thread.into(),
                });
            }
        }
        Ok(ret)
    }

    pub fn child_processes(&self) -> Result<Vec<(Pid, Pid)>, Error> {
        let mut processes = std::collections::HashMap::new();
        unsafe {
            // we're using NtGetNextProcess - mainly because the TLHelp32 code
            // seemed crazy slow when I was first using it for getting the threads.
            // This does have a downside, in that this will include processes that
            // aren't the child of the current one and doesn't include the ppid.
            // SO we're also using NtQueryInformationProcess to get the PROCESS_BASIC_INFORMATION
            // to get the ppid and then later filter down to the correct list
            // This might be worth coming back to a later date and benchmarking
            // against tlhelp32 Process32First/Process32Next code - but seems to work
            // well enough for now
            let mut process: HANDLE = *self.handle;
            while NtGetNextProcess(process, MAXIMUM_ALLOWED, 0, 0, &mut process as *mut HANDLE) == 0
            {
                let mut basic_info = std::mem::zeroed::<PROCESS_BASIC_INFORMATION>();
                let size: ULONG = 0;
                let retcode = NtQueryInformationProcess(
                    process,
                    0,
                    &mut basic_info as *const _ as *mut _,
                    std::mem::size_of_val(&basic_info) as ULONG,
                    &size as *const _ as *mut _,
                );
                if retcode == 0 {
                    processes.insert(
                        basic_info.unique_process_id as Pid,
                        basic_info.inherited_from_unique_process_id as Pid,
                    );
                }
            }
        }
        Ok(crate::filter_child_pids(self.pid, &processes))
    }
    #[cfg(feature = "unwind")]
    pub fn unwinder(&self) -> Result<unwinder::Unwinder, Error> {
        unwinder::Unwinder::new(*self.handle)
    }
    #[cfg(feature = "unwind")]
    pub fn symbolicator(&self) -> Result<Symbolicator, Error> {
        Symbolicator::new(*self.handle)
    }
}

impl super::ProcessMemory for Process {
    fn read(&self, addr: usize, buf: &mut [u8]) -> Result<(), Error> {
        Ok(self.handle.copy_address(addr, buf)?)
    }
}

#[derive(Eq, PartialEq, Hash, Clone)]
pub struct Thread {
    thread: ProcessHandle,
}

impl Thread {
    pub fn new(tid: Tid) -> Result<Thread, Error> {
        // we can't just use try_into_prcess_handle here because we need some additional permissions
        unsafe {
            let thread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);
            if thread == (0 as std::os::windows::io::RawHandle) {
                return Err(Error::from(std::io::Error::last_os_error()));
            }

            Ok(Thread {
                thread: thread.into(),
            })
        }
    }
    pub fn lock(&self) -> Result<ThreadLock, Error> {
        ThreadLock::new(self.thread.clone())
    }

    pub fn id(&self) -> Result<Tid, Error> {
        unsafe { Ok(GetThreadId(*self.thread)) }
    }

    pub fn active(&self) -> Result<bool, Error> {
        // Getting whether a thread is active or not is surprisingly difficult on windows
        // we're getting the syscall the thread is doing here, and then checking against a list
        // of known waiting syscalls to get this
        unsafe {
            let mut data = std::mem::zeroed::<THREAD_LAST_SYSCALL_INFORMATION>();
            let ret = NtQueryInformationThread(
                *self.thread,
                21,
                &mut data as *mut _ as *mut VOID,
                std::mem::size_of::<THREAD_LAST_SYSCALL_INFORMATION>() as u32,
                NULL as *mut u32,
            );

            // if we're not in a syscall, we're active
            if ret != 0 {
                return Ok(true);
            }

            // otherwise assume we're idle
            Ok(false)
        }
    }
}

pub struct Lock {
    process: ProcessHandle,
}

impl Lock {
    pub fn new(process: ProcessHandle) -> Result<Lock, Error> {
        unsafe {
            let ret = NtSuspendProcess(*process);
            if ret != 0 {
                return Err(Error::from(std::io::Error::from_raw_os_error(
                    RtlNtStatusToDosError(ret) as i32,
                )));
            }
        }
        Ok(Lock { process })
    }
}

impl Drop for Lock {
    fn drop(&mut self) {
        unsafe {
            let ret = NtResumeProcess(*self.process);
            if ret != 0 {
                panic!(
                    "Failed to resume process: {}",
                    std::io::Error::from_raw_os_error(RtlNtStatusToDosError(ret) as i32)
                );
            }
        }
    }
}

pub struct ThreadLock {
    thread: ProcessHandle,
}

impl ThreadLock {
    pub fn new(thread: ProcessHandle) -> Result<ThreadLock, Error> {
        unsafe {
            let ret = SuspendThread(*thread);
            if ret.wrapping_add(1) == 0 {
                return Err(std::io::Error::last_os_error().into());
            }

            Ok(ThreadLock { thread })
        }
    }
}

impl Drop for ThreadLock {
    fn drop(&mut self) {
        unsafe {
            if ResumeThread(*self.thread).wrapping_add(1) == 0 {
                panic!(
                    "Failed to resume thread {}",
                    std::io::Error::last_os_error()
                );
            }
        }
    }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct THREAD_LAST_SYSCALL_INFORMATION {
    arg1: PVOID,
    syscall_number: USHORT,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
struct PROCESS_BASIC_INFORMATION {
    exit_status: NTSTATUS,
    peb_base_address: *mut libc::c_void,
    affinity_mask: *mut ULONG,
    base_priority: ULONG,
    unique_process_id: HANDLE,
    inherited_from_unique_process_id: HANDLE,
}

unsafe impl Send for Process {}
