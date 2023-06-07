mod mach_thread_bindings;
mod utils;

use mach;
use std;
use std::convert::TryInto;

use super::Error;
use mach::kern_return::KERN_SUCCESS;
use mach::port::{mach_port_name_t, mach_port_t, MACH_PORT_NULL};
use mach::traps::{mach_task_self, task_for_pid};
use read_process_memory::{CopyAddress, ProcessHandle};

use libc::{c_int, c_void, pid_t};

use mach::kern_return::kern_return_t;
use mach::mach_types::thread_act_t;
use mach::structs::x86_thread_state64_t;
use mach::thread_act::thread_get_state;
use mach::thread_status::x86_THREAD_STATE64;
use mach::vm_types::{mach_vm_address_t, mach_vm_size_t};

pub use self::utils::{TaskLock, ThreadLock};

use libproc::libproc::proc_pid::{pidinfo, pidpath, PIDInfo, PidInfoFlavor};

pub type Pid = pid_t;
pub type Tid = u32;

pub struct Process {
    pub pid: Pid,
    pub task: mach_port_name_t,
}

#[derive(Eq, PartialEq, Hash, Copy, Clone)]
pub struct Thread {
    pub tid: Tid,
}

impl Process {
    pub fn new(pid: Pid) -> Result<Process, Error> {
        let mut task: mach_port_name_t = MACH_PORT_NULL;
        let result = unsafe { task_for_pid(mach_task_self(), pid as c_int, &mut task) };
        if result != KERN_SUCCESS {
            return Err(Error::IOError(std::io::Error::last_os_error()));
        }
        Ok(Process { pid, task })
    }

    pub fn exe(&self) -> Result<String, Error> {
        pidpath(self.pid).map_err(|e| Error::Other(format!("proc_pidpath failed: {}", e)))
    }

    pub fn cwd(&self) -> Result<String, Error> {
        let cwd = pidinfo::<proc_vnodepathinfo>(self.pid, 0)
            .map_err(|e| Error::Other(format!("proc_pidinfo failed: {}", e)))?;
        Ok(
            unsafe { std::ffi::CStr::from_ptr(cwd.pvi_cdir.vip_path.as_ptr()) }
                .to_string_lossy()
                .to_string(),
        )
    }

    pub fn cmdline(&self) -> Result<Vec<String>, Error> {
        unsafe {
            let mib: [i32; 3] = [libc::CTL_KERN, libc::KERN_PROCARGS2, self.pid];
            let args: [u8; 65536] = std::mem::zeroed();
            let size: usize = std::mem::size_of_val(&args);
            let ret = libc::sysctl(
                &mib as *const _ as *mut _,
                3,
                &args as *const _ as *mut _,
                &size as *const _ as *mut _,
                std::ptr::null_mut(),
                0,
            );

            if ret < 0 {
                return Err(Error::IOError(std::io::Error::last_os_error()));
            }

            // get the number of arguments
            let argcount: i32 = *(&args as *const _ as *const i32);
            let args = &args[std::mem::size_of_val(&argcount)..];

            // split off of the exe from the beginning
            let args = &args[libc::strlen(args as *const _ as *const i8)..];

            let mut ret = Vec::new();
            for arg in args.split(|b| *b == 0) {
                // ignore leading nulls
                if arg.len() == 0 && ret.len() == 0 {
                    continue;
                }

                let arg = String::from_utf8(arg.to_vec())
                    .map_err(|e| Error::Other(format!("Failed to convert utf8 {}", e)))?;

                ret.push(arg);
                if ret.len() >= argcount as usize {
                    break;
                }
            }
            Ok(ret)
        }
    }

    pub fn lock(&self) -> Result<TaskLock, Error> {
        Ok(TaskLock::new(self.task)?)
    }

    pub fn threads(&self) -> Result<Vec<Thread>, Error> {
        let mut threads: mach::mach_types::thread_act_array_t = unsafe { std::mem::zeroed() };
        let mut thread_count: u32 = 0;
        let result =
            unsafe { mach::task::task_threads(self.task, &mut threads, &mut thread_count) };
        if result != KERN_SUCCESS {
            return Err(Error::IOError(std::io::Error::last_os_error()));
        }

        let mut ret = Vec::new();
        for i in 0..thread_count {
            let tid = unsafe { *threads.offset(i as isize) };
            ret.push(Thread { tid });
        }

        let memsize = thread_count as usize * std::mem::size_of::<Tid>();
        unsafe {
            vm_deallocate(
                mach_task_self(),
                threads as mach_vm_address_t,
                memsize as mach_vm_size_t,
            );
        }
        Ok(ret)
    }

    pub fn child_processes(&self) -> Result<Vec<(Pid, Pid)>, Error> {
        fn recurse(pid: Pid, ret: &mut Vec<(Pid, Pid)>) -> Result<(), Error> {
            for child in childpids(pid)? {
                ret.push((child, pid));
                recurse(child, ret)?;
            }
            Ok(())
        }
        let mut ret = Vec::new();
        recurse(self.pid, &mut ret)?;
        Ok(ret)
    }
}

fn childpids(pid: Pid) -> Result<Vec<Pid>, Error> {
    let size = unsafe { proc_listchildpids(pid, std::ptr::null_mut(), 0) };
    if size < 0 {
        return Err(Error::IOError(std::io::Error::last_os_error()));
    }
    let mut ret: Vec<pid_t> = Vec::with_capacity(size as usize);
    let size = unsafe { proc_listchildpids(pid, ret.as_mut_ptr() as *mut _, size) };
    if size < 0 {
        return Err(Error::IOError(std::io::Error::last_os_error()));
    }
    unsafe {
        ret.set_len(size as usize);
    }
    Ok(ret)
}

impl super::ProcessMemory for Process {
    fn read(&self, addr: usize, buf: &mut [u8]) -> Result<(), Error> {
        let handle: ProcessHandle = self.task.try_into()?;
        Ok(handle.copy_address(addr, buf)?)
    }
}

use self::mach_thread_bindings::{
    thread_basic_info, thread_identifier_info, thread_info, THREAD_BASIC_INFO,
    THREAD_IDENTIFIER_INFO, TH_FLAGS_IDLE, TH_STATE_RUNNING,
};

extern "C" {
    fn vm_deallocate(
        target_task: mach_port_t,
        address: mach_vm_address_t,
        size: mach_vm_size_t,
    ) -> kern_return_t;
}

impl Thread {
    pub fn new(tid: Tid) -> Result<Thread, Error> {
        Ok(Thread { tid })
    }

    pub fn id(&self) -> Result<Tid, Error> {
        Ok(self.tid)
    }

    pub fn thread_handle(&self) -> Result<u64, Error> {
        let thread_id = self.get_thread_identifier_info()?;
        Ok(thread_id.thread_handle)
    }

    pub fn active(&self) -> Result<bool, Error> {
        let info = self.get_thread_basic_info()?;
        Ok(info.run_state == TH_STATE_RUNNING as i32 && info.flags & TH_FLAGS_IDLE as i32 == 0)
    }

    pub fn lock(&self) -> Result<ThreadLock, Error> {
        Ok(ThreadLock::new(self.tid)?)
    }

    pub fn registers(&self) -> Result<x86_thread_state64_t, std::io::Error> {
        unsafe {
            let thread_state = x86_thread_state64_t::new();
            let thread_state_size = x86_thread_state64_t::count();
            let result = thread_get_state(
                self.tid,
                x86_THREAD_STATE64,
                std::mem::transmute(&thread_state),
                std::mem::transmute(&thread_state_size),
            );
            if result != KERN_SUCCESS {
                return Err(std::io::Error::last_os_error());
            }
            Ok(thread_state)
        }
    }

    pub fn get_thread_basic_info(&self) -> Result<thread_basic_info, std::io::Error> {
        let mut info: thread_basic_info = unsafe { std::mem::zeroed() };
        let mut info_size: u32 =
            (std::mem::size_of::<thread_basic_info>() / std::mem::size_of::<i32>()) as u32;

        let result = unsafe {
            thread_info(
                self.tid,
                THREAD_BASIC_INFO,
                &mut info as *mut thread_basic_info as *mut i32,
                &mut info_size,
            )
        };
        if result != KERN_SUCCESS {
            return Err(std::io::Error::last_os_error());
        }
        Ok(info)
    }

    pub fn get_thread_identifier_info(&self) -> Result<thread_identifier_info, std::io::Error> {
        let mut thread_id: thread_identifier_info = unsafe { std::mem::zeroed() };
        let mut thread_id_size: u32 =
            (std::mem::size_of::<thread_identifier_info>() / std::mem::size_of::<i32>()) as u32;
        let result = unsafe {
            thread_info(
                self.tid,
                THREAD_IDENTIFIER_INFO,
                &mut thread_id as *mut thread_identifier_info as *mut i32,
                &mut thread_id_size,
            )
        };
        if result != KERN_SUCCESS {
            return Err(std::io::Error::last_os_error());
        }
        Ok(thread_id)
    }
}

// extra struct definitions needed to get CWD from proc_pidinfo
#[repr(C)]
#[derive(Copy, Clone)]
struct vnode_info_path {
    _opaque: [::std::os::raw::c_char; 152],
    pub vip_path: [::std::os::raw::c_char; 1024],
}
#[repr(C)]
#[derive(Copy, Clone)]
struct proc_vnodepathinfo {
    pub pvi_cdir: vnode_info_path,
    pub pvi_rdir: vnode_info_path,
}
impl Default for proc_vnodepathinfo {
    fn default() -> Self {
        unsafe { ::std::mem::zeroed() }
    }
}
impl PIDInfo for proc_vnodepathinfo {
    fn flavor() -> PidInfoFlavor {
        PidInfoFlavor::VNodePathInfo
    }
}

#[cfg(target_os = "macos")]
#[link(name = "proc", kind = "dylib")]
extern "C" {
    fn proc_listchildpids(pid: pid_t, buffer: *mut c_void, buffersize: c_int) -> c_int;
}
