use libc::{c_int, c_void, lwpid_t, pid_t};
use libc::{PIOD_READ_D, PT_ATTACH, PT_DETACH, PT_IO};

use std::io::{Error, ErrorKind};
use std::ptr;

macro_rules! ptrace {
    ($request:ident, $pid:expr, $addr:expr, $data:expr) => {
        unsafe {
            let ret = ptrace($request, $pid, $addr, $data);

            if ret < 0 {
                return Err(Error::last_os_error());
            }

            ret
        }
    };
}

extern "C" {
    fn ptrace(request: c_int, pid: pid_t, data: *const c_void, count: c_int) -> c_int;
}

pub fn attach(tid: lwpid_t) -> Result<(), Error> {
    ptrace!(PT_ATTACH, tid, ptr::null(), 0);

    Ok(())
}

pub fn detach(tid: lwpid_t) -> Result<(), Error> {
    ptrace!(PT_DETACH, tid, ptr::null(), 0);

    Ok(())
}

#[repr(C)]
struct PtraceIoDesc {
    piod_op: c_int,
    piod_offs: *mut c_void,
    piod_addr: *mut c_void,
    piod_len: usize,
}

pub fn read(pid: pid_t, addr: usize, buf: &mut [u8]) -> Result<(), Error> {
    let mut desc = PtraceIoDesc {
        piod_op: PIOD_READ_D,
        piod_offs: addr as *mut c_void,
        piod_addr: buf.as_mut_ptr() as *mut c_void,
        piod_len: buf.len(),
    };
    ptrace!(
        PT_IO,
        pid,
        &mut desc as *mut PtraceIoDesc as *const c_void,
        0
    );

    if desc.piod_len != buf.len() {
        return Err(Error::new(ErrorKind::UnexpectedEof, "partial read"));
    }
    Ok(())
}
