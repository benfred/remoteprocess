//! This crate provides a cross platform way of querying information about other processes running
//! on the system. This let's you build profiling and debugging tools.
//!
//! Features:
//!
//! * Getting the process executable name and current working directory
//! * Listing all the threads in the process
//! * Suspending the execution of a process or thread
//! * Returning if a thread is running or not
//! * Getting a stack trace for a thread in the target process
//! * Resolve symbols for an address in the other process
//! * Copy memory from the other process (using the read_process_memory crate)
//!
//! This crate provides implementations for Linux, OSX and Windows. However this crate is still
//! very much in alpha stage, and the following caveats apply:
//!
//! * Stack unwinding only works on x86_64 processors right now, and is disabled for arm/x86
//! * the OSX stack unwinding code is very unstable and shouldn't be relied on
//! * Getting the cwd on windows returns incorrect results
//!
//! # Example
//!
//! ```rust,no_run
//! #[cfg(feature="unwind")]
//! fn get_backtrace(pid: remoteprocess::Pid) -> Result<(), remoteprocess::Error> {
//!     // Create a new handle to the process
//!     let process = remoteprocess::Process::new(pid)?;
//!     // Create a stack unwind object, and use it to get the stack for each thread
//!     let unwinder = process.unwinder()?;
//!     let symbolicator = process.symbolicator()?;
//!     for thread in process.threads()?.iter() {
//!         println!("Thread {} - {}", thread.id()?, if thread.active()? { "running" } else { "idle" });
//!
//!         // lock the thread to get a consistent snapshot (unwinding will fail otherwise)
//!         // Note: the thread will appear idle when locked, so we are calling
//!         // thread.active() before this
//!         let _lock = thread.lock()?;
//!
//!         // Iterate over the callstack for the current thread
//!         for ip in unwinder.cursor(&thread)? {
//!             let ip = ip?;
//!
//!             // Lookup the current stack frame containing a filename/function/linenumber etc
//!             // for the current address
//!             symbolicator.symbolicate(ip, true, &mut |sf| {
//!                 println!("\t{}", sf);
//!             })?;
//!         }
//!     }
//!     Ok(())
//! }
//! ```

#[cfg(target_os = "macos")]
mod osx;
#[cfg(target_os = "macos")]
pub use osx::*;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(target_os = "freebsd")]
mod freebsd;
#[cfg(target_os = "freebsd")]
pub use freebsd::*;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

#[derive(Debug)]
pub enum Error {
    NoBinaryForAddress(u64),
    GoblinError(::goblin::error::Error),
    IOError(std::io::Error),
    Other(String),
    #[cfg(use_libunwind)]
    LibunwindError(linux::libunwind::Error),
    #[cfg(target_os = "linux")]
    NixError(nix::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match *self {
            Error::NoBinaryForAddress(addr) => {
                write!(
                    f,
                    "No binary found for address 0x{:016x}. Try reloading.",
                    addr
                )
            }
            Error::GoblinError(ref e) => e.fmt(f),
            Error::IOError(ref e) => e.fmt(f),
            Error::Other(ref e) => write!(f, "{}", e),
            #[cfg(use_libunwind)]
            Error::LibunwindError(ref e) => e.fmt(f),
            #[cfg(target_os = "linux")]
            Error::NixError(ref e) => e.fmt(f),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match *self {
            Error::GoblinError(ref e) => Some(e),
            Error::IOError(ref e) => Some(e),
            #[cfg(use_libunwind)]
            Error::LibunwindError(ref e) => Some(e),
            #[cfg(target_os = "linux")]
            Error::NixError(ref e) => Some(e),
            _ => None,
        }
    }
}

impl From<goblin::error::Error> for Error {
    fn from(err: goblin::error::Error) -> Error {
        Error::GoblinError(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::IOError(err)
    }
}

#[cfg(target_os = "linux")]
impl From<nix::Error> for Error {
    fn from(err: nix::Error) -> Error {
        Error::NixError(err)
    }
}

#[cfg(use_libunwind)]
impl From<linux::libunwind::Error> for Error {
    fn from(err: linux::libunwind::Error) -> Error {
        Error::LibunwindError(err)
    }
}

#[derive(Debug, Clone)]
pub struct StackFrame {
    pub line: Option<u64>,
    pub filename: Option<String>,
    pub function: Option<String>,
    pub module: String,
    pub addr: u64,
}

impl std::fmt::Display for StackFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        let function = self.function.as_ref().map(String::as_str).unwrap_or("?");
        if let Some(filename) = self.filename.as_ref() {
            write!(
                f,
                "0x{:016x} {} ({}:{})",
                self.addr,
                function,
                filename,
                self.line.unwrap_or(0)
            )
        } else {
            write!(f, "0x{:016x} {} ({})", self.addr, function, self.module)
        }
    }
}

/// Compile-time check that every bit pattern of `size_of::<T>()` bytes is a
/// valid `T`, so that `T` can be safely materialized from bytes read out of
/// another process.
///
/// `T: Copy` is not enough for that. A type with invalid bit patterns has a
/// *niche*, and rustc is free to store an enum discriminant in it - in
/// particular the discriminant of the `Result<T, Error>` that the copy
/// functions below return, when the niche leaves no room for a real tag. A
/// stale read whose bytes happen to hit the niche value then produces an `Err`
/// whose payload is bytes from the target process, and dropping that error
/// frees a pointer that came from the target process.
///
/// That is not hypothetical: it is the root cause of a `free(): invalid
/// pointer` crash in py-spy on Python 3.11, whose `_PyInterpreterFrame`
/// binding has a `bool` as its only niche, in the last 4 bytes of an 80 byte
/// struct that leaves `Result<_PyInterpreterFrame, Error>` no room for a tag.
/// See https://github.com/grafana/pyroscope-python/pull/146.
///
/// A type without a niche always makes `Option<T>` strictly larger than `T`,
/// which is what this checks. The check is intentionally conservative: it
/// rejects `bool`, `char`, references, `NonNull`, enums and any struct
/// containing them, and accepts integers, floats, raw pointers, function
/// pointers wrapped in `Option`, arrays and structs built out of those.
struct AssertNoNiche<T>(std::marker::PhantomData<T>);

impl<T> AssertNoNiche<T> {
    const ASSERT: () = assert!(
        std::mem::size_of::<Option<T>>() > std::mem::size_of::<T>(),
        "this type has a niche: not every bit pattern is a valid value, so it \
         must not be copied out of another process. rustc may store an enum \
         discriminant in the niche, which turns a stale read into an `Err` \
         holding bytes from the target process"
    );
}

pub trait ProcessMemory {
    /// Copies memory from another process into an already allocated
    /// byte buffer
    fn read(&self, addr: usize, buf: &mut [u8]) -> Result<(), Error>;

    /// Copies a series of bytes from another process. Main difference
    /// with 'read' is that this will allocate memory for you
    fn copy(&self, addr: usize, length: usize) -> Result<Vec<u8>, Error> {
        let mut data = vec![0; length];
        self.read(addr, &mut data)?;
        Ok(data)
    }

    /// Copies a structure from another process
    ///
    /// `T` must be valid for every bit pattern, since the bytes come from
    /// another process: this fails to compile for types that have a niche.
    fn copy_struct<T: Copy>(&self, addr: usize) -> Result<T, Error> {
        let () = AssertNoNiche::<T>::ASSERT;
        let mut data = vec![0; std::mem::size_of::<T>()];
        self.read(addr, &mut data)?;
        Ok(unsafe { std::ptr::read(data.as_ptr() as *const _) })
    }

    /// Given a pointer that points to a struct in another process, returns the struct
    fn copy_pointer<T: Copy>(&self, ptr: *const T) -> Result<T, Error> {
        self.copy_struct(ptr as usize)
    }

    /// Copies a series of bytes from another process into a vector of
    /// structures of type T.
    ///
    /// As with [`ProcessMemory::copy_struct`], `T` must be valid for every bit
    /// pattern.
    fn copy_vec<T: Copy>(&self, addr: usize, length: usize) -> Result<Vec<T>, Error> {
        let () = AssertNoNiche::<T>::ASSERT;
        let mut vec = self.copy(addr, length * std::mem::size_of::<T>())?;
        let capacity = vec.capacity() as usize / std::mem::size_of::<T>() as usize;
        let ptr = vec.as_mut_ptr() as *mut T;
        std::mem::forget(vec);
        unsafe { Ok(Vec::from_raw_parts(ptr, capacity, capacity)) }
    }
}

#[doc(hidden)]
/// Mock for using ProcessMemory on the local process.
pub struct LocalProcess;
impl ProcessMemory for LocalProcess {
    fn read(&self, addr: usize, buf: &mut [u8]) -> Result<(), Error> {
        unsafe {
            std::ptr::copy_nonoverlapping(addr as *mut u8, buf.as_mut_ptr(), buf.len());
        }
        Ok(())
    }
}

#[cfg(any(target_os = "linux", target_os = "windows", target_os = "freebsd"))]
#[doc(hidden)]
/// Filters pids to own include descendations of target_pid
fn filter_child_pids(
    target_pid: Pid,
    processes: &std::collections::HashMap<Pid, Pid>,
) -> Vec<(Pid, Pid)> {
    let mut ret = Vec::new();
    for (child, parent) in processes.iter() {
        let mut current = *parent;
        loop {
            if current == target_pid {
                ret.push((*child, *parent));
                break;
            }
            current = match processes.get(&current) {
                Some(pid) => {
                    if current == *pid {
                        break;
                    }
                    *pid
                }
                None => break,
            };
        }
    }
    ret
}

#[cfg(test)]
pub mod tests {
    use super::*;

    #[derive(Copy, Clone)]
    struct Point {
        x: i32,
        y: i64,
    }

    #[test]
    fn test_copy_pointer() {
        let original = Point { x: 15, y: 25 };
        let copy = LocalProcess.copy_pointer(&original).unwrap();
        assert_eq!(original.x, copy.x);
        assert_eq!(original.y, copy.y);
    }

    #[test]
    fn test_copy_struct() {
        let original = Point { x: 10, y: 20 };
        let copy: Point = LocalProcess
            .copy_struct(&original as *const Point as usize)
            .unwrap();
        assert_eq!(original.x, copy.x);
        assert_eq!(original.y, copy.y);
    }
}
