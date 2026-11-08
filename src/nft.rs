//! A small binding to libnftables, the library behind the `nft` command.
//!
//! The library is loaded at runtime, so building needs no nftables headers. One
//! `Nft` holds one netlink socket for its whole life, which is what lets the guard
//! own a table with the nftables `owner` flag and keep changing it.

use std::ffi::{CStr, CString, c_char, c_int, c_uint, c_void};
use std::sync::LazyLock;

const NFT_CTX_OUTPUT_STATELESS: c_uint = 1 << 2;

type Ctx = *mut c_void;

struct Api {
    ctx_new: unsafe extern "C" fn(u32) -> Ctx,
    ctx_free: unsafe extern "C" fn(Ctx),
    run_cmd: unsafe extern "C" fn(Ctx, *const c_char) -> c_int,
    buffer_output: unsafe extern "C" fn(Ctx) -> c_int,
    buffer_error: unsafe extern "C" fn(Ctx) -> c_int,
    output_buffer: unsafe extern "C" fn(Ctx) -> *const c_char,
    error_buffer: unsafe extern "C" fn(Ctx) -> *const c_char,
    output_set_flags: unsafe extern "C" fn(Ctx, c_uint),
    set_dry_run: unsafe extern "C" fn(Ctx, bool),
}

static API: LazyLock<Result<Api, String>> = LazyLock::new(load);

fn api() -> Result<&'static Api, String> {
    API.as_ref().map_err(Clone::clone)
}

fn load() -> Result<Api, String> {
    // SAFETY: dlopen/dlsym with NUL-terminated names. Each symbol is cast to the
    // signature declared in <nftables/libnftables.h>.
    unsafe {
        let lib = libc::dlopen(
            c"libnftables.so.1".as_ptr(),
            libc::RTLD_NOW | libc::RTLD_LOCAL,
        );
        if lib.is_null() {
            return Err("cannot load libnftables.so.1; install the nftables package".into());
        }
        macro_rules! sym {
            ($name:literal: $ty:ty) => {{
                let ptr = libc::dlsym(lib, concat!($name, "\0").as_ptr().cast());
                if ptr.is_null() {
                    return Err(concat!("libnftables has no ", $name).into());
                }
                std::mem::transmute::<*mut c_void, $ty>(ptr)
            }};
        }
        Ok(Api {
            ctx_new: sym!("nft_ctx_new": unsafe extern "C" fn(u32) -> Ctx),
            ctx_free: sym!("nft_ctx_free": unsafe extern "C" fn(Ctx)),
            run_cmd: sym!("nft_run_cmd_from_buffer": unsafe extern "C" fn(Ctx, *const c_char) -> c_int),
            buffer_output: sym!("nft_ctx_buffer_output": unsafe extern "C" fn(Ctx) -> c_int),
            buffer_error: sym!("nft_ctx_buffer_error": unsafe extern "C" fn(Ctx) -> c_int),
            output_buffer: sym!("nft_ctx_get_output_buffer": unsafe extern "C" fn(Ctx) -> *const c_char),
            error_buffer: sym!("nft_ctx_get_error_buffer": unsafe extern "C" fn(Ctx) -> *const c_char),
            output_set_flags: sym!("nft_ctx_output_set_flags": unsafe extern "C" fn(Ctx, c_uint)),
            set_dry_run: sym!("nft_ctx_set_dry_run": unsafe extern "C" fn(Ctx, bool)),
        })
    }
}

pub struct Nft {
    api: &'static Api,
    ctx: Ctx,
}

impl Nft {
    pub fn new() -> Result<Self, String> {
        let api = api()?;
        // SAFETY: plain constructor; a null return is handled.
        let ctx = unsafe { (api.ctx_new)(0) };
        if ctx.is_null() {
            return Err("nft_ctx_new failed".into());
        }
        // SAFETY: ctx is valid until Drop.
        unsafe {
            (api.buffer_output)(ctx);
            (api.buffer_error)(ctx);
        }
        Ok(Nft { api, ctx })
    }

    /// Run nft commands as one transaction. Returns what nft would print.
    pub fn run(&mut self, commands: &str) -> Result<String, String> {
        let commands = CString::new(commands).map_err(|_| "nft commands contain a NUL byte")?;
        // SAFETY: ctx is valid; the buffers are owned by ctx and copied right away.
        let (rc, out, err) = unsafe {
            let rc = (self.api.run_cmd)(self.ctx, commands.as_ptr());
            (
                rc,
                take((self.api.output_buffer)(self.ctx)),
                take((self.api.error_buffer)(self.ctx)),
            )
        };
        if rc == 0 {
            Ok(out)
        } else if err.trim().is_empty() {
            Err("nft command failed".into())
        } else {
            Err(err.trim_end().to_string())
        }
    }

    /// Leave out counters and other changing state when listing.
    pub fn stateless(self) -> Self {
        // SAFETY: ctx is valid.
        unsafe { (self.api.output_set_flags)(self.ctx, NFT_CTX_OUTPUT_STATELESS) };
        self
    }

    /// Check commands against the kernel without applying them (`nft -c`).
    pub fn dry_run(self) -> Self {
        // SAFETY: ctx is valid.
        unsafe { (self.api.set_dry_run)(self.ctx, true) };
        self
    }
}

impl Drop for Nft {
    fn drop(&mut self) {
        // SAFETY: ctx came from nft_ctx_new and is freed once.
        unsafe { (self.api.ctx_free)(self.ctx) };
    }
}

/// Copy a buffer libnftables owns.
///
/// SAFETY: `ptr` is null or a NUL-terminated string that stays valid for this call.
unsafe fn take(ptr: *const c_char) -> String {
    if ptr.is_null() {
        String::new()
    } else {
        // SAFETY: see above.
        unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned()
    }
}
