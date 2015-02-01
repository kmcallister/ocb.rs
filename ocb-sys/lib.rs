#![feature(libc)]
#![deny(warnings)]

/// See `ocb/ae.h` for documentation.

extern crate libc;

use libc::{c_int, c_void};

pub const AE_SUCCESS:       c_int = 0;
pub const AE_INVALID:       c_int = -1;
pub const AE_NOT_SUPPORTED: c_int = -2;

pub const AE_FINALIZE:      c_int = 1;
pub const AE_PENDING:       c_int = 0;

// define AE_CTX_SIZEOF
include!(concat!(env!("OUT_DIR"), "/generated.rs"));

// Keep these configuration options in sync with ocb.c!
pub const OCB_KEY_LEN: c_int = 16;
pub const OCB_TAG_LEN: c_int = 16;

#[repr(C)]
#[allow(missing_copy_implementations)]
pub struct ae_ctx {
    __private: (),
}

// These routines call OpenSSL's libcrypto.
#[link(name="crypto")]
extern "C" {
    pub fn ae_allocate(misc: *mut c_void) -> *mut ae_ctx;
    pub fn ae_free(ctx: *mut ae_ctx);
    pub fn ae_clear(ctx: *mut ae_ctx) -> c_int;
    pub fn ae_ctx_sizeof() -> c_int;

    pub fn ae_init(ctx: *mut ae_ctx,
                   key: *const u8,
                   key_len: c_int,
                   nonce_len: c_int,
                   tag_len: c_int) -> c_int;

    pub fn ae_encrypt(ctx: *mut ae_ctx,
                      nonce: *const u8,
                      pt: *const u8,
                      pt_len: c_int,
                      ad: *const u8,
                      ad_len: c_int,
                      ct: *mut u8,
                      tag: *mut u8,
                      final_: c_int) -> c_int;

    pub fn ae_decrypt(ctx: *mut ae_ctx,
                      nonce: *const u8,
                      ct: *const u8,
                      ct_len: c_int,
                      ad: *const u8,
                      ad_len: c_int,
                      pt: *mut u8,
                      tag: *const u8,
                      final_: c_int) -> c_int;
}
