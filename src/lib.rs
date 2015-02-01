#![feature(libc, hash, core)]
#![deny(warnings)]

extern crate "ocb-sys" as ocb_sys;
extern crate libc;

use std::{result, mem, fmt, ptr, simd};
use std::intrinsics::volatile_set_memory;

use ocb_sys::{AE_SUCCESS, AE_INVALID, AE_NOT_SUPPORTED};
use ocb_sys::{AE_FINALIZE, AE_CTX_SIZEOF};
use ocb_sys::{OCB_KEY_LEN, OCB_TAG_LEN};
use ocb_sys::{ae_ctx, ae_ctx_sizeof, ae_clear, ae_init, ae_encrypt, ae_decrypt};

use libc::c_int;

/// AES-128 key size = 16 bytes.
pub const KEY_LEN: usize = OCB_KEY_LEN as usize;

/// Authentication tag length = 16 bytes.
pub const TAG_LEN: usize = OCB_TAG_LEN as usize;

// OCB's ae_init() only accepts this value.
/// Nonce length = 12 bytes.
pub const NONCE_LEN: usize = 12;

/// Errors the library can produce.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Error {
    InvalidTag,
    NotSupported,
    NonceNotAvailable,
    Other(c_int),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        <Self as fmt::Debug>::fmt(self, f)
    }
}

pub type Result<T> = result::Result<T, Error>;

fn check(x: c_int) -> Result<c_int> {
    match x {
        AE_INVALID => Err(Error::InvalidTag),
        AE_NOT_SUPPORTED => Err(Error::NotSupported),
        x if x < 0 => Err(Error::Other(x)),
        x => Ok(x),
    }
}

/// An OCB encryption/decryption context.
pub struct Context {
    _align: [simd::u32x4; 0],
    ctx: [u8; AE_CTX_SIZEOF],
}

impl Drop for Context {
    fn drop(&mut self) {
        unsafe {
            check(ae_clear(self.ctx())).unwrap();
        }
    }
}

macro_rules! clear_on_drop {
    ($t:ty) => {
        impl Drop for $t {
            fn drop(&mut self) {
                let buf = &mut self.0;
                unsafe {
                    volatile_set_memory(buf.as_mut_ptr(), 0, buf.len());
                }
            }
        }
    }
}

/// AES-128 key for use with OCB-AES.
#[derive(Clone)]
pub struct Key(pub [u8; KEY_LEN]);
clear_on_drop!(Key);

/// Cryptographic nonce.
///
/// See `Context::encrypt` for proper usage.
#[allow(missing_copy_implementations)]
#[derive(Clone, Debug)]
pub struct Nonce(pub [u8; NONCE_LEN]);

/// A source of unique nonces, counting sequentially as a little-endian
/// integer.
#[allow(missing_copy_implementations)]
pub struct Counter([u8; NONCE_LEN]);

impl Counter {
    /// Create a counter with a specified first output.
    pub fn new(n: Nonce) -> Counter {
        Counter(n.0)
    }
}

impl Iterator for Counter {
    type Item = Nonce;

    fn next(&mut self) -> Option<Nonce> {
        let v = self.0;
        for i in 0..NONCE_LEN {
            self.0[i] += 1;
            if self.0[i] != 0 {
                break;
            }
        }
        Some(Nonce(v))
    }
}

impl Context {
    fn ctx(&mut self) -> *mut ae_ctx {
        self.ctx.as_mut_ptr() as *mut ae_ctx
    }

    /// Initialize an OCB context with the given key.
    pub fn new(key: Key) -> Result<Context> {
        unsafe {
            assert_eq!(AE_CTX_SIZEOF, ae_ctx_sizeof() as usize);

            let mut ctx = Context {
                _align: [mem::uninitialized(); 0],
                ctx: mem::uninitialized(),
            };
            let n = try!(check(ae_init(ctx.ctx(), key.0.as_ptr(),
                OCB_KEY_LEN, NONCE_LEN as c_int, OCB_TAG_LEN)));
            assert_eq!(n, AE_SUCCESS);
            Ok(ctx)
        }
    }

    /// Encrypt and authenticate a message.
    ///
    /// The `nonce_stream` iterator is used to obtain a nonce, a "number used
    /// once", just for this encryption.  You *must not* encrypt two messages
    /// using the same key and nonce. This will fatally compromise security.
    /// Take extra care when using the same key in multiple processes or on
    /// multiple machines.  It's often better for each direction of
    /// communication to have its own key.
    ///
    /// The nonce is not secret.  It's usually transmitted along with the
    /// message, and it's needed at the receiving end.  The nonce is allowed to
    /// be predictable, as well.  A simple counter is a good source of unique
    /// nonces, so long as it's reset only when the key changes.  The type
    /// `Counter` implements such a nonce source, but you can use any
    /// `Iterator<Item=Nonce>`, so long as it *never* produces the same value
    /// twice (for the same key).
    ///
    /// The "associated data" is authenticated as well, but it is not encrypted
    /// or copied into the output.  In other words, decryption will succeed if
    /// and only if the receiver supplies the same associated data.  For example,
    /// it could be transmitted in the clear alongside the encrypted message.
    ///
    /// Many applications don't need associated data and can pass an empty slice.
    pub fn encrypt<N>(&mut self,
                      nonce_stream: &mut N,
                      plaintext: &[u8],
                      assoc_data: &[u8]) -> Result<(Nonce, Vec<u8>)>
        where N: Iterator<Item=Nonce>
    {
        let nonce = match nonce_stream.next() {
            Some(n) => n,
            None => return Err(Error::NonceNotAvailable),
        };

        let ct_len = plaintext.len() + TAG_LEN;
        let mut ct: Vec<u8> = Vec::with_capacity(ct_len);
        unsafe {
            let n = try!(check(ae_encrypt(self.ctx(), nonce.0.as_ptr(),
                plaintext.as_ptr(), plaintext.len() as c_int,
                assoc_data.as_ptr(), assoc_data.len() as c_int,
                ct.as_mut_ptr(), ptr::null_mut(), AE_FINALIZE)));

            assert_eq!(ct_len, n as usize);
            ct.set_len(ct_len);
            Ok((nonce, ct))
        }
    }

    /// Decrypt and verify a message.
    ///
    /// If the ciphertext was generated correctly, using the specified nonce and
    /// associated data, with the key stored in this context, then `decrypt` will
    /// return the original plaintext.  Otherwise, you get an error saying what
    /// went wrong.
    pub fn decrypt(&mut self,
                   nonce: Nonce,
                   ciphertext: &[u8],
                   assoc_data: &[u8]) -> Result<Vec<u8>> {
        assert!(ciphertext.len() >= TAG_LEN);
        let pt_len = ciphertext.len() - TAG_LEN;
        let mut pt: Vec<u8> = Vec::with_capacity(pt_len);
        unsafe {
            let n = try!(check(ae_decrypt(self.ctx(), nonce.0.as_ptr(),
                ciphertext.as_ptr(), ciphertext.len() as c_int,
                assoc_data.as_ptr(), assoc_data.len() as c_int,
                pt.as_mut_ptr(), ptr::null_mut(), AE_FINALIZE)));
            assert_eq!(pt_len, n as usize);
            pt.set_len(pt_len);
            Ok(pt)
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn counter() {
        let mut n = Counter::new(Nonce([0; NONCE_LEN]));
        assert_eq!(n.next().unwrap().0, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(n.next().unwrap().0, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(n.next().unwrap().0, [2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        n.0[0] = 0xFE;
        assert_eq!(n.next().unwrap().0, [0xFE, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(n.next().unwrap().0, [0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(n.next().unwrap().0, [0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);

        let mut n = Counter::new(Nonce([0xFF; NONCE_LEN]));
        n.0[0] = 0xFE;
        assert_eq!(n.next().unwrap().0, [0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(n.next().unwrap().0, [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                         0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(n.next().unwrap().0, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(n.next().unwrap().0, [1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
    }

    #[test]
    fn smoke_test() {
        let mut ctx = Context::new(Key([0; KEY_LEN])).unwrap();
        let mut counter = Counter::new(Nonce([0; NONCE_LEN]));

        let msg = "Hello, world!".as_bytes();
        let assoc = "rust rulez".as_bytes();

        let (nonce, mut ct) = ctx.encrypt(&mut counter, msg, assoc).unwrap();
        assert_eq!(nonce.0, [0; NONCE_LEN]);

        let pt = ctx.decrypt(nonce.clone(), &ct[], assoc).unwrap();
        assert_eq!(&pt[], msg);

        assert_eq!(ctx.decrypt(nonce.clone(), &ct[], "bogus".as_bytes()),
            Err(Error::InvalidTag));

        ct[0] ^= 0x01;
        assert_eq!(ctx.decrypt(nonce.clone(), &ct[], assoc),
            Err(Error::InvalidTag));
        ct[0] ^= 0x01;
        assert!(ctx.decrypt(nonce.clone(), &ct[], assoc).is_ok());

        let mut ctx2 = Context::new(Key([5; KEY_LEN])).unwrap();
        assert_eq!(ctx2.decrypt(nonce, &ct[], assoc),
            Err(Error::InvalidTag));
    }
}
