# OCB-AES authenticryption for Rust

[![Build Status](https://travis-ci.org/kmcallister/ocb.rs.svg?branch=master)](https://travis-ci.org/kmcallister/ocb.rs)

This library implements the [OCB mode][] for authenticated encryption with
associated data (AEAD), described in [RFC 7253][].  It uses OCB on top of
[AES][]-128.  It includes and builds the [optimized C implementation][] of OCB
by Ted Krovetz, with a safe Rust API on top.  This library uses OpenSSL for the
AES block primitive.

See the [API documentation](https://kmcallister.github.io/docs/ocb.rs) for more.

Phillip Rogaway holds patents relevant to OCB.  Please read the [patent grant
for open-source or non-military software](http://web.cs.ucdavis.edu/~rogaway/ocb/grant.htm).

[OCB mode]: http://web.cs.ucdavis.edu/~rogaway/ocb/
[AES]: http://en.wikipedia.org/wiki/Advanced_Encryption_Standard
[optimized C implementation]: http://web.cs.ucdavis.edu/~rogaway/ocb/news/
[RFC 7253]: http://tools.ietf.org/html/rfc7253
