#![deny(warnings)]

extern crate ocb;

use std::iter;

// From the end of http://tools.ietf.org/html/rfc7253#appendix-A

#[test]
fn iterative() {
    let mut key = [0; 16];
    key[15] = 128;

    let mut ctx = ocb::Context::new(ocb::Key(key)).unwrap();
    let mut ct = vec![];

    // a macro rather than a lambda due to lifetime problems :(
    macro_rules! enc {
        ($nonce:expr, $pt:expr, $ad:expr) => {{
            let mut n = [0; 12];
            n[10] = ($nonce >> 8) as u8;
            n[11] = ($nonce & 0xFF) as u8;
            ctx.encrypt(&mut Some(ocb::Nonce(n)).into_iter(), $pt, $ad)
                .unwrap().1
        }}
    }

    for i in 0..128us {
        // NB: plaintext and associated data are swapped in the spec's OCB-ENCRYPT
        let s: Vec<u8> = iter::repeat(0).take(i).collect();
        ct.extend(enc!(3*i+1, &s[], &s[]).into_iter());
        ct.extend(enc!(3*i+2, &s[], &[]).into_iter());
        ct.extend(enc!(3*i+3, &[], &s[]).into_iter());
    }

    let result = enc!(385, &[], &ct[]);
    assert_eq!(&result[],
        [0x67, 0xE9, 0x44, 0xD2, 0x32, 0x56, 0xC5, 0xE0,
         0xB6, 0xC6, 0x1F, 0xA2, 0x2F, 0xDF, 0x1E, 0xA2]);
}
