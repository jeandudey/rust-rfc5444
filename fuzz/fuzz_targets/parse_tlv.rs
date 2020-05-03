#![no_main]

use libfuzzer_sys::fuzz_target;

use rfc5444::Buf;
use rfc5444::parser::tlv;

fuzz_target!(|data: &[u8]| {
    let mut buf = Buf::new(data);
    tlv(&mut buf).ok();
});
