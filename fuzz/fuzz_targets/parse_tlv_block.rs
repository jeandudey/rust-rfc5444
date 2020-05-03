#![no_main]
use libfuzzer_sys::fuzz_target;

use rfc5444::Buf;
use rfc5444::parser::tlv_block;

fuzz_target!(|data: &[u8]| {
    let mut buf = Buf::new(data);
    if let Ok(mut iter) = tlv_block(&mut buf) {
        while let Some(tlv) = iter.next() {
            if let Err(_) = tlv {
                break;
            }
        }
    }
});
