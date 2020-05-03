#![no_main]
use libfuzzer_sys::fuzz_target;

use rfc5444::parser::tlv_block;

fuzz_target!(|data: &[u8]| {
    if let Ok((_, mut iter)) = tlv_block(data) {
        while let Some(tlv) = iter.next() {
            if let Err(_) = tlv {
                break;
            }
        }
    }
});
