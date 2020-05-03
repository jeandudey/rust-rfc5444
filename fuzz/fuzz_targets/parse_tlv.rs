#![no_main]

use libfuzzer_sys::fuzz_target;

use rfc5444::parser::tlv;

fuzz_target!(|data: &[u8]| {
    tlv(data).ok();
});
