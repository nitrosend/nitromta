#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| fuzz::smtp_server(data));
