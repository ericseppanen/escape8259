#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Try to unescape the input, just to verify it doesn't panic.
        let _ = escape8259::unescape(s);
        //
        let escaped = escape8259::escape(s);
        let recovered = escape8259::unescape(escaped).unwrap();
        assert_eq!(s, recovered);
    }
});
