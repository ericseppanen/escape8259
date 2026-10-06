#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Try to unescape the input, just to verify it doesn't panic.
        let _ = escape8259::unescape(s);
        // Verify that all 3 forms of `escape` return identical results.
        let escaped1 = escape8259::escape(s);
        let escaped2 = escape8259::escape_str(s);
        assert_eq!(escaped1, escaped2);
        let escaped3 = escape8259::escape_string(s.into());
        assert_eq!(escaped1, escaped3);

        let recovered1 = escape8259::unescape(escaped1).unwrap();
        assert_eq!(s, recovered1);
        let recovered2 = escape8259::unescape_str(&escaped2).unwrap();
        assert_eq!(s, recovered2);
        let recovered3 = escape8259::unescape_string(escaped3).unwrap();
        assert_eq!(s, recovered3);
    }
});
