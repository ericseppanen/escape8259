<!-- cargo-sync-readme start -->

`escape8259` performs RFC8259-compliant string escaping and un-escaping.

[RFC8259] is a JSON encoding standard.  Many JSON encoders exist, but other
RFCs use the same string escaping mechanism, so it's useful to be able to
access the string escaping functions without needing a full JSON implementation.

`escape8259` is compatible with Rust 1.38.0 and above.

# Examples

```rust
use escape8259::{escape, unescape};

let s = "A null (\0) and a double-quote (\")";
assert_eq!(escape(s), r#"A null (\u0000) and a double-quote (\")"#);

let crab = r#"This is a crab: \ud83e\udd80"#;
assert_eq!(unescape(crab).unwrap(), "This is a crab: 🦀");

// We accept encodings that weren't really necessary.
assert_eq!(unescape(r#"\u0041\n"#).unwrap(), "A\n");

let multiline = r#"hello
 world"#;
assert_eq!(escape(multiline), r#"hello\n world"#);
```

[RFC8259]: https://tools.ietf.org/html/rfc8259

<!-- cargo-sync-readme end -->
