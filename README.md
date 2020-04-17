`escape8259` performs RFC8259-compliant string escaping and un-escaping.

[RFC8259] is a JSON encoding standard.  Many JSON encoders exist, but other
RFCs use the same string escaping mechanism, so it's useful to be able to
access the string escaping functions by themselves.

# Examples

```rust
use escape8259::{escape, unescape};

assert_eq!(unescape(r#"\u0041\n"#).unwrap(), "A\n");

let multiline = r#"hello
 world"#;
assert_eq!(escape(multiline), r#"hello\n world"#);
```

[RFC8259]: https://tools.ietf.org/html/rfc8259
