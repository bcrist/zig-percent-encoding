# Percent (URL) Encoding and Decoding for Zig

This library can be used in a variety of ways:

* Use `encode()` or `decode()` directly as an iterator.  They will return slices of the output until the whole input string has been encoded or decoded.
* Use `encode_alloc()` or `decode_alloc()`.  It will always return a single slice allocated from the provided allocator, even if the output is identical to the input.
* Use `encode_append()` or `decode_append()`.  Instead of an allocator, you can pass a `*std.ArrayList(u8)` and the result will be appended to it.  The input string must not be owned by the ArrayList.
* Use `encode_maybe_append()` or `decode_maybe_append()`.  Similar to `*_append()`, except the ArrayList won't be modified if the input and output are identical.  The input string must not be owned by the ArrayList.  Returns either the input string, or a slice from the ArrayList.  The ArrayList does not need to be empty and won't be cleared before appending.
* Use `std.fmt.Formatter` aware APIs with `fmtEncoded()`.

Encoding can specify which kinds of bytes are encoded independently for:
* unreserved characters (`[-._~A-Za-z0-9]`)
* spaces
* each of the reserved characters
    * `!`
    * `#`
    * `$`
    * `&`
    * `'`
    * `(`
    * `)`
    * `*`
    * `+`
    * `,`
    * `/`
    * `:`
    * `;`
    * `=`
    * `?`
    * `@`
    * `[`
    * `]`
* other bytes

Interpretation of spaces as `+` and vice versa can be configured for both encoding and decoding.
