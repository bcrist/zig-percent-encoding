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

## Encoding with `std`

Consider using the standard library's [`std.Uri.Component.percentEncode`](https://ziglang.org/documentation/master/std/#std.Uri.Component.percentEncode) when:
* You have a writer available
* You don't mind creating an `isValidChar` helper function to pass in
* You don't need to encode spaces as `+`

## Decoding with `std`

The standard library provides [`std.Uri.percentDecodeInPlace`](https://ziglang.org/documentation/master/std/#std.Uri.percentDecodeInPlace)/[`std.Uri.percentDecodeBackwards`](https://ziglang.org/documentation/master/std/#std.Uri.percentDecodeBackwards) however these require a preallocated mutable output buffer.  Additionally, they do not support decoding `+` as a space.

## Performance comparison

It's highly unlikely that percent encoding/decoding will be a bottleneck for most applications, but some performance comparisons with the `std` implementations are provided in the `benchmark.zig` file and can be run with `zig build benchmark`.  As with all microbenchmarks, take the results with several grains of salt.

Here are the results from my machine:

|                                  | Debug     | Release   |
| -------------------------------- | --------- | --------- |
| percent_encoding.encode_append   | 6.2 ns/B  | 1.7 ns/B  |
| percent_encoding.fmtEncoded      | 7.8 ns/B  | 1.9 ns/B  |
| percent_encoding.encode_writer   | 8.0 ns/B  | 1.8 ns/B  |
| std.Uri.Component.percentEncode  | 12 ns/B   | 2.4 ns/B  |
| percent_encoding.decode_in_place | 7.7 ns/B  | 0.84 ns/B |
| std.Uri.percentDecodeInPlace     | 8.9 ns/B  | 0.83 ns/B |
