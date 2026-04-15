# Percent (URL) Encoding and Decoding for Zig

The zig standard library contains some basic percent encoding functions:
* `std.Uri.percentEncode`
* `std.Uri.Component.format*`
* `std.Uri.percentDecodeBackwards`
* `std.Uri.percentDecodeInPlace`

This library provides an alternative implementation that's more flexible:
* Use `encode()` or `decode()` directly as an iterator.  They will return slices of the output until the whole input string has been encoded or decoded.
* Use `encode_alloc()` or `decode_alloc()`.  It will always return a single slice allocated from the provided allocator, even if the output is identical to the input.
* Use `encode_append()` or `decode_append()`.  Instead of an allocator, you can pass a `*std.ArrayList(u8)` and the result will be appended to it.  The input string must not be owned by the ArrayList.
* Use `encode_maybe_append()` or `decode_maybe_append()`.  Similar to `*_append()`, except the ArrayList won't be modified if the input and output are identical.  The input string must not be owned by the ArrayList.  Returns either the input string, or a slice from the ArrayList.  The ArrayList does not need to be empty and won't be cleared before appending.
* Use with `std.Io.Writer.print` with `fmt()`.

`Encode_Options` can specify which kinds of bytes are encoded independently for:
* ASCII alphabetical characters (`[A-Za-z]`)
* Decimal digits (`[0-9]`)
* spaces
* ASCII symbols
* C0 control characters and bytes >= 0x80

The default `Encode_Options` is conservative; it will encode `application/x-www-form-urlencoded` data according to [HTML's rules](https://url.spec.whatwg.org/#concept-urlencoded-serializer), except that spaces will be encoded as `%20` instead of `+`. Servers generally don't care if `%20` or `+` is used, so this shouldn't be a problem, and it means it can also be used safely to escape URI data.  Encoding spaces as `+` can be enabled explicitly if desired.

When decoding, `+` _will_ be treated as a space by default, so make sure you turn this off explicitly if you're processing data where `+` is meant to be an unencoded literal `+`.

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

| Encoding Method                  | Debug     | ReleaseSafe | ReleaseFast |
| -------------------------------- | --------- | ----------- | ----------- |
| percent_encoding.encode_append   | 6.4 ns/B  | 1.8 ns/B    | 1.7 ns/B    |
| percent_encoding.fmt             | 5.9 ns/B  | 1.7 ns/B    | 1.7 ns/B    |
| percent_encoding.encode_writer   | 6.0 ns/B  | 1.7 ns/B    | 1.7 ns/B    |
| std.Uri.Component.percentEncode  | 8.6 ns/B  | 2.2 ns/B    | 1.9 ns/B    |

| Decoding Method                  | Debug     | ReleaseSafe | ReleaseFast |
| -------------------------------- | --------- | ----------- | ----------- |
| percent_encoding.decode_in_place | 8.7 ns/B  | 0.82 ns/B   | 0.80 ns/B   |
| std.Uri.percentDecodeInPlace     | 9.2 ns/B  | 1.0 ns/B    | 0.96 ns/B   |
