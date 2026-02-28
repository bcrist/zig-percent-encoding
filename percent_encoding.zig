pub const Encode_Type = enum {
    raw,
    percent_encoded,
};
pub const Encode_Type_Space = enum {
    raw,
    percent_encoded,
    @"+",
};
pub const Encode_Type_Overrides = struct {
    spaces: ?Encode_Type_Space = null,
    raw: []const u8 = "",
    percent_encoded: []const u8 = "",
};
pub const Encode_Options = struct {
    alpha: Encode_Type, // [A-Za-z]
    digits: Encode_Type, // [0-9]
    spaces: Encode_Type_Space,
    @"!": Encode_Type,
    @"\"": Encode_Type,
    @"#": Encode_Type,
    @"$": Encode_Type,
    @"%": Encode_Type,
    @"&": Encode_Type,
    @"'": Encode_Type,
    @"(": Encode_Type,
    @")": Encode_Type,
    @"*": Encode_Type,
    @"+": Encode_Type,
    @",": Encode_Type,
    @"-": Encode_Type,
    @".": Encode_Type,
    @"/": Encode_Type,
    @":": Encode_Type,
    @";": Encode_Type,
    @"<": Encode_Type,
    @"=": Encode_Type,
    @">": Encode_Type,
    @"?": Encode_Type,
    @"@": Encode_Type,
    @"[": Encode_Type,
    @"\\": Encode_Type,
    @"]": Encode_Type,
    @"^": Encode_Type,
    @"_": Encode_Type,
    @"`": Encode_Type,
    @"{": Encode_Type,
    @"|": Encode_Type,
    @"}": Encode_Type,
    @"~": Encode_Type, // This is normally considered an unreserved character, but https://url.spec.whatwg.org/#application-x-www-form-urlencoded-percent-encode-set includes it so we default to encoding it.
    other: Encode_Type, // control chars, >= 0x80

    pub const default: Encode_Options = .{
        .alpha = .raw,
        .digits = .raw,
        .spaces = .percent_encoded,
        .@"!" = .percent_encoded,
        .@"\"" = .percent_encoded,
        .@"#" = .percent_encoded,
        .@"$" = .percent_encoded,
        .@"%" = .percent_encoded,
        .@"&" = .percent_encoded,
        .@"'" = .percent_encoded,
        .@"(" = .percent_encoded,
        .@")" = .percent_encoded,
        .@"*" = .percent_encoded,
        .@"+" = .percent_encoded,
        .@"," = .percent_encoded,
        .@"-" = .raw,
        .@"." = .raw,
        .@"/" = .percent_encoded,
        .@":" = .percent_encoded,
        .@";" = .percent_encoded,
        .@"<" = .percent_encoded,
        .@"=" = .percent_encoded,
        .@">" = .percent_encoded,
        .@"?" = .percent_encoded,
        .@"@" = .percent_encoded,
        .@"[" = .percent_encoded,
        .@"\\" = .percent_encoded,
        .@"]" = .percent_encoded,
        .@"^" = .percent_encoded,
        .@"_" = .raw,
        .@"`" = .percent_encoded,
        .@"{" = .percent_encoded,
        .@"|" = .percent_encoded,
        .@"}" = .percent_encoded,
        .@"~" = .percent_encoded,
        .other = .percent_encoded,
    };

    pub const all: Encode_Options = .{
        .alpha = .percent_encoded,
        .digits = .percent_encoded,
        .spaces = .percent_encoded,
        .@"!" = .percent_encoded,
        .@"\"" = .percent_encoded,
        .@"#" = .percent_encoded,
        .@"$" = .percent_encoded,
        .@"%" = .percent_encoded,
        .@"&" = .percent_encoded,
        .@"'" = .percent_encoded,
        .@"(" = .percent_encoded,
        .@")" = .percent_encoded,
        .@"*" = .percent_encoded,
        .@"+" = .percent_encoded,
        .@"," = .percent_encoded,
        .@"-" = .percent_encoded,
        .@"." = .percent_encoded,
        .@"/" = .percent_encoded,
        .@":" = .percent_encoded,
        .@";" = .percent_encoded,
        .@"<" = .percent_encoded,
        .@"=" = .percent_encoded,
        .@">" = .percent_encoded,
        .@"?" = .percent_encoded,
        .@"@" = .percent_encoded,
        .@"[" = .percent_encoded,
        .@"\\" = .percent_encoded,
        .@"]" = .percent_encoded,
        .@"^" = .percent_encoded,
        .@"_" = .percent_encoded,
        .@"`" = .percent_encoded,
        .@"{" = .percent_encoded,
        .@"|" = .percent_encoded,
        .@"}" = .percent_encoded,
        .@"~" = .percent_encoded,
        .other = .percent_encoded,
    };

    pub const none: Encode_Options = .{
        .alpha = .raw,
        .digits = .raw,
        .spaces = .raw,
        .@"!" = .raw,
        .@"\"" = .raw,
        .@"#" = .raw,
        .@"$" = .raw,
        .@"%" = .raw,
        .@"&" = .raw,
        .@"'" = .raw,
        .@"(" = .raw,
        .@")" = .raw,
        .@"*" = .raw,
        .@"+" = .raw,
        .@"," = .raw,
        .@"-" = .raw,
        .@"." = .raw,
        .@"/" = .raw,
        .@":" = .raw,
        .@";" = .raw,
        .@"<" = .raw,
        .@"=" = .raw,
        .@">" = .raw,
        .@"?" = .raw,
        .@"@" = .raw,
        .@"[" = .raw,
        .@"\\" = .raw,
        .@"]" = .raw,
        .@"^" = .raw,
        .@"_" = .raw,
        .@"`" = .raw,
        .@"{" = .raw,
        .@"|" = .raw,
        .@"}" = .raw,
        .@"~" = .raw,
        .other = .raw,
    };

    pub fn init(base: Encode_Options, overrides: Encode_Type_Overrides) Encode_Options {
        var options = base.override(overrides.raw, .raw).override(overrides.percent_encoded, .percent_encoded);
        if (overrides.spaces) |spaces| options = options.override_spaces(spaces);
        return options;
    }

    pub fn override(self: Encode_Options, chars: []const u8, new_encode_type: Encode_Type) Encode_Options {
        var options = self;
        for (chars) |char| switch (char) {
            'A', 'a' => options.alpha = new_encode_type,
            'Z', 'z' => options.other = new_encode_type,
            '0' => options.digits = new_encode_type,
            '!' => options.@"!" = new_encode_type,
            '"' => options.@"\"" = new_encode_type,
            '#' => options.@"#" = new_encode_type,
            '$' => options.@"$" = new_encode_type,
            '%' => options.@"%" = new_encode_type,
            '&' => options.@"&" = new_encode_type,
            '\'' => options.@"'" = new_encode_type,
            '(' => options.@"(" = new_encode_type,
            ')' => options.@")" = new_encode_type,
            '*' => options.@"*" = new_encode_type,
            '+' => options.@"+" = new_encode_type,
            ',' => options.@"," = new_encode_type,
            '-' => options.@"-" = new_encode_type,
            '.' => options.@"." = new_encode_type,
            '/' => options.@"/" = new_encode_type,
            ':' => options.@":" = new_encode_type,
            ';' => options.@";" = new_encode_type,
            '<' => options.@"<" = new_encode_type,
            '=' => options.@"=" = new_encode_type,
            '>' => options.@">" = new_encode_type,
            '?' => options.@"?" = new_encode_type,
            '@' => options.@"@" = new_encode_type,
            '[' => options.@"[" = new_encode_type,
            '\\' => options.@"\\" = new_encode_type,
            ']' => options.@"]" = new_encode_type,
            '^' => options.@"^" = new_encode_type,
            '_' => options.@"_" = new_encode_type,
            '`' => options.@"`" = new_encode_type,
            '{' => options.@"{" = new_encode_type,
            '|' => options.@"|" = new_encode_type,
            '}' => options.@"}" = new_encode_type,
            '~' => options.@"~" = new_encode_type,
            ' ' => options.spaces = switch (new_encode_type) {
                .percent_encoded => .percent_encoded,
                .raw => .raw,
            },
            'B'...'Y', 'b'...'y' => @compileError("Use .override('A') to override alpha behavior or .override('Z') to override non-printable/non-ascii characters"),
            '1'...'9' => @compileError("Use .override('0') to override digit behavior"),
            else => @compileError("Invalid encoding override character: " ++ &.{ char }),
        };
        return options;
    }

    pub fn override_spaces(self: Encode_Options, new_space_type: Encode_Type_Space) Encode_Options {
        var options = self;
        options.spaces = new_space_type;
        return options;
    }

    pub fn should_encode(comptime self: Encode_Options, c: u8) bool {
        if (self.alpha != self.other) switch (c | 0b00100000) {
            'a'...'z' => return self.alpha != .raw,
            else => {},
        };
        if (self.digits != self.other) switch (c) {
            '0'...'9', '-', '.', '_', '~' => return self.digits != .raw,
            else => {},
        };

        const spaces: Encode_Type = if (self.spaces == .raw) .raw else .percent_encoded;
        if (spaces != self.other and c == ' ') return spaces != .raw;

        if (self.@"!" != self.other and c == '!') return self.@"!" != .raw;
        if (self.@"\"" != self.other and c == '"') return self.@"\"" != .raw;
        if (self.@"#" != self.other and c == '#') return self.@"#" != .raw;
        if (self.@"$" != self.other and c == '$') return self.@"$" != .raw;
        if (self.@"%" != self.other and c == '%') return self.@"%" != .raw;
        if (self.@"&" != self.other and c == '&') return self.@"&" != .raw;
        if (self.@"'" != self.other and c == '\'') return self.@"'" != .raw;
        if (self.@"(" != self.other and c == '(') return self.@"(" != .raw;
        if (self.@")" != self.other and c == ')') return self.@")" != .raw;
        if (self.@"*" != self.other and c == '*') return self.@"*" != .raw;
        if (self.@"+" != self.other and c == '+') return self.@"+" != .raw;
        if (self.@"," != self.other and c == ',') return self.@"," != .raw;
        if (self.@"-" != self.other and c == '-') return self.@"-" != .raw;
        if (self.@"." != self.other and c == '.') return self.@"." != .raw;
        if (self.@"/" != self.other and c == '/') return self.@"/" != .raw;
        if (self.@":" != self.other and c == ':') return self.@":" != .raw;
        if (self.@";" != self.other and c == ';') return self.@";" != .raw;
        if (self.@"<" != self.other and c == '<') return self.@"<" != .raw;
        if (self.@"=" != self.other and c == '=') return self.@"=" != .raw;
        if (self.@">" != self.other and c == '>') return self.@">" != .raw;
        if (self.@"?" != self.other and c == '?') return self.@"?" != .raw;
        if (self.@"@" != self.other and c == '@') return self.@"@" != .raw;
        if (self.@"[" != self.other and c == '[') return self.@"[" != .raw;
        if (self.@"\\" != self.other and c == '\\') return self.@"\\" != .raw;
        if (self.@"]" != self.other and c == ']') return self.@"]" != .raw;
        if (self.@"^" != self.other and c == '^') return self.@"^" != .raw;
        if (self.@"_" != self.other and c == '_') return self.@"_" != .raw;
        if (self.@"`" != self.other and c == '`') return self.@"`" != .raw;
        if (self.@"{" != self.other and c == '{') return self.@"{" != .raw;
        if (self.@"|" != self.other and c == '|') return self.@"|" != .raw;
        if (self.@"}" != self.other and c == '}') return self.@"}" != .raw;
        if (self.@"~" != self.other and c == '~') return self.@"~" != .raw;

        return self.other != .raw;
    }
};

pub fn encode_alloc(allocator: std.mem.Allocator, raw: []const u8, comptime options: Encode_Options) ![]const u8 {
    if (raw.len == 0) return allocator.dupe(u8, raw);

    var iter = encode(raw, options);
    const first = iter.next().?;
    if (first.len == raw.len and first.ptr == raw.ptr) return allocator.dupe(u8, raw);

    var len = first.len;
    while (iter.next()) |part| len += part.len;

    var result = std.ArrayListUnmanaged(u8).initBuffer(try allocator.alloc(u8, len));

    iter = encode(raw, options);
    while (iter.next()) |part| {
        result.appendSliceAssumeCapacity(part);
    }

    return result.items;
}
test encode_alloc {
    try test_encode_alloc("", .default, "");
    try test_encode_alloc("Hellorld!", .default, "Hellorld%21");
    try test_encode_alloc("a b c", .default, "a%20b%20c");
    try test_encode_alloc("a b c", .init(.default, .{ .spaces = .@"+" }), "a+b+c");
    try test_encode_alloc(" ", .init(.default, .{ .spaces = .percent_encoded }), "%20");
    try test_encode_alloc("Hello World", .init(.default, .{ .spaces = .raw }), "Hello World");
    try test_encode_alloc("_.-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz", .default, "_.-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz");
    try test_encode_alloc("\x00\xFF", .default, "%00%FF");
    try test_encode_alloc("\x00\xFF", .init(.default, .{ .raw = "Z" }), "\x00\xFF");
    try test_encode_alloc("!!", .default, "%21%21");
    try test_encode_alloc("!\"", .default, "%21%22");
    try test_encode_alloc("!#", .default, "%21%23");
    try test_encode_alloc("!$", .default, "%21%24");
    try test_encode_alloc("!%", .default, "%21%25");
    try test_encode_alloc("!&", .default, "%21%26");
    try test_encode_alloc("!'", .default, "%21%27");
    try test_encode_alloc("!(", .default, "%21%28");
    try test_encode_alloc("!)", .default, "%21%29");
    try test_encode_alloc("!*", .default, "%21%2A");
    try test_encode_alloc("!,", .default, "%21%2C");
    try test_encode_alloc("!/", .default, "%21%2F");
    try test_encode_alloc("!:", .default, "%21%3A");
    try test_encode_alloc("!;", .default, "%21%3B");
    try test_encode_alloc("!<", .default, "%21%3C");
    try test_encode_alloc("!=", .default, "%21%3D");
    try test_encode_alloc("!>", .default, "%21%3E");
    try test_encode_alloc("!?", .default, "%21%3F");
    try test_encode_alloc("!@", .default, "%21%40");
    try test_encode_alloc("![", .default, "%21%5B");
    try test_encode_alloc("!\\", .default, "%21%5C");
    try test_encode_alloc("!]", .default, "%21%5D");
    try test_encode_alloc("!^", .default, "%21%5E");
    try test_encode_alloc("!`", .default, "%21%60");
    try test_encode_alloc("!{", .default, "%21%7B");
    try test_encode_alloc("!|", .default, "%21%7C");
    try test_encode_alloc("!}", .default, "%21%7D");
    try test_encode_alloc("!!", .init(.all, .{ .raw = "!" }), "!!");
    try test_encode_alloc("!#", .init(.all, .{ .raw = "#" }), "%21#");
    try test_encode_alloc("!$", .init(.all, .{ .raw = "$" }), "%21$");
    try test_encode_alloc("!&", .init(.all, .{ .raw = "&" }), "%21&");
    try test_encode_alloc("!'", .init(.all, .{ .raw = "'" }), "%21'");
    try test_encode_alloc("!(", .init(.all, .{ .raw = "(" }), "%21(");
    try test_encode_alloc("!)", .init(.all, .{ .raw = ")" }), "%21)");
    try test_encode_alloc("!*", .init(.all, .{ .raw = "*" }), "%21*");
    try test_encode_alloc("!,", .init(.all, .{ .raw = "," }), "%21,");
    try test_encode_alloc("!/", .init(.all, .{ .raw = "/" }), "%21/");
    try test_encode_alloc("!:", .init(.all, .{ .raw = ":" }), "%21:");
    try test_encode_alloc("!;", .init(.all, .{ .raw = ";" }), "%21;");
    try test_encode_alloc("!=", .init(.all, .{ .raw = "=" }), "%21=");
    try test_encode_alloc("!?", .init(.all, .{ .raw = "?" }), "%21?");
    try test_encode_alloc("!@", .init(.all, .{ .raw = "@" }), "%21@");
    try test_encode_alloc("![", .init(.all, .{ .raw = "[" }), "%21[");
    try test_encode_alloc("!]", .init(.all, .{ .raw = "]" }), "%21]");
}
fn test_encode_alloc(input: []const u8, comptime options: Encode_Options, expected: []const u8) !void {
    const actual = try encode_alloc(std.testing.allocator, input, options);
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings(expected, actual);
}

pub fn encode_maybe_append(allocator: std.mem.Allocator, list: *std.ArrayList(u8), raw: []const u8, comptime options: Encode_Options) ![]const u8 {
    // `raw` must not reference the list's backing buffer, since it might be reallocated in this function.
    std.debug.assert(@intFromPtr(raw.ptr) >= @intFromPtr(list.items.ptr + list.capacity)
                  or @intFromPtr(list.items.ptr) >= @intFromPtr(raw.ptr + raw.len));

    if (raw.len == 0) return raw;

    var iter = encode(raw, options);
    const first = iter.next().?;
    if (first.len == raw.len and first.ptr == raw.ptr) return first;

    const prefix_length = list.items.len;
    try list.appendSlice(allocator, first);
    while (iter.next()) |part| {
        try list.appendSlice(allocator, part);
    }

    return list.items[prefix_length..];
}
test encode_maybe_append {
    try test_encode_maybe_append("", .default, "");
    try test_encode_maybe_append("Hellorld!", .default, "Hellorld%21");
    try test_encode_maybe_append(" ", .init(.default, .{ .spaces = .percent_encoded }), "%20");
    try test_encode_maybe_append("Hello World", .init(.default, .{ .spaces = .raw }), "Hello World");
    try test_encode_maybe_append("_.-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz", .default, "_.-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz");
    try test_encode_maybe_append("_.-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz", .init(.default, .{ .percent_encoded = "A0" }), "_.-%41%42%43%44%45%46%47%48%49%4A%4B%4C%4D%4E%4F%50%51%52%53%54%55%56%57%58%59%5A%30%31%32%33%34%35%36%37%38%39%61%62%63%64%65%66%67%68%69%6A%6B%6C%6D%6E%6F%70%71%72%73%74%75%76%77%78%79%7A");
    try test_encode_maybe_append("\x00\xFF", .default, "%00%FF");
    try test_encode_maybe_append("\x00\xFF", .init(.default, .{ .raw = "Z" }), "\x00\xFF");
}
fn test_encode_maybe_append(input: []const u8, comptime options: Encode_Options, expected: []const u8) !void {
    var temp: std.ArrayList(u8) = .empty;
    defer temp.deinit(std.testing.allocator);

    const actual = try encode_maybe_append(std.testing.allocator, &temp, input, options);
    try std.testing.expectEqualStrings(expected, actual);
}

pub fn encode_append(allocator: std.mem.Allocator, list: *std.ArrayList(u8), raw: []const u8, comptime options: Encode_Options) !void {
    var iter = encode(raw, options);
    while (iter.next()) |part| {
        try list.appendSlice(allocator, part);
    }
}
test encode_append {
    try test_encode_append("", .default, "");
    try test_encode_append("Hellorld!", .default, "Hellorld%21");
    try test_encode_append(" ", .init(.default, .{ .spaces = .percent_encoded }), "%20");
    try test_encode_append("Hello World", .init(.default, .{ .spaces = .raw }), "Hello World");
    try test_encode_append("_.-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz", .default, "_.-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz");
    try test_encode_append("_.-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz", .init(.default, .{ .percent_encoded = "A0" }), "_.-%41%42%43%44%45%46%47%48%49%4A%4B%4C%4D%4E%4F%50%51%52%53%54%55%56%57%58%59%5A%30%31%32%33%34%35%36%37%38%39%61%62%63%64%65%66%67%68%69%6A%6B%6C%6D%6E%6F%70%71%72%73%74%75%76%77%78%79%7A");
    try test_encode_append("\x00\xFF", .default, "%00%FF");
    try test_encode_append("\x00\xFF", .init(.default, .{ .raw = "Z" }), "\x00\xFF");
}
fn test_encode_append(input: []const u8, comptime options: Encode_Options, expected: []const u8) !void {
    var temp: std.ArrayList(u8) = .empty;
    defer temp.deinit(std.testing.allocator);

    try encode_append(std.testing.allocator, &temp, input, options);
    try std.testing.expectEqualStrings(expected, temp.items);
}

pub fn encode_writer(writer: *std.Io.Writer, input: []const u8, comptime options: Encode_Options) std.Io.Writer.Error!void {
    var encoder = encode(input, options);
    while (encoder.next()) |chunk| {
        try writer.writeAll(chunk);
    }
}

pub fn encode(raw: []const u8, comptime options: Encode_Options) Encoder(options) {
    return .{ .remaining = raw };
}
pub fn Encoder(comptime options: Encode_Options) type {
    comptime if (options.spaces == .@"+") std.debug.assert(options.@"+" == .percent_encoded);
    return struct {
        remaining: []const u8,
        temp: [3]u8 = "%00".*,

        pub fn next(self: *@This()) ?[]const u8 {
            const remaining = self.remaining;
            if (remaining.len == 0) return null;

            for (0.., remaining) |i, c| {
                const should_encode = options.should_encode(c);

                if (should_encode) {
                    if (i > 0) {
                        self.remaining = remaining[i..];
                        return remaining[0..i];
                    }
                    var temp: []u8 = &self.temp;
                    if (c == ' ' and options.spaces == .@"+") {
                        temp = temp[2..];
                        temp[0] = '+';
                    } else {
                        @memcpy(temp[1..], &std.fmt.bytesToHex(&[_]u8{c}, .upper));
                    }
                    self.remaining = remaining[1..];
                    return temp;
                }
            }

            self.remaining = "";
            return remaining;
        }
    };
}

pub const Decode_Options = struct {
    decode_plus_as_space: bool,

    pub const default: Decode_Options = .{
        .decode_plus_as_space = true,
    };
};
pub fn decode_alloc(allocator: std.mem.Allocator, encoded: []const u8, comptime options: Decode_Options) ![]const u8 {
    if (encoded.len == 0) return try allocator.dupe(u8, encoded);

    var iter = decode(encoded, options);
    const first = iter.next().?;
    if (first.len == encoded.len and first.ptr == encoded.ptr) return try allocator.dupe(u8, encoded);

    var len = first.len;
    while (iter.next()) |part| len += part.len;

    var result = std.ArrayListUnmanaged(u8).initBuffer(try allocator.alloc(u8, len));

    iter = decode(encoded, options);
    while (iter.next()) |part| {
        result.appendSliceAssumeCapacity(part);
    }

    return result.items;
}
test decode_alloc {
    try test_decode_alloc("", .default, "");
    try test_decode_alloc("Hellorld!", .default, "Hellorld!");
    try test_decode_alloc("Hellorld%21", .default, "Hellorld!");
    try test_decode_alloc("a+b+c", .default, "a b c");
    try test_decode_alloc("+", .{ .decode_plus_as_space = false }, "+");
    try test_decode_alloc("Hello%20World", .default, "Hello World");
    try test_decode_alloc("~_.-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz", .default, "~_.-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz");
    try test_decode_alloc("%00%FF", .default, "\x00\xFF");
    try test_decode_alloc("%21%21", .default, "!!");
    try test_decode_alloc("%21%22", .default, "!\"");
    try test_decode_alloc("%21%23", .default, "!#");
    try test_decode_alloc("%21%24", .default, "!$");
    try test_decode_alloc("%21%25", .default, "!%");
    try test_decode_alloc("%21%26", .default, "!&");
    try test_decode_alloc("%21%27", .default, "!'");
    try test_decode_alloc("%21%28", .default, "!(");
    try test_decode_alloc("%21%29", .default, "!)");
    try test_decode_alloc("%21%2A", .default, "!*");
    try test_decode_alloc("%21%2C", .default, "!,");
    try test_decode_alloc("%21%2F", .default, "!/");
    try test_decode_alloc("%21%3A", .default, "!:");
    try test_decode_alloc("%21%3B", .default, "!;");
    try test_decode_alloc("%21%3C", .default, "!<");
    try test_decode_alloc("%21%3D", .default, "!=");
    try test_decode_alloc("%21%3E", .default, "!>");
    try test_decode_alloc("%21%3F", .default, "!?");
    try test_decode_alloc("%21%40", .default, "!@");
    try test_decode_alloc("%21%5B", .default, "![");
    try test_decode_alloc("%21%5C", .default, "!\\");
    try test_decode_alloc("%21%5D", .default, "!]");
    try test_decode_alloc("%21%5E", .default, "!^");
    try test_decode_alloc("%21%60", .default, "!`");
    try test_decode_alloc("%21%7B", .default, "!{");
    try test_decode_alloc("%21%7C", .default, "!|");
    try test_decode_alloc("%21%7D", .default, "!}");
}
fn test_decode_alloc(input: []const u8, comptime options: Decode_Options, expected: []const u8) !void {
    const actual = try decode_alloc(std.testing.allocator, input, options);
    defer std.testing.allocator.free(actual);
    try std.testing.expectEqualStrings(expected, actual);
}

pub fn decode_maybe_append(allocator: std.mem.Allocator, list: *std.ArrayList(u8), encoded: []const u8, comptime options: Decode_Options) ![]const u8 {
    // `encoded` must not reference the list's backing buffer, since it might be reallocated in this function.
    std.debug.assert(@intFromPtr(encoded.ptr) >= @intFromPtr(list.items.ptr + list.capacity)
                  or @intFromPtr(list.items.ptr) >= @intFromPtr(encoded.ptr + encoded.len));

    if (encoded.len == 0) return encoded;

    var iter = decode(encoded, options);
    const first = iter.next().?;
    if (first.len == encoded.len and first.ptr == encoded.ptr) return first;

    const prefix_length = list.items.len;
    try list.appendSlice(allocator, first);
    while (iter.next()) |part| {
        try list.appendSlice(allocator, part);
    }

    return list.items[prefix_length..];
}
test decode_maybe_append {
    try test_decode_maybe_append("", .default, "");
    try test_decode_maybe_append("Hellorld!", .default, "Hellorld!");
    try test_decode_maybe_append("Hellorld%21", .default, "Hellorld!");
    try test_decode_maybe_append("a+b+c", .default, "a b c");
    try test_decode_maybe_append("+", .{ .decode_plus_as_space = false }, "+");
    try test_decode_maybe_append("Hello%20World", .default, "Hello World");
    try test_decode_maybe_append("~_.-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz", .default, "~_.-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz");
}
fn test_decode_maybe_append(input: []const u8, comptime options: Decode_Options, expected: []const u8) !void {
    var temp: std.ArrayList(u8) = .empty;
    defer temp.deinit(std.testing.allocator);

    const actual = try decode_maybe_append(std.testing.allocator, &temp, input, options);
    try std.testing.expectEqualStrings(expected, actual);
}

pub fn decode_append(allocator: std.mem.Allocator, list: *std.ArrayList(u8), encoded: []const u8, comptime options: Decode_Options) !void {
    var iter = decode(encoded, options);
    while (iter.next()) |part| {
        try list.appendSlice(allocator, part);
    }
}
test decode_append {
    try test_decode_append("", .default, "");
    try test_decode_append("Hellorld!", .default, "Hellorld!");
    try test_decode_append("Hellorld%21", .default, "Hellorld!");
    try test_decode_append("a+b+c", .default, "a b c");
    try test_decode_append("+", .{ .decode_plus_as_space = false }, "+");
    try test_decode_append("Hello%20World", .default, "Hello World");
    try test_decode_append("~_.-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz", .default, "~_.-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz");
}
fn test_decode_append(input: []const u8, comptime options: Decode_Options, expected: []const u8) !void {
    var temp: std.ArrayList(u8) = .empty;
    defer temp.deinit(std.testing.allocator);

    try decode_append(std.testing.allocator, &temp, input, options);
    try std.testing.expectEqualStrings(expected, temp.items);
}

pub fn decode_in_place(encoded: []u8, comptime options: Decode_Options) []const u8 {
    return decode_backwards(encoded, encoded, options);
}

pub fn decode_backwards(output: []u8, encoded: []const u8, comptime options: Decode_Options) []const u8 {
    var remaining = output;
    var iter = decode(encoded, options);
    while (iter.next()) |span| {
        std.mem.copyForwards(u8, remaining, span);
        remaining = remaining[span.len..];
    }
    return output[0 .. output.len - remaining.len];
}

pub fn decode_writer(writer: *std.Io.Writer, encoded: []const u8, comptime options: Decode_Options) std.Io.Writer.Error!void {
    var iter = decode(encoded, options);
    while (iter.next()) |part| {
        try writer.writeAll(part);
    }
}

pub fn decode(encoded: []const u8, comptime options: Decode_Options) Decoder(options) {
    return .{ .remaining = encoded };
}
pub fn Decoder(comptime options: Decode_Options) type {
    return struct {
        remaining: []const u8,
        temp: [1]u8 = undefined,

        pub fn next(self: *@This()) ?[]const u8 {
            const remaining = self.remaining;
            if (remaining.len == 0) return null;

            if (remaining[0] == '%') {
                if (remaining.len >= 3) {
                    self.temp[0] = std.fmt.parseInt(u8, remaining[1..3], 16) catch {
                        self.remaining = remaining[1..];
                        return remaining[0..1];
                    };
                    self.remaining = remaining[3..];
                    return &self.temp;
                } else {
                    self.remaining = remaining[1..];
                    return remaining[0..1];
                }
            } else if (options.decode_plus_as_space and remaining[0] == '+') {
                self.temp[0] = ' ';
                self.remaining = remaining[1..];
                return &self.temp;
            }

            if (options.decode_plus_as_space) {
                if (std.mem.indexOfAny(u8, remaining, "%+")) |end| {
                    self.remaining = remaining[end..];
                    return remaining[0..end];
                }
            } else {
                if (std.mem.indexOfScalar(u8, remaining, '%')) |end| {
                    self.remaining = remaining[end..];
                    return remaining[0..end];
                }
            }

            self.remaining = "";
            return remaining;
        }
    };
}

pub fn fmt(raw: []const u8, comptime encode_options: Encode_Options) Formatter(encode_options) {
    return .{ .data = raw };
}

pub fn Formatter(comptime encode_options: Encode_Options) type {
    return struct {
        data: []const u8,

        pub fn format(self: @This(), writer: *std.Io.Writer) std.Io.Writer.Error!void {
            var encoder = encode(self.data, encode_options);
            while (encoder.next()) |chunk| {
                try writer.writeAll(chunk);
            }
        }
    };
}

test fmt {
    try test_fmt("", .default, "");
    try test_fmt("Hellorld!", .default, "Hellorld%21");
    try test_fmt(" ", .default, "%20");
    try test_fmt("~_.-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz", .default, "~_.-ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz");
    try test_fmt("@*", .init(.none, .{ .percent_encoded = "*" }), "@%2A");
    try test_fmt("[@*]", .init(.all, .{ .raw = "[]" }), "[%40%2A]");
}
fn test_fmt(input: []const u8, comptime options: Encode_Options, expected: []const u8) !void {
    const temp = try std.fmt.allocPrint(std.testing.allocator, "{f}", .{ fmt(input, options) });
    defer std.testing.allocator.free(temp);
    try std.testing.expectEqualStrings(expected, temp);
}

const std = @import("std");
