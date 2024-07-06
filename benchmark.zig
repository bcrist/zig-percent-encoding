
const min_content_length = 100 * 1024 * 1024;
const total_iterations = 10;
const warmup_iterations = 2;

pub fn main() !void {
    defer std.debug.assert(.ok == gpa.deinit());

    var content = try std.ArrayList(u8).initCapacity(gpa.allocator(), min_content_length + 100);
    defer content.deinit();
    
    var xoshiro: std.rand.Xoshiro256 = .{ .s = .{
        std.crypto.random.int(u64),
        std.crypto.random.int(u64),
        std.crypto.random.int(u64),
        std.crypto.random.int(u64),
    }};
    const rnd = xoshiro.random();
    while (content.items.len < min_content_length) {
        const kind = rnd.float(f32);
        if (kind < 0.1) {
            // random byte
            try content.append(rnd.int(u8));
        } else if (kind < 0.5) {
            // random reserved char
            const reserved = "!#$&\'()*+,/:;=?@[] ";
            try content.append(reserved[rnd.intRangeLessThan(u8, 0, reserved.len)]);
        } else {
            // alphanumeric string
            const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
            for (0..100) |_| {
                try content.append(alpha[rnd.intRangeLessThan(u8, 0, alpha.len)]);
                if (rnd.float(f32) < 0.05) break;
            }
        }
    }

    var temp = try std.ArrayList(u8).initCapacity(gpa.allocator(), min_content_length + 100);
    defer temp.deinit();

    var temp2 = try std.ArrayList(u8).initCapacity(gpa.allocator(), min_content_length + 100);
    defer temp2.deinit();

    for (0..total_iterations) |i| {
        temp.clearRetainingCapacity();

        const begin = std.time.nanoTimestamp();
        try percent_encoding.encode_append(&temp, content.items, .{ .spaces = .percent_encoded });
        const end = std.time.nanoTimestamp();

        if (i >= warmup_iterations) {
            const nanos: f64 = @floatFromInt(end - begin);
            const bytes: f64 = @floatFromInt(content.items.len);
            const nanos_per_byte = nanos / bytes;
            std.debug.print("percent_encoding.encode_append: {} ns/B\n", .{ nanos_per_byte });
        }
    }

    for (0..total_iterations) |i| {
        temp.clearRetainingCapacity();
        const writer = temp.writer();

        const begin = std.time.nanoTimestamp();
        try writer.print("{ }", .{ percent_encoding.fmtEncoded(content.items) });
        const end = std.time.nanoTimestamp();

        if (i >= warmup_iterations) {
            const nanos: f64 = @floatFromInt(end - begin);
            const bytes: f64 = @floatFromInt(content.items.len);
            const nanos_per_byte = nanos / bytes;
            std.debug.print("percent_encoding.fmtEncoded: {} ns/B\n", .{ nanos_per_byte });
        }
    }

    for (0..total_iterations) |i| {
        temp.clearRetainingCapacity();
        const writer = temp.writer();

        const begin = std.time.nanoTimestamp();
        try percent_encoding.encode_writer(writer, content.items, .{ .spaces = .percent_encoded });
        const end = std.time.nanoTimestamp();

        if (i >= warmup_iterations) {
            const nanos: f64 = @floatFromInt(end - begin);
            const bytes: f64 = @floatFromInt(content.items.len);
            const nanos_per_byte = nanos / bytes;
            std.debug.print("percent_encoding.encode_writer: {} ns/B\n", .{ nanos_per_byte });
        }
    }

    for (0..total_iterations) |i| {
        temp.clearRetainingCapacity();
        const writer = temp.writer();

        const begin = std.time.nanoTimestamp();
        try std.Uri.Component.percentEncode(writer, content.items, is_valid);
        const end = std.time.nanoTimestamp();

        if (i >= warmup_iterations) {
            const nanos: f64 = @floatFromInt(end - begin);
            const bytes: f64 = @floatFromInt(content.items.len);
            const nanos_per_byte = nanos / bytes;
            std.debug.print("std.Uri.Component.percentEncode: {} ns/B\n", .{ nanos_per_byte });
        }
    }

    for (0..total_iterations) |i| {
        temp2.clearRetainingCapacity();
        try temp2.appendSlice(temp.items);

        const begin = std.time.nanoTimestamp();
        const result = percent_encoding.decode_in_place(temp2.items, .{ .decode_plus_as_space = false });
        const end = std.time.nanoTimestamp();

        var checksum: usize = 0;
        for (result) |b| {
            checksum += b;
        }

        if (i >= warmup_iterations) {
            const nanos: f64 = @floatFromInt(end - begin);
            const bytes: f64 = @floatFromInt(content.items.len);
            const nanos_per_byte = nanos / bytes;
            std.debug.print("percent_encoding.decode_in_place: {} ns/B (checksum {})\n", .{ nanos_per_byte, checksum });
        }
    }

    for (0..total_iterations) |i| {
        temp2.clearRetainingCapacity();
        try temp2.appendSlice(temp.items);

        const begin = std.time.nanoTimestamp();
        const result = std.Uri.percentDecodeInPlace(temp2.items);
        const end = std.time.nanoTimestamp();

        var checksum: usize = 0;
        for (result) |b| {
            checksum += b;
        }

        if (i >= warmup_iterations) {
            const nanos: f64 = @floatFromInt(end - begin);
            const bytes: f64 = @floatFromInt(content.items.len);
            const nanos_per_byte = nanos / bytes;
            std.debug.print("std.Uri.percentDecodeInPlace: {} ns/B (checksum {})\n", .{ nanos_per_byte, checksum });
        }
    }
}

fn is_valid(c: u8) bool {
    return switch (c) {
        '-', '.', '_', '~', 'A'...'Z', 'a'...'z', '0'...'9' => true,
        else => false,
    };
}

var gpa: std.heap.GeneralPurposeAllocator(.{}) = .{};

const percent_encoding = @import("percent_encoding.zig");
const std = @import("std");
