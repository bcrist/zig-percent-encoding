
const min_content_length = 50 * 1024 * 1024;
const total_iterations = 5;
const warmup_iterations = 1;

pub fn main(init: std.process.Init) !void {
    var content: std.ArrayList(u8) = try .initCapacity(init.gpa, min_content_length + 100);
    defer content.deinit(init.gpa);
    
    var seed: [4]u64 = undefined;
    std.Io.random(init.io, std.mem.asBytes(&seed));

    var xoshiro: std.Random.Xoshiro256 = .{ .s = seed };
    const rnd = xoshiro.random();
    while (content.items.len < min_content_length) {
        const kind = rnd.float(f32);
        if (kind < 0.1) {
            // random byte
            try content.append(init.gpa, rnd.int(u8));
        } else if (kind < 0.5) {
            // random reserved char
            const reserved = "!#$&\'()*+,/:;=?@[] ";
            try content.append(init.gpa, reserved[rnd.intRangeLessThan(u8, 0, reserved.len)]);
        } else {
            // alphanumeric string
            const alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
            for (0..100) |_| {
                try content.append(init.gpa, alpha[rnd.intRangeLessThan(u8, 0, alpha.len)]);
                if (rnd.float(f32) < 0.05) break;
            }
        }
    }

    var temp: std.ArrayList(u8) = try .initCapacity(init.gpa, min_content_length + 100);
    defer temp.deinit(init.gpa);

    var temp2: std.ArrayList(u8) = try .initCapacity(init.gpa, min_content_length + 100);
    defer temp2.deinit(init.gpa);

    for (0..total_iterations) |i| {
        temp.clearRetainingCapacity();

        const begin = std.Io.Clock.awake.now(init.io);
        try percent_encoding.encode_append(init.gpa, &temp, content.items, .init(.default, .{ .spaces = .percent_encoded }));
        const end = std.Io.Clock.awake.now(init.io);

        if (i >= warmup_iterations) {
            const nanos: f64 = @floatFromInt(begin.durationTo(end).toNanoseconds());
            const bytes: f64 = @floatFromInt(content.items.len);
            const nanos_per_byte = nanos / bytes;
            std.debug.print("percent_encoding.encode_append: {} ns/B\n", .{ nanos_per_byte });
        }
    }

    for (0..total_iterations) |i| {
        temp.clearRetainingCapacity();
        var writer = std.Io.Writer.Allocating.fromArrayList(init.gpa, &temp);

        const begin = std.Io.Clock.awake.now(init.io);
        try writer.writer.print("{f}", .{ percent_encoding.fmt(content.items, .default) });
        const end = std.Io.Clock.awake.now(init.io);

        temp = writer.toArrayList();

        if (i >= warmup_iterations) {
            const nanos: f64 = @floatFromInt(begin.durationTo(end).toNanoseconds());
            const bytes: f64 = @floatFromInt(content.items.len);
            const nanos_per_byte = nanos / bytes;
            std.debug.print("percent_encoding.fmt: {} ns/B\n", .{ nanos_per_byte });
        }
    }

    for (0..total_iterations) |i| {
        temp.clearRetainingCapacity();
        var writer = std.Io.Writer.Allocating.fromArrayList(init.gpa, &temp);

        const begin = std.Io.Clock.awake.now(init.io);
        try percent_encoding.encode_writer(&writer.writer, content.items, .init(.default, .{ .spaces = .percent_encoded }));
        const end = std.Io.Clock.awake.now(init.io);

        temp = writer.toArrayList();

        if (i >= warmup_iterations) {
            const nanos: f64 = @floatFromInt(begin.durationTo(end).toNanoseconds());
            const bytes: f64 = @floatFromInt(content.items.len);
            const nanos_per_byte = nanos / bytes;
            std.debug.print("percent_encoding.encode_writer: {} ns/B\n", .{ nanos_per_byte });
        }
    }

    for (0..total_iterations) |i| {
        temp.clearRetainingCapacity();
        var writer = std.Io.Writer.Allocating.fromArrayList(init.gpa, &temp);

        const begin = std.Io.Clock.awake.now(init.io);
        try std.Uri.Component.percentEncode(&writer.writer, content.items, is_valid);
        const end = std.Io.Clock.awake.now(init.io);

        temp = writer.toArrayList();

        if (i >= warmup_iterations) {
            const nanos: f64 = @floatFromInt(begin.durationTo(end).toNanoseconds());
            const bytes: f64 = @floatFromInt(content.items.len);
            const nanos_per_byte = nanos / bytes;
            std.debug.print("std.Uri.Component.percentEncode: {} ns/B\n", .{ nanos_per_byte });
        }
    }

    for (0..total_iterations) |i| {
        temp2.clearRetainingCapacity();
        try temp2.appendSlice(init.gpa, temp.items);

        const begin = std.Io.Clock.awake.now(init.io);
        const result = percent_encoding.decode_in_place(temp2.items, .{ .decode_plus_as_space = false });
        const end = std.Io.Clock.awake.now(init.io);

        var checksum: usize = 0;
        for (result) |b| {
            checksum += b;
        }

        if (i >= warmup_iterations) {
            const nanos: f64 = @floatFromInt(begin.durationTo(end).toNanoseconds());
            const bytes: f64 = @floatFromInt(content.items.len);
            const nanos_per_byte = nanos / bytes;
            std.debug.print("percent_encoding.decode_in_place: {} ns/B (checksum {})\n", .{ nanos_per_byte, checksum });
        }
    }

    for (0..total_iterations) |i| {
        temp2.clearRetainingCapacity();
        try temp2.appendSlice(init.gpa, temp.items);

        const begin = std.Io.Clock.awake.now(init.io);
        const result = std.Uri.percentDecodeInPlace(temp2.items);
        const end = std.Io.Clock.awake.now(init.io);

        var checksum: usize = 0;
        for (result) |b| {
            checksum += b;
        }

        if (i >= warmup_iterations) {
            const nanos: f64 = @floatFromInt(begin.durationTo(end).toNanoseconds());
            const bytes: f64 = @floatFromInt(content.items.len);
            const nanos_per_byte = nanos / bytes;
            std.debug.print("std.Uri.percentDecodeInPlace: {} ns/B (checksum {})\n", .{ nanos_per_byte, checksum });
        }
    }
}

fn is_valid(c: u8) bool {
    return !percent_encoding.Encode_Options.should_encode(.default, c);
}

const percent_encoding = @import("percent_encoding.zig");
const std = @import("std");
