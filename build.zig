const std = @import("std");

pub fn build(b: *std.Build) void {
    _ = b.addModule("percent_encoding", .{
        .root_source_file = b.path("percent_encoding.zig"),
    });

    const tests = b.addTest(.{
        .root_source_file = b.path("percent_encoding.zig"),
        .target = b.standardTargetOptions(.{}),
        .optimize = b.standardOptimizeOption(.{}),
    });

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);
}
