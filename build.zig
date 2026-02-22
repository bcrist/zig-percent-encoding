const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    _ = b.addModule("percent_encoding", .{
        .root_source_file = b.path("percent_encoding.zig"),
    });

    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("percent_encoding.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.step("test", "Run tests").dependOn(&b.addRunArtifact(tests).step);

    const benchmark = b.addExecutable(.{
        .name = "benchmark",
        .root_module = b.createModule(.{
            .root_source_file = b.path("benchmark.zig"),
            .target = target,
            .optimize = optimize,
        }),
    });
    b.step("benchmark", "Run benchmark").dependOn(&b.addRunArtifact(benchmark).step);
}
