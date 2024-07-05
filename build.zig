const std = @import("std");

pub fn build(b: *std.Build) void {
    _ = b.addModule("percent_encoding", .{
        .root_source_file = b.path("percent_encoding.zig"),
    });

    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const tests = b.addTest(.{
        .root_source_file = b.path("percent_encoding.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_tests.step);

    const benchmark = b.addExecutable(.{
        .name = "benchmark",
        .root_source_file = b.path("benchmark.zig"),
        .target = target,
        .optimize = optimize,
    });

    const run_benchmark = b.addRunArtifact(benchmark);
    const benchmark_step = b.step("benchmark", "Run benchmark");
    benchmark_step.dependOn(&run_benchmark.step);
}
