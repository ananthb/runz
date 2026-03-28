const std = @import("std");
const containerfile = @import("containerfile.zig");
const image = @import("image.zig");
const layout_writer = @import("layout_writer.zig");

// Fuzz targets for oci-zig parsers.
// Run with: zig build fuzz -ffuzz
// Run once (as regular test): zig build fuzz

test "fuzz: containerfile parser" {
    try std.testing.fuzz({}, struct {
        fn testOne(_: void, input: []const u8) !void {
            // The parser should never crash on arbitrary input
            const cf = containerfile.Containerfile.parse(std.testing.allocator, input) catch return;
            cf.deinit(std.testing.allocator);
        }
    }.testOne, .{
        .corpus = &.{
            "FROM alpine\nRUN echo hello\n",
            "FROM ubuntu:22.04\nCOPY . /app\nCMD [\"./app\"]\n",
            "FROM scratch\nENV FOO=bar\nWORKDIR /app\nENTRYPOINT [\"/bin/sh\"]\n",
            "ARG VERSION=1.0\nFROM alpine:${VERSION}\nLABEL version=${VERSION}\n",
            "FROM golang:1.21 AS builder\nCOPY --from=builder /app /app\n",
            "FROM alpine\nRUN apk add \\\n  curl \\\n  jq\n",
            "",
            "#",
            "INVALID LINE",
            "FROM",
            "COPY",
            "ENV",
            "RUN [\"echo\", \"hello\"]",
        },
    });
}

test "fuzz: image reference parser" {
    try std.testing.fuzz({}, struct {
        fn testOne(_: void, input: []const u8) !void {
            // The parser should never crash on arbitrary input
            var ref = image.ImageReference.parse(input, std.testing.allocator) catch return;
            ref.deinit(std.testing.allocator);
        }
    }.testOne, .{
        .corpus = &.{
            "alpine",
            "alpine:latest",
            "alpine:3.18",
            "library/alpine:latest",
            "docker.io/library/alpine:latest",
            "ghcr.io/user/repo:v1.0",
            "localhost:5000/myimage:tag",
            "registry.example.com/org/repo:sha256@abc123",
            "",
            ":",
            "/",
            "@sha256:",
            "a:b:c:d",
            "very/deep/nested/path/image:tag",
        },
    });
}

test "fuzz: image reference normalizer" {
    const config = @import("containerfile.zig"); // just to get it compiled
    _ = config;

    try std.testing.fuzz({}, struct {
        fn testOne(_: void, input: []const u8) !void {
            // hashBytes should never crash
            _ = layout_writer.hashBytes(input);
        }
    }.testOne, .{
        .corpus = &.{
            "",
            "hello world",
            "a",
            &[_]u8{0} ** 64,
            &[_]u8{0xFF} ** 256,
        },
    });
}

test "fuzz: json string array builder" {
    try std.testing.fuzz({}, struct {
        fn testOne(_: void, input: []const u8) !void {
            // Split input on newlines to create array items
            var items_list: std.ArrayListUnmanaged([]const u8) = .{};
            defer items_list.deinit(std.testing.allocator);

            var iter = std.mem.splitScalar(u8, input, '\n');
            while (iter.next()) |item| {
                items_list.append(std.testing.allocator, item) catch return;
            }

            const result = layout_writer.buildJsonStringArray(
                std.testing.allocator,
                items_list.items,
            ) catch return;
            std.testing.allocator.free(result);
        }
    }.testOne, .{
        .corpus = &.{
            "",
            "hello",
            "hello\nworld",
            "/bin/sh\n-c\necho hello",
            "path with spaces\n\"quotes\"\nnewline\\n",
        },
    });
}
