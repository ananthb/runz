const std = @import("std");
const log = @import("log.zig");
const image = @import("image.zig");

const scoped_log = log.scoped("oci/layer");

pub const LayerError = error{
    InvalidLayer,
    ExtractionFailed,
    UnsupportedCompression,
    InvalidWhiteout,
    IoError,
    OutOfMemory,
} || std.fs.File.OpenError || std.fs.File.ReadError;

/// Supported compression formats
pub const Compression = enum {
    none,
    gzip,
    zstd,

    pub fn fromMediaType(media_type: []const u8) Compression {
        if (std.mem.indexOf(u8, media_type, "+gzip") != null) {
            return .gzip;
        } else if (std.mem.indexOf(u8, media_type, "+zstd") != null) {
            return .zstd;
        }
        return .none;
    }
};

/// Layer extraction options
pub const ExtractOptions = struct {
    /// Target directory
    target: []const u8,

    /// Handle whiteout files (OCI layer deletions)
    handle_whiteouts: bool = true,

    /// Preserve permissions and ownership
    preserve_permissions: bool = true,

    /// Overwrite existing files
    overwrite: bool = true,
};

/// Extract a layer tarball to a directory using Zig's std.tar and
/// std.compress for decompression (no external tar/gzip/zstd binaries).
pub fn extractLayer(
    layer_path: []const u8,
    compression: Compression,
    options: ExtractOptions,
    allocator: std.mem.Allocator,
) LayerError!void {
    scoped_log.info("Extracting layer {s} to {s}", .{ layer_path, options.target });

    // Open the layer file
    const file = std.fs.openFileAbsolute(layer_path, .{}) catch |err| {
        scoped_log.err("Failed to open layer file {s}: {}", .{ layer_path, err });
        return err;
    };
    defer file.close();

    // Create a file reader
    var read_buf: [32768]u8 = undefined;
    var file_reader = file.reader(&read_buf);

    // Open the target directory
    var dir = std.fs.openDirAbsolute(options.target, .{}) catch |err| {
        scoped_log.err("Failed to open target directory {s}: {}", .{ options.target, err });
        return error.ExtractionFailed;
    };
    defer dir.close();

    // Set up decompression based on compression type and extract
    switch (compression) {
        .none => {
            scoped_log.debug("Extracting uncompressed tar {s}", .{layer_path});
            std.tar.pipeToFileSystem(dir, &file_reader.interface, .{}) catch |err| {
                scoped_log.err("Failed to extract tar: {}", .{err});
                return error.ExtractionFailed;
            };
        },
        .gzip => {
            scoped_log.debug("Extracting gzip-compressed tar {s}", .{layer_path});
            var decompress_buf: [std.compress.flate.max_window_len]u8 = undefined;
            var decompressor = std.compress.flate.Decompress.init(&file_reader.interface, .gzip, &decompress_buf);
            std.tar.pipeToFileSystem(dir, &decompressor.reader, .{}) catch |err| {
                scoped_log.err("Failed to extract gzip tar: {}", .{err});
                return error.ExtractionFailed;
            };
        },
        .zstd => {
            scoped_log.debug("Extracting zstd-compressed tar {s}", .{layer_path});
            var zstd_buf: [std.compress.zstd.default_window_len + std.compress.zstd.block_size_max]u8 = undefined;
            var decompressor = std.compress.zstd.Decompress.init(&file_reader.interface, &zstd_buf, .{});
            std.tar.pipeToFileSystem(dir, &decompressor.reader, .{}) catch |err| {
                scoped_log.err("Failed to extract zstd tar: {}", .{err});
                return error.ExtractionFailed;
            };
        },
    }

    // Handle whiteout files if requested
    if (options.handle_whiteouts) {
        processWhiteouts(options.target, allocator) catch |err| {
            scoped_log.warn("Whiteout processing failed: {}", .{err});
        };
    }

    scoped_log.info("Layer extracted successfully", .{});
}

/// Process OCI whiteout files in a directory
fn processWhiteouts(dir_path: []const u8, allocator: std.mem.Allocator) !void {
    scoped_log.debug("Processing whiteouts in {s}", .{dir_path});

    var whiteouts: std.ArrayListUnmanaged([]const u8) = .{};
    defer {
        for (whiteouts.items) |w| {
            allocator.free(w);
        }
        whiteouts.deinit(allocator);
    }

    // Walk directory tree looking for whiteout files
    try collectWhiteouts(dir_path, &whiteouts, allocator);

    // Process each whiteout
    for (whiteouts.items) |whiteout_path| {
        applyWhiteout(whiteout_path, allocator) catch {};
    }
}

/// Collect all whiteout files in a directory tree
fn collectWhiteouts(dir_path: []const u8, whiteouts: *std.ArrayListUnmanaged([]const u8), allocator: std.mem.Allocator) !void {
    var dir = std.fs.openDirAbsolute(dir_path, .{ .iterate = true }) catch return;
    defer dir.close();

    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        const full_path = try std.fs.path.join(allocator, &.{ dir_path, entry.name });
        errdefer allocator.free(full_path);

        if (entry.kind == .directory) {
            try collectWhiteouts(full_path, whiteouts, allocator);
            allocator.free(full_path);
        } else if (std.mem.startsWith(u8, entry.name, ".wh.")) {
            try whiteouts.append(allocator, full_path);
        } else {
            allocator.free(full_path);
        }
    }
}

/// Apply a whiteout file (delete the target and the whiteout marker)
fn applyWhiteout(whiteout_path: []const u8, allocator: std.mem.Allocator) !void {
    const basename = std.fs.path.basename(whiteout_path);
    const dirname = std.fs.path.dirname(whiteout_path) orelse return;

    // Extract target name (remove .wh. prefix)
    if (!std.mem.startsWith(u8, basename, ".wh.")) return;
    const target_name = basename[4..];

    // Handle .wh..wh..opq (opaque whiteout - delete entire directory contents)
    if (std.mem.eql(u8, target_name, ".opq")) {
        std.fs.deleteFileAbsolute(whiteout_path) catch {};
        return;
    }

    // Regular whiteout - delete the target
    const target_path = try std.fs.path.join(allocator, &.{ dirname, target_name });
    defer allocator.free(target_path);

    // Try to delete as file first, then as directory
    std.fs.deleteFileAbsolute(target_path) catch {
        std.fs.deleteTreeAbsolute(target_path) catch {};
    };

    // Delete the whiteout marker
    std.fs.deleteFileAbsolute(whiteout_path) catch {};
}

/// Verify layer integrity using digest
pub fn verifyLayer(layer_path: []const u8, expected_digest: []const u8) !bool {
    scoped_log.debug("Verifying layer {s} against {s}", .{ layer_path, expected_digest });

    const colon_idx = std.mem.indexOf(u8, expected_digest, ":") orelse return false;
    const algorithm = expected_digest[0..colon_idx];
    const hash = expected_digest[colon_idx + 1 ..];

    if (!std.mem.eql(u8, algorithm, "sha256")) {
        scoped_log.warn("Unsupported digest algorithm: {s}", .{algorithm});
        return false;
    }

    const file = std.fs.openFileAbsolute(layer_path, .{}) catch return false;
    defer file.close();

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});

    var buf: [8192]u8 = undefined;
    while (true) {
        const n = file.read(&buf) catch return false;
        if (n == 0) break;
        hasher.update(buf[0..n]);
    }

    var computed_hash: [32]u8 = undefined;
    hasher.final(&computed_hash);

    const computed_hex = std.fmt.bytesToHex(computed_hash, .lower);

    return std.mem.eql(u8, &computed_hex, hash);
}

/// Get layer size from a file
pub fn getLayerSize(layer_path: []const u8) !u64 {
    const file = try std.fs.openFileAbsolute(layer_path, .{});
    defer file.close();

    const stat = try file.stat();
    return stat.size;
}

test "compression detection" {
    const testing = std.testing;

    try testing.expectEqual(Compression.gzip, Compression.fromMediaType("application/vnd.oci.image.layer.v1.tar+gzip"));
    try testing.expectEqual(Compression.zstd, Compression.fromMediaType("application/vnd.oci.image.layer.v1.tar+zstd"));
    try testing.expectEqual(Compression.none, Compression.fromMediaType("application/vnd.oci.image.layer.v1.tar"));
}

test "ExtractOptions defaults" {
    const opts = ExtractOptions{
        .target = "/tmp/test",
    };

    const testing = std.testing;
    try testing.expect(opts.handle_whiteouts);
    try testing.expect(opts.preserve_permissions);
    try testing.expect(opts.overwrite);
}
