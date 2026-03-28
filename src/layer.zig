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
///
/// Uses a custom extraction loop instead of std.tar.pipeToFileSystem because:
/// 1. OCI layers can have absolute paths (leading /) that must be made relative
/// 2. Later layers must overwrite files from earlier layers (no O_EXCL)
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

    // Set up decompression and extract
    switch (compression) {
        .none => {
            scoped_log.debug("Extracting uncompressed tar {s}", .{layer_path});
            extractTarToDir(dir, &file_reader.interface) catch |err| {
                scoped_log.err("Failed to extract tar: {}", .{err});
                return error.ExtractionFailed;
            };
        },
        .gzip => {
            scoped_log.debug("Extracting gzip-compressed tar {s}", .{layer_path});
            var decompress_buf: [std.compress.flate.max_window_len]u8 = undefined;
            var decompressor = std.compress.flate.Decompress.init(&file_reader.interface, .gzip, &decompress_buf);
            extractTarToDir(dir, &decompressor.reader) catch |err| {
                scoped_log.err("Failed to extract gzip tar: {}", .{err});
                return error.ExtractionFailed;
            };
        },
        .zstd => {
            scoped_log.debug("Extracting zstd-compressed tar {s}", .{layer_path});
            var zstd_buf: [std.compress.zstd.default_window_len + std.compress.zstd.block_size_max]u8 = undefined;
            var decompressor = std.compress.zstd.Decompress.init(&file_reader.interface, &zstd_buf, .{});
            extractTarToDir(dir, &decompressor.reader) catch |err| {
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

/// Strip leading slashes and ./ from a tar entry name to make it relative.
fn stripLeadingSlashes(name: []const u8) []const u8 {
    var result = name;
    while (result.len > 0 and result[0] == '/') {
        result = result[1..];
    }
    if (std.mem.startsWith(u8, result, "./")) {
        result = result[2..];
    }
    return result;
}

/// Extract tar entries to a directory, handling OCI layer quirks:
/// - Strips leading / from paths (some layers use absolute paths)
/// - Overwrites existing files (later layers override earlier ones)
/// - Creates hard links (common in alpine/busybox images)
/// - Skips unsupported entry types without failing
///
/// Uses raw tar header reading because Zig's std.tar.Iterator drops
/// hard link entries entirely (they become diagnostics errors with no
/// link target preserved).
fn extractTarToDir(dir: std.fs.Dir, reader: *std.Io.Reader) !void {
    var long_name: ?[std.fs.max_path_bytes]u8 = null;
    var long_name_len: usize = 0;
    var long_link: ?[std.fs.max_path_bytes]u8 = null;
    var long_link_len: usize = 0;

    while (true) {
        // Read 512-byte header
        var header_buf: [512]u8 = undefined;
        reader.readSliceAll(&header_buf) catch return; // EOF
        // Check for end-of-archive (two zero blocks)
        if (std.mem.allEqual(u8, &header_buf, 0)) return;

        // Parse header fields
        const kind = header_buf[156];
        const size = parseOctal(header_buf[124..136]) orelse 0;
        const mode = parseOctal(header_buf[100..108]) orelse 0o644;
        const padding = if (size % 512 != 0) 512 - (size % 512) else 0;

        // Get name: use GNU long name if set, otherwise from header
        var name_buf: [std.fs.max_path_bytes]u8 = undefined;
        var name: []const u8 = undefined;
        if (long_name != null) {
            name = long_name.?[0..long_name_len];
            long_name = null;
        } else {
            // name is at offset 0, length 100; prefix at offset 345, length 155
            const raw_name = trimNull(header_buf[0..100]);
            const prefix = trimNull(header_buf[345..500]);
            if (prefix.len > 0) {
                @memcpy(name_buf[0..prefix.len], prefix);
                name_buf[prefix.len] = '/';
                @memcpy(name_buf[prefix.len + 1 ..][0..raw_name.len], raw_name);
                name = name_buf[0 .. prefix.len + 1 + raw_name.len];
            } else {
                name = raw_name;
            }
        }

        // Get link name
        var link_name: []const u8 = undefined;
        if (long_link != null) {
            link_name = long_link.?[0..long_link_len];
            long_link = null;
        } else {
            link_name = trimNull(header_buf[157..257]);
        }

        const rel_name = stripLeadingSlashes(name);
        const rel_link = stripLeadingSlashes(link_name);

        switch (kind) {
            'L' => {
                // GNU long name - next header's name
                long_name = .{0} ** std.fs.max_path_bytes;
                const to_read: usize = @min(size, std.fs.max_path_bytes);
                reader.readSliceAll(long_name.?[0..to_read]) catch return;
                long_name_len = std.mem.indexOfScalar(u8, long_name.?[0..to_read], 0) orelse to_read;
                // Skip remaining + padding
                discardBytes(reader, size - to_read + padding);
            },
            'K' => {
                // GNU long link name
                long_link = .{0} ** std.fs.max_path_bytes;
                const to_read: usize = @min(size, std.fs.max_path_bytes);
                reader.readSliceAll(long_link.?[0..to_read]) catch return;
                long_link_len = std.mem.indexOfScalar(u8, long_link.?[0..to_read], 0) orelse to_read;
                discardBytes(reader, size - to_read + padding);
            },
            '5' => {
                // Directory
                if (rel_name.len > 0) {
                    dir.makePath(rel_name) catch {};
                }
                discardBytes(reader, size + padding);
            },
            0, '0', '7' => {
                // Regular file
                if (rel_name.len == 0) {
                    discardBytes(reader, size + padding);
                    continue;
                }
                dir.deleteFile(rel_name) catch {};
                if (std.fs.path.dirname(rel_name)) |parent| {
                    dir.makePath(parent) catch {};
                }
                if (dir.createFile(rel_name, .{ .mode = tarMode(mode) })) |fs_file| {
                    defer fs_file.close();
                    var remaining: u64 = size;
                    var buf: [32768]u8 = undefined;
                    while (remaining > 0) {
                        const to_read: usize = @intCast(@min(remaining, buf.len));
                        reader.readSliceAll(buf[0..to_read]) catch return;
                        fs_file.writeAll(buf[0..to_read]) catch break;
                        remaining -= to_read;
                    }
                    discardBytes(reader, padding);
                } else |_| {
                    discardBytes(reader, size + padding);
                }
            },
            '1' => {
                // Hard link
                if (rel_name.len > 0 and rel_link.len > 0) {
                    dir.deleteFile(rel_name) catch {};
                    if (std.fs.path.dirname(rel_name)) |parent| {
                        dir.makePath(parent) catch {};
                    }
                    // Try hard link first, fall back to copy
                    const link_z = std.posix.toPosixPath(rel_link) catch {
                        scoped_log.debug("Hard link path too long: {s}", .{rel_link});
                        discardBytes(reader, size + padding);
                        continue;
                    };
                    const name_z = std.posix.toPosixPath(rel_name) catch {
                        discardBytes(reader, size + padding);
                        continue;
                    };
                    const rc = std.os.linux.linkat(dir.fd, &link_z, dir.fd, &name_z, 0);
                    if (std.os.linux.E.init(rc) != .SUCCESS) {
                        scoped_log.debug("Hard link failed, copying: {s} -> {s}", .{ rel_name, rel_link });
                        // Fall back: copy the file
                        if (dir.openFile(rel_link, .{})) |src| {
                            defer src.close();
                            if (dir.createFile(rel_name, .{ .mode = tarMode(mode) })) |dst| {
                                defer dst.close();
                                var buf: [32768]u8 = undefined;
                                while (true) {
                                    const n = src.read(&buf) catch break;
                                    if (n == 0) break;
                                    dst.writeAll(buf[0..n]) catch break;
                                }
                            } else |_| {}
                        } else |_| {}
                    }
                }
                discardBytes(reader, size + padding);
            },
            '2' => {
                // Symbolic link
                if (rel_name.len > 0) {
                    dir.deleteFile(rel_name) catch {};
                    if (std.fs.path.dirname(rel_name)) |parent| {
                        dir.makePath(parent) catch {};
                    }
                    dir.symLink(link_name, rel_name, .{}) catch |err| {
                        scoped_log.debug("Cannot create symlink {s} -> {s}: {}", .{ rel_name, link_name, err });
                    };
                }
                discardBytes(reader, size + padding);
            },
            'x', 'g', 'X' => {
                // Extended headers (pax) - skip data
                discardBytes(reader, size + padding);
            },
            else => {
                // Unknown type - skip
                scoped_log.debug("Skipping tar entry type '{c}': {s}", .{ kind, rel_name });
                discardBytes(reader, size + padding);
            },
        }
    }
}

/// Parse an octal string from a tar header field
fn parseOctal(bytes: []const u8) ?u64 {
    const trimmed = trimNull(bytes);
    const stripped = std.mem.trim(u8, trimmed, " ");
    if (stripped.len == 0) return null;
    return std.fmt.parseInt(u64, stripped, 8) catch null;
}

/// Trim trailing null bytes and spaces
fn trimNull(bytes: []const u8) []const u8 {
    var end = bytes.len;
    while (end > 0 and (bytes[end - 1] == 0 or bytes[end - 1] == ' ')) {
        end -= 1;
    }
    return bytes[0..end];
}

/// Discard N bytes from reader
fn discardBytes(reader: *std.Io.Reader, n: u64) void {
    var remaining = n;
    var buf: [4096]u8 = undefined;
    while (remaining > 0) {
        const to_read: usize = @intCast(@min(remaining, buf.len));
        reader.readSliceAll(buf[0..to_read]) catch return;
        remaining -= to_read;
    }
}

/// Convert tar mode to filesystem mode (preserve executable bit)
fn tarMode(mode: u64) std.fs.File.Mode {
    if (!std.fs.has_executable_bit) return std.fs.File.default_mode;
    const m: u32 = @truncate(mode);
    if (m & 0o111 != 0) return 0o777;
    return 0o666;
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
