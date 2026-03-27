const std = @import("std");
const builtin = @import("builtin");
const ocispec = @import("ocispec");
const log = @import("log.zig");
const oci_registry = @import("registry.zig");

/// Container image configuration (entrypoint, cmd, env, working directory)
pub const ImageConfig = struct {
    entrypoint: ?[]const []const u8 = null,
    cmd: ?[]const []const u8 = null,
    env: ?[]const []const u8 = null,
    working_dir: ?[]const u8 = null,
};

const scoped_log = log.scoped("oci/layout_writer");

pub const OciDigest = struct {
    manifest_digest: [64]u8, // hex sha256 of manifest
    manifest_size: u64,
};

/// Map our platform arch string to ocispec Arch enum
fn mapArch(arch_str: []const u8) ocispec.image.Arch {
    if (std.mem.eql(u8, arch_str, "amd64")) return .Amd64;
    if (std.mem.eql(u8, arch_str, "arm64")) return .ARM64;
    if (std.mem.eql(u8, arch_str, "arm")) return .ARM;
    return .Amd64; // default
}

/// Write an OCI image layout from a rootfs directory.
/// Returns the manifest sha256 digest (hex) and size.
pub fn writeOciLayout(
    allocator: std.mem.Allocator,
    rootfs_dir: []const u8,
    output_dir: []const u8,
    image_config: ?ImageConfig,
) !OciDigest {
    // 1. Create output directories
    std.fs.deleteTreeAbsolute(output_dir) catch {};
    std.fs.makeDirAbsolute(output_dir) catch return error.IoError;
    {
        var dir = std.fs.openDirAbsolute(output_dir, .{}) catch return error.IoError;
        defer dir.close();
        dir.makePath("blobs/sha256") catch return error.IoError;
    }

    // 2. Create tar layer from rootfs (uncompressed — no gzip dependency)
    const tmp_dir = std.posix.getenv("TMPDIR") orelse "/tmp";
    const tmp_tar = try std.fmt.allocPrint(allocator, "{s}/oci-layer-{x}.tar", .{ tmp_dir, @as(u64, @truncate(@as(u128, @bitCast(std.time.nanoTimestamp())))) });
    defer allocator.free(tmp_tar);
    defer std.fs.deleteFileAbsolute(tmp_tar) catch {};

    try createTarFromDir(rootfs_dir, tmp_tar, allocator);

    // 3. Compute sha256 of layer, get size, copy to blobs
    const layer_hash_hex = try hashFile(tmp_tar);
    const layer_size = blk: {
        const file = try std.fs.openFileAbsolute(tmp_tar, .{});
        defer file.close();
        const stat = try file.stat();
        break :blk stat.size;
    };

    const layer_blob_path = try std.fmt.allocPrint(allocator, "{s}/blobs/sha256/{s}", .{ output_dir, &layer_hash_hex });
    defer allocator.free(layer_blob_path);

    try copyFile(tmp_tar, layer_blob_path);

    // diffID = layer hash (same since uncompressed)
    const diff_id_hex = layer_hash_hex;

    // 4. Build OCI image config JSON using ocispec types
    const arch_str = oci_registry.getPlatformArch() orelse "amd64";
    const arch = mapArch(arch_str);

    // Build the diff_id string "sha256:<hex>"
    const diff_id_str = try std.fmt.allocPrint(allocator, "sha256:{s}", .{&diff_id_hex});
    defer allocator.free(diff_id_str);

    var diff_ids_array = [_][]const u8{diff_id_str};

    // Build ocispec config object
    var oci_config: ?ocispec.image.Config = null;
    if (image_config) |cfg| {
        oci_config = ocispec.image.Config{
            .Entrypoint = if (cfg.entrypoint) |ep| @constCast(ep) else null,
            .Cmd = if (cfg.cmd) |cmd| @constCast(cmd) else null,
            .Env = if (cfg.env) |env| @constCast(env) else null,
            .WorkingDir = cfg.working_dir,
        };
    }

    const img_config = ocispec.image.Configuration{
        .created = "1970-01-01T00:00:00Z",
        .architecture = arch,
        .os = .Linux,
        .config = oci_config,
        .rootfs = .{
            .type = "layers",
            .diff_ids = &diff_ids_array,
        },
    };

    const config_json = try img_config.toString(allocator);
    defer allocator.free(config_json);

    const config_hash_hex = hashBytes(config_json);
    const config_size = config_json.len;

    const config_blob_path = try std.fmt.allocPrint(allocator, "{s}/blobs/sha256/{s}", .{ output_dir, &config_hash_hex });
    defer allocator.free(config_blob_path);

    try writeFileBytes(config_blob_path, config_json);

    // 5. Build OCI manifest JSON using ocispec types
    const layer_digest_str = try std.fmt.allocPrint(allocator, "sha256:{s}", .{&layer_hash_hex});
    defer allocator.free(layer_digest_str);

    const config_digest_str = try std.fmt.allocPrint(allocator, "sha256:{s}", .{&config_hash_hex});
    defer allocator.free(config_digest_str);

    var layers_array = [_]ocispec.image.Descriptor{.{
        .mediaType = .ImageLayer,
        .digest = try ocispec.image.Digest.initFromString(allocator, layer_digest_str),
        .size = layer_size,
    }};

    const manifest = ocispec.image.Manifest{
        .mediaType = .ImageManifest,
        .config = .{
            .mediaType = .ImageConfig,
            .digest = try ocispec.image.Digest.initFromString(allocator, config_digest_str),
            .size = config_size,
        },
        .layers = &layers_array,
    };

    const manifest_json = try manifest.toString(allocator);
    defer allocator.free(manifest_json);

    const manifest_hash_hex = hashBytes(manifest_json);
    const manifest_size = manifest_json.len;

    const manifest_blob_path = try std.fmt.allocPrint(allocator, "{s}/blobs/sha256/{s}", .{ output_dir, &manifest_hash_hex });
    defer allocator.free(manifest_blob_path);

    try writeFileBytes(manifest_blob_path, manifest_json);

    // 6. Write oci-layout file using ocispec types
    const oci_layout = ocispec.image.OciLayout{};
    const oci_layout_json = try oci_layout.toString(allocator);
    defer allocator.free(oci_layout_json);

    const oci_layout_path = try std.fmt.allocPrint(allocator, "{s}/oci-layout", .{output_dir});
    defer allocator.free(oci_layout_path);

    try writeFileBytes(oci_layout_path, oci_layout_json);

    // 7. Write index.json using ocispec types
    const manifest_digest_str = try std.fmt.allocPrint(allocator, "sha256:{s}", .{&manifest_hash_hex});
    defer allocator.free(manifest_digest_str);

    var manifests_array = [_]ocispec.image.Descriptor{.{
        .mediaType = .ImageManifest,
        .digest = try ocispec.image.Digest.initFromString(allocator, manifest_digest_str),
        .size = manifest_size,
    }};

    const index = ocispec.image.Index{
        .mediaType = .ImageIndex,
        .manifests = &manifests_array,
    };

    const index_json = try index.toString(allocator);
    defer allocator.free(index_json);

    const index_path = try std.fmt.allocPrint(allocator, "{s}/index.json", .{output_dir});
    defer allocator.free(index_path);

    try writeFileBytes(index_path, index_json);

    // 8. Return manifest digest
    return OciDigest{
        .manifest_digest = manifest_hash_hex,
        .manifest_size = manifest_size,
    };
}

pub fn buildConfigJson(
    allocator: std.mem.Allocator,
    arch: []const u8,
    diff_id_hex: []const u8,
    image_config: ?ImageConfig,
) ![]const u8 {
    // Build the "config" object contents
    var config_parts: std.ArrayListUnmanaged([]const u8) = .{};
    defer {
        for (config_parts.items) |p| allocator.free(p);
        config_parts.deinit(allocator);
    }

    if (image_config) |cfg| {
        if (cfg.entrypoint) |ep| {
            const arr = try buildJsonStringArray(allocator, ep);
            defer allocator.free(arr);
            const part = try std.fmt.allocPrint(allocator, "\"Entrypoint\":{s}", .{arr});
            try config_parts.append(allocator, part);
        }

        if (cfg.cmd) |cmd| {
            const arr = try buildJsonStringArray(allocator, cmd);
            defer allocator.free(arr);
            const part = try std.fmt.allocPrint(allocator, "\"Cmd\":{s}", .{arr});
            try config_parts.append(allocator, part);
        }

        if (cfg.env) |env| {
            const arr = try buildJsonStringArray(allocator, env);
            defer allocator.free(arr);
            const part = try std.fmt.allocPrint(allocator, "\"Env\":{s}", .{arr});
            try config_parts.append(allocator, part);
        }

        if (cfg.working_dir) |wd| {
            const part = try std.fmt.allocPrint(allocator, "\"WorkingDir\":\"{s}\"", .{wd});
            try config_parts.append(allocator, part);
        }
    }

    // Join config parts with commas
    var config_inner: []const u8 = "";
    var config_inner_allocated = false;
    defer if (config_inner_allocated) allocator.free(config_inner);

    if (config_parts.items.len > 0) {
        config_inner = try std.mem.join(allocator, ",", config_parts.items);
        config_inner_allocated = true;
    }

    return try std.fmt.allocPrint(allocator,
        \\{{"architecture":"{s}","os":"linux","config":{{{s}}},"rootfs":{{"type":"layers","diff_ids":["sha256:{s}"]}}}}
    , .{ arch, config_inner, diff_id_hex });
}

pub fn buildJsonStringArray(allocator: std.mem.Allocator, items: []const []const u8) ![]const u8 {
    var parts: std.ArrayListUnmanaged([]const u8) = .{};
    defer {
        for (parts.items) |p| allocator.free(p);
        parts.deinit(allocator);
    }

    for (items) |item| {
        const quoted = try std.fmt.allocPrint(allocator, "\"{s}\"", .{item});
        try parts.append(allocator, quoted);
    }

    // Join with commas and wrap in brackets
    const joined = try std.mem.join(allocator, ",", parts.items);
    defer allocator.free(joined);
    return try std.fmt.allocPrint(allocator, "[{s}]", .{joined});
}

/// Create an uncompressed tar archive from a directory using std.tar.Writer.
/// Replaces the external `tar cf` shell-out.
pub fn createTarFromDir(rootfs_dir: []const u8, output_path: []const u8, allocator: std.mem.Allocator) !void {
    // Open the source directory
    var source_dir = try std.fs.openDirAbsolute(rootfs_dir, .{ .iterate = true });
    defer source_dir.close();

    // Create the output tar file
    const out_dir_path = std.fs.path.dirname(output_path) orelse "/";
    var out_dir = try std.fs.openDirAbsolute(out_dir_path, .{});
    defer out_dir.close();
    var out_file = try out_dir.createFile(std.fs.path.basename(output_path), .{});
    defer out_file.close();

    var write_buf: [32768]u8 = undefined;
    var file_writer = out_file.writer(&write_buf);

    var tar_writer: std.tar.Writer = .{ .underlying_writer = &file_writer.interface };

    // Walk the source directory recursively and add entries
    var walker = try source_dir.walk(allocator);
    defer walker.deinit();
    while (try walker.next()) |entry| {
        switch (entry.kind) {
            .directory => {
                try tar_writer.writeDir(entry.path, .{});
            },
            .file => {
                const file = try entry.dir.openFile(entry.basename, .{});
                defer file.close();
                const stat = try file.stat();
                var file_read_buf: [32768]u8 = undefined;
                var reader = file.reader(&file_read_buf);
                try tar_writer.writeFile(entry.path, &reader, stat.mtime);
            },
            .sym_link => {
                var link_buf: [std.fs.max_path_bytes]u8 = undefined;
                const link_name = try source_dir.readLink(entry.path, &link_buf);
                try tar_writer.writeLink(entry.path, link_name, .{});
            },
            else => {},
        }
    }

    try tar_writer.finishPedantically();
    try file_writer.interface.flush();
}

/// Compute sha256 hex of a file on disk
fn hashFile(path: []const u8) ![64]u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var buf: [32768]u8 = undefined;
    while (true) {
        const n = try file.readAll(&buf);
        if (n == 0) break;
        hasher.update(buf[0..n]);
        if (n < buf.len) break;
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

/// Compute sha256 hex of in-memory bytes
pub fn hashBytes(data: []const u8) [64]u8 {
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    hasher.update(data);
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return std.fmt.bytesToHex(digest, .lower);
}

/// Copy a file from src to dst
fn copyFile(src: []const u8, dst: []const u8) !void {
    const src_file = try std.fs.openFileAbsolute(src, .{});
    defer src_file.close();

    const dir_path = std.fs.path.dirname(dst) orelse "/";
    var dir = try std.fs.openDirAbsolute(dir_path, .{});
    defer dir.close();

    var dst_file = try dir.createFile(std.fs.path.basename(dst), .{});
    defer dst_file.close();

    var buf: [32768]u8 = undefined;
    while (true) {
        const n = try src_file.readAll(&buf);
        if (n == 0) break;
        try dst_file.writeAll(buf[0..n]);
        if (n < buf.len) break;
    }
}

/// Write bytes to a file path
fn writeFileBytes(path: []const u8, data: []const u8) !void {
    const dir_path = std.fs.path.dirname(path) orelse "/";
    var dir = try std.fs.openDirAbsolute(dir_path, .{});
    defer dir.close();

    var file = try dir.createFile(std.fs.path.basename(path), .{});
    defer file.close();
    try file.writeAll(data);
}

test "hashBytes produces correct length" {
    const hex = hashBytes("hello world");
    const testing = std.testing;
    try testing.expectEqual(@as(usize, 64), hex.len);
}

test "buildJsonStringArray" {
    const testing = std.testing;
    const items = &[_][]const u8{ "hello", "world" };
    const result = try buildJsonStringArray(testing.allocator, items);
    defer testing.allocator.free(result);
    try testing.expectEqualStrings("[\"hello\",\"world\"]", result);
}
