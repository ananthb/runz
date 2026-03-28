//! OCI library - container image operations for Zig
//!
//! Provides OCI spec types, registry client, image building,
//! Containerfile parsing, and layout reading/writing.

/// OCI spec types (image, runtime, distribution)
pub const spec = @import("ocispec");

/// OCI image reference parsing and types
pub const image = @import("image.zig");

/// Registry HTTP client (pull, auth, platform resolution)
pub const registry = @import("registry.zig");

/// Registry authentication (token fetching, WWW-Authenticate parsing)
pub const auth = @import("auth.zig");

/// Layer extraction and whiteout handling
pub const layer = @import("layer.zig");

/// Blob caching
pub const cache = @import("cache.zig");

/// OCI image layout writer
pub const layout_writer = @import("layout_writer.zig");

/// Containerfile/Dockerfile parser
pub const containerfile = @import("containerfile.zig");

/// Container command execution (RUN support via chroot)
pub const run = @import("run.zig");

/// Linux-specific utilities (namespaces, mounts, seccomp, device setup)
pub const linux_util = @import("linux.zig");
