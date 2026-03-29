//! # runz - OCI Container Runtime & Library
//!
//! A high-performance, daemonless OCI container runtime and library written in Zig.
//!
//! ## Technical Specifications
//! - **OCI Standards**: Implements the OCI runtime and image specifications.
//! - **Zig Implementation**: predictable performance and memory safety.
//! - **Daemonless**: Executes containers without a background process.
//! - **Library & CLI**: Provides a standalone binary and a Zig module for integration.
//!
//! ## Installation
//!
//! ### Prerequisites
//! - Zig 0.13.0 or later
//! - Linux (for runtime features)
//!
//! ### Using as a Library
//! Add `runz` to your `build.zig.zon`:
//! ```zig
//! .dependencies = .{
//!     .runz = .{
//!         .url = "git+https://github.com/ananthb/runz",
//!         .hash = "...",
//!     },
//! },
//! ```
//!
//! ## Basic Usage
//!
//! ### Pulling an Image
//! ```zig
//! const std = @import("std");
//! const runz = @import("runz");
//!
//! pub fn main() !void {
//!     var gpa = std.heap.GeneralPurposeAllocator(.{}){};
//!     const allocator = gpa.allocator();
//!     defer _ = gpa.deinit();
//!
//!     var client = try runz.registry.RegistryClient.init(allocator, "registry-1.docker.io");
//!     defer client.deinit();
//!
//!     try client.ensureAuth("library/alpine");
//!     const manifest = try client.fetchManifest("library/alpine", "latest", null);
//! }
//! ```

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

/// Container lifecycle management (create, start, kill, delete)
pub const container = @import("container.zig");

/// OCI Runtime Spec (config.json parsing)
pub const runtime_spec = @import("runtime_spec.zig");

/// OCI lifecycle hooks
pub const hooks = @import("hooks.zig");

/// Daemonless container runner (like podman run)
pub const runz = @import("runz.zig");

/// Run a container from an OCI runtime spec bundle
pub const spec_run = @import("spec_run.zig");

/// OCI container lifecycle (create/start FIFO split)
pub const lifecycle = @import("lifecycle.zig");

/// Process OCI spec mounts
pub const spec_mount = @import("spec_mount.zig");

/// Execute processes inside running containers (nsenter)
pub const exec = @import("exec.zig");

/// Logging (set log level, colors)
pub const log = @import("log.zig");

/// OCI annotations support
pub const annotations = @import("annotations.zig");

/// Linux-specific utilities (namespaces, mounts, seccomp, cgroups, capabilities)
pub const linux_util = @import("linux.zig");
