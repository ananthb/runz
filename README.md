# oci-zig

OCI container library for Zig. Provides types, registry client, image building, and Containerfile parsing.

## Modules

- **spec** - OCI specification types (image, runtime, distribution)
- **registry** - HTTP registry client with authentication and multi-platform resolution
- **auth** - Registry authentication
- **layer** - Tar layer extraction with gzip/zstd decompression and OCI whiteout handling
- **cache** - Content-addressable blob caching
- **layout_writer** - OCI image layout writer
- **containerfile** - Containerfile/Dockerfile parser
- **image** - Image reference parsing

## Usage

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .oci = .{
        .url = "git+https://github.com/ananthb/oci-zig",
        .hash = "...",
    },
},
```

In `build.zig`:

```zig
const oci_dep = b.dependency("oci", .{});
exe.root_module.addImport("oci", oci_dep.module("oci"));
```

In your code:

```zig
const oci = @import("oci");

// Parse an image reference
var ref = try oci.image.ImageReference.parse("alpine:latest", allocator);

// Pull from a registry
var client = oci.registry.RegistryClient.init(allocator, "registry-1.docker.io");
defer client.deinit();
try client.ensureAuth("library/alpine");
const manifest = try client.fetchManifest("library/alpine", "latest", null);

// Parse a Containerfile
const cf = try oci.containerfile.Containerfile.parse(allocator, dockerfile_content);
defer cf.deinit(allocator);

// Write an OCI image layout
const digest = try oci.layout_writer.writeOciLayout(allocator, rootfs_dir, output_dir, image_config);
```

## Development

```sh
nix develop    # enter devshell (zig, zls, pre-commit hooks)
zig build test # run tests
nix flake check # run all CI checks (test, fmt, build, pre-commit)
```

## License

Licensed under the terms of the [AGPL-3.0](./LICENSE).

OCI specification [code](src/spec) borrowed from [oci-spec-zig](https://github.com/navidys/oci-spec-zig)
distributed under the terms of the MIT license and terms of the AGPL.
