{
  description = "runz - OCI container runtime and library in Zig";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    pre-commit-hooks = {
      url = "github:cachix/git-hooks.nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    oci-spec-zig = {
      url = "github:navidys/oci-spec-zig";
      flake = false;
    };
    runtime-tools-src = {
      url = "github:opencontainers/runtime-tools/8a4db579f5c88af5a0d036fad34bddc9c1f703f3";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, flake-utils, pre-commit-hooks, oci-spec-zig, runtime-tools-src }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        version = if (self ? shortRev) then self.shortRev else "dev";

        # Zig dependency hash must match build.zig.zon
        ociSpecHash = "ocispec-0.4.0-dev-voj0cey1AgDS-1Itn3Xu5AiWtB6cwMddZtDUssOtWrIn";

        # Pre-fetch zig deps for sandboxed builds
        zigDepsDir = pkgs.runCommand "runz-deps" {} ''
          mkdir -p $out
          ln -s ${oci-spec-zig} $out/${ociSpecHash}
        '';

        # Upstream OCI runtime-tools validation suite. Builds runtimetest
        # (injected into each test bundle), oci-runtime-tool (config helper),
        # and the validation/*.t test binaries. Uses the in-tree vendor/
        # directory so the build is offline-clean inside the Nix sandbox.
        oci-runtime-tools = pkgs.stdenv.mkDerivation {
          pname = "oci-runtime-tools";
          version = "unstable-2026-03-16";
          src = runtime-tools-src;

          nativeBuildInputs = [ pkgs.go ];

          dontConfigure = true;

          buildPhase = ''
            runHook preBuild
            export HOME=$(mktemp -d)
            export GOFLAGS=-mod=vendor
            export CGO_ENABLED=0

            go build -o runtimetest ./cmd/runtimetest
            go build -o oci-runtime-tool ./cmd/oci-runtime-tool

            for dir in validation/*/; do
              name=$(basename "$dir")
              if [ -f "$dir$name.go" ]; then
                go build -o "$dir$name.t" "./$dir"
              fi
            done
            runHook postBuild
          '';

          installPhase = ''
            runHook preInstall
            mkdir -p $out/bin $out/libexec/oci-validation
            install -m755 runtimetest        $out/bin/
            install -m755 oci-runtime-tool   $out/bin/
            for t in validation/*/*.t; do
              install -m755 "$t" "$out/libexec/oci-validation/"
            done
            runHook postInstall
          '';
        };

        pre-commit-check = pre-commit-hooks.lib.${system}.run {
          src = ./.;
          hooks = {
            zig-fmt = {
              enable = true;
              name = "zig fmt";
              entry = "${pkgs.zig}/bin/zig fmt";
              files = "\\.zig$";
              pass_filenames = false;
              args = [ "--check" "src/" ];
            };

            trailing-whitespace = {
              enable = true;
              name = "trailing whitespace";
              entry = "${pkgs.python3}/bin/python3 -c \"
import sys, pathlib
ok = True
for f in pathlib.Path('.').rglob('*.zig'):
    for i, line in enumerate(f.read_text().splitlines(), 1):
        if line != line.rstrip():
            print(f'{f}:{i}: trailing whitespace')
            ok = False
sys.exit(0 if ok else 1)
\"";
              files = "\\.zig$";
              pass_filenames = false;
            };
          };
        };

        zigBuildArgs = "--system ${zigDepsDir}";

      in
      {
        packages.default = pkgs.stdenv.mkDerivation {
          pname = "runz";
          inherit version;
          src = ./.;

          nativeBuildInputs = [ pkgs.zig ];
          dontConfigure = true;

          buildPhase = ''
            export ZIG_GLOBAL_CACHE_DIR=$(mktemp -d)
            zig build -Doptimize=ReleaseSafe ${zigBuildArgs}
          '';

          installPhase = ''
            mkdir -p $out/bin
            cp zig-out/bin/runz $out/bin/
          '';
        };

        checks = {
          inherit pre-commit-check;

          test = pkgs.stdenv.mkDerivation {
            pname = "runz-test";
            inherit version;
            src = ./.;

            nativeBuildInputs = [ pkgs.zig ];
            dontConfigure = true;
            dontInstall = true;

            buildPhase = ''
              export ZIG_GLOBAL_CACHE_DIR=$(mktemp -d)
              zig build test ${zigBuildArgs}
              touch $out
            '';
          };

          fuzz = pkgs.stdenv.mkDerivation {
            pname = "runz-fuzz";
            inherit version;
            src = ./.;

            nativeBuildInputs = [ pkgs.zig ];
            dontConfigure = true;
            dontInstall = true;

            buildPhase = ''
              export ZIG_GLOBAL_CACHE_DIR=$(mktemp -d)
              zig build fuzz ${zigBuildArgs}
              touch $out
            '';
          };

          fmt = pkgs.stdenv.mkDerivation {
            pname = "runz-fmt";
            inherit version;
            src = ./.;

            nativeBuildInputs = [ pkgs.zig ];
            dontConfigure = true;
            dontInstall = true;

            buildPhase = ''
              export ZIG_GLOBAL_CACHE_DIR=$(mktemp -d)
              zig fmt --check src/
              touch $out
            '';
          };

          build = pkgs.stdenv.mkDerivation {
            pname = "runz-build";
            inherit version;
            src = ./.;

            nativeBuildInputs = [ pkgs.zig ];
            dontConfigure = true;
            dontInstall = true;

            buildPhase = ''
              export ZIG_GLOBAL_CACHE_DIR=$(mktemp -d)
              zig build ${zigBuildArgs}
              touch $out
            '';
          };

          test-integration = pkgs.stdenv.mkDerivation {
            pname = "runz-test-integration";
            inherit version;
            src = ./.;

            nativeBuildInputs = [ pkgs.zig ];
            dontConfigure = true;
            dontInstall = true;

            buildPhase = ''
              export ZIG_GLOBAL_CACHE_DIR=$(mktemp -d)
              zig build test-integration ${zigBuildArgs}
              touch $out
            '';
          };

          test-cli = pkgs.stdenv.mkDerivation {
            pname = "runz-test-cli";
            inherit version;
            src = ./.;

            nativeBuildInputs = [ pkgs.zig ];
            dontConfigure = true;
            dontInstall = true;

            buildPhase = ''
              export ZIG_GLOBAL_CACHE_DIR=$(mktemp -d)
              zig build test-cli ${zigBuildArgs}
              touch $out
            '';
          };
        };

        devShells.default = pkgs.mkShell {
          inherit (pre-commit-check) shellHook;

          buildInputs = with pkgs; [
            zig
            zls
            valgrind
            skopeo
            podman
            jq
            nodejs_22
            python3
            python3Packages.mkdocs-material
            oci-runtime-tools
          ];

          # Consumed by scripts/oci-validation.sh (invoked by
          # `zig build test-oci-validation`).
          OCI_VALIDATION_DIR = "${oci-runtime-tools}/libexec/oci-validation";
          OCI_RUNTIMETEST   = "${oci-runtime-tools}/bin/runtimetest";
        };
      }
    ) // {
      # Layer 3: NixOS VM integration tests
      # Run with: nix flake check (requires Linux with KVM)
      checks.x86_64-linux = let
        pkgs = nixpkgs.legacyPackages.x86_64-linux;

      in (pkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
        # NixOS VM tests that don't require network access go here.
        # Network-dependent tests (skopeo/podman image pulls) must be run
        # outside the nix sandbox: nix build .#checks.x86_64-linux.skopeo-compat --no-sandbox
      });
    };
}
