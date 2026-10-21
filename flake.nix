{
  description = "Positron standalone database";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/cd4ea8d57de16f4810bc5f14207bac45fbf19f67";
  inputs.rust-overlay = {
    url = "github:oxalica/rust-overlay/83dd732f2428827f35d997deae108a2ced5125f4";
    inputs.nixpkgs.follows = "nixpkgs";
  };

  outputs = { self, nixpkgs, rust-overlay }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
      eachSystem = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: import nixpkgs {
        inherit system;
        overlays = [ rust-overlay.overlays.default ];
      };
      toolchainFor = system: (pkgsFor system).rust-bin.fromRustupToolchainFile ./rust-toolchain.toml;
      shellToolchainFor = system: (toolchainFor system).override {
        extensions = (builtins.fromTOML (builtins.readFile ./rust-toolchain.toml)).toolchain.components
          ++ [ "llvm-tools-preview" ];
      };
      packageFor = system: import ./deploy/nix/package.nix {
        pkgs = pkgsFor system;
        toolchain = toolchainFor system;
        src = self;
      };
    in {
      packages = eachSystem (system: rec {
        positron = packageFor system;
        default = positron;
      });
      devShells = eachSystem (system:
        let pkgs = pkgsFor system; in {
          default = pkgs.mkShell {
            inputsFrom = [ self.packages.${system}.positron ];
            packages = with pkgs; [ (shellToolchainFor system) cargo-llvm-cov cargo-fuzz ];
          };
        });
      checks = eachSystem (system:
        let pkgs = pkgsFor system; in {
          package = self.packages.${system}.positron;
          configuration = pkgs.runCommand "positron-configuration-parity" { } ''
            ${self.packages.${system}.positron}/bin/positron config validate \
              --config ${self.packages.${system}.positron}/share/positron/positron.toml.example
            touch "$out"
          '';
        } // nixpkgs.lib.optionalAttrs pkgs.stdenv.isLinux {
          service = let upgrade = import ./deploy/nix/upgrade-check.nix {
            inherit pkgs;
            src = self;
            toolchain = toolchainFor system;
            package = self.packages.${system}.positron;
          }; in import ./deploy/nix/test.nix {
            inherit pkgs;
            inherit (upgrade) candidate fixture commit;
            package = self.packages.${system}.positron;
            module = self.nixosModules.default;
          };
        });
      nixosModules.default = import ./deploy/nix/module.nix self;
    };
}
