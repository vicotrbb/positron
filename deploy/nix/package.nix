{ pkgs, src, toolchain }:
let
  manifest = builtins.fromTOML (builtins.readFile (src + /Cargo.toml));
  target = {
    x86_64-linux = "linux-x86_64";
    aarch64-linux = "linux-aarch64";
    x86_64-darwin = "macos-x86_64";
    aarch64-darwin = "macos-aarch64";
  }.${pkgs.stdenv.hostPlatform.system};
in
(pkgs.makeRustPlatform { cargo = toolchain; rustc = toolchain; }).buildRustPackage {
  pname = "positron";
  version = manifest.workspace.package.version;
  inherit src;
  cargoLock.lockFile = src + /Cargo.lock;
  cargoBuildFlags = [ "--package" "positron" ];
  preBuild = ''
    export CFLAGS="''${CFLAGS:-} -fdebug-prefix-map=$PWD=/positron-source"
    export RUSTFLAGS="''${RUSTFLAGS:-} --remap-path-prefix=$PWD=/positron-source ${pkgs.lib.optionalString pkgs.stdenv.isDarwin "-C link-arg=-Wl,-reproducible"}"
  '';
  # These public contracts run within the sandbox without host service access.
  checkPhase = ''
    runHook preCheck
    cargo test --frozen --release --jobs "$NIX_BUILD_CORES" -p positron-config -p positron-release --tests
    runHook postCheck
  '';
  nativeBuildInputs = [ pkgs.cmake pkgs.pkg-config ];
  env = pkgs.lib.optionalAttrs pkgs.stdenv.isDarwin {
    MACOSX_DEPLOYMENT_TARGET = "15.0";
  };
  # Preserve the compiler's executable bytes and signatures after linking.
  dontStrip = true;
  dontPatchELF = true;
  postInstall = ''
    "$out/bin/positron" release archive --target ${target} \
      --binary "$out/bin/positron" --out native.tar.gz
    mkdir archive
    tar -xzf native.tar.gz -C archive
    mkdir -p "$out/share/positron" "$out/share/doc/positron"
    cp archive/positron/etc/positron.toml.example "$out/share/positron/"
    cp archive/positron/share/* "$out/share/positron/"
    cp -R archive/positron/docs/operations "$out/share/doc/positron/"
    cp archive/positron/LICENSE "$out/share/doc/positron/"
    cp ${./README.md} "$out/share/doc/positron/nix.md"
  '';
  meta = {
    description = "Standalone observability database";
    license = pkgs.lib.licenses.mit;
    mainProgram = "positron";
    platforms = [ "x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin" ];
  };
}
