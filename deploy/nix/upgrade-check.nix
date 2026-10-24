{ pkgs, src, toolchain, package }:
let
  version = (builtins.fromTOML (builtins.readFile (src + /Cargo.toml))).workspace.package.version;
  parts = pkgs.lib.splitString "." version;
  successor = "${builtins.elemAt parts 0}.${builtins.elemAt parts 1}.${toString (pkgs.lib.toInt (builtins.elemAt parts 2) + 1)}";
  manifest = builtins.toFile "Cargo.toml" (builtins.replaceStrings
    [ "version = \"${version}\"" ] [ "version = \"${successor}\"" ]
    (builtins.readFile (src + /Cargo.toml)));
  lockText = builtins.readFile (src + /Cargo.lock);
  packages = builtins.filter (entry: pkgs.lib.hasPrefix "positron" entry.name && entry.version == version)
    (builtins.fromTOML lockText).package;
  lockFile = builtins.toFile "Cargo.lock" (builtins.replaceStrings
    (map (entry: "name = \"${entry.name}\"\nversion = \"${version}\"") packages)
    (map (entry: "name = \"${entry.name}\"\nversion = \"${successor}\"") packages)
    lockText);
  successorSource = pkgs.runCommand "positron-private-upgrade-source" { } ''
    mkdir "$out"
    cp -R ${src}/. "$out/"
    chmod -R u+w "$out"
    cp ${manifest} "$out/Cargo.toml"
    cp ${lockFile} "$out/Cargo.lock"
  '';
in {
  commit = src.rev or (builtins.substring 0 40 src.dirtyRev);
  # Private next-patch fixture, never a published product release.
  candidate = import ./package.nix {
    inherit pkgs toolchain lockFile;
    src = successorSource;
    version = successor;
  };
  fixture = package.overrideAttrs (_: {
    pname = "positron-upgrade-fixture";
    cargoBuildFlags = [ "--package" "positron" "--test" "upgrade_native_cli" ];
    doCheck = false;
    installPhase = ''
      mkdir -p "$out/bin"
      find target -type f -name 'upgrade_native_cli-*' -perm /111 \
        -exec cp '{}' "$out/bin/positron-upgrade-fixture" \;
      test -x "$out/bin/positron-upgrade-fixture"
    '';
    postInstall = "";
  });
}
