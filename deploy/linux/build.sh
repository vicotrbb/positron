#!/bin/sh
# Build-only native packaging. Input is an independently verified native archive.
set -eu
if [ "$#" != 5 ]; then
    echo 'usage: build.sh deb|rpm VERIFIED_ARCHIVE VERSION x86_64|aarch64 NEW_OUTPUT_DIRECTORY' >&2
    exit 2
fi
kind=$1 archive=$(realpath "$2") version=$3 arch=$4 output=$5
printf '%s\n' "$version" | grep -Eq '^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || { echo 'invalid version' >&2; exit 2; }
case "$arch" in x86_64) debarch=amd64 machine='Advanced Micro Devices X86-64';; aarch64) debarch=arm64 machine=AArch64;; *) exit 2;; esac
case "$kind" in deb|rpm) ;; *) exit 2;; esac
recipe=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
mkdir -m 700 -- "$output"
output=$(realpath "$output")
work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT HUP INT TERM
tar -xzf "$archive" -C "$work"
payload=$work/positron
readelf -h "$payload/bin/positron" | grep -F "Machine:                           $machine" >/dev/null
# All package targets share the RHEL 9 GNU libc floor. Refuse a newer build.
ceiling=$(objdump -T "$payload/bin/positron" | sed -n 's/.*(GLIBC_\([0-9.]*\)).*/\1/p' | sort -V | tail -n 1)
[ -n "$ceiling" ]
[ "$(printf '%s\n' "$ceiling" 2.34 | sort -V | tail -n 1)" = 2.34 ] || { echo 'executable requires GNU libc newer than 2.34' >&2; exit 2; }
for library in $(readelf -d "$payload/bin/positron" | sed -n 's/.*(NEEDED).*\[\([^]]*\)\].*/\1/p'); do
    case "$library" in
        libc.so.6|libgcc_s.so.1|libm.so.6|libpthread.so.0|libdl.so.2|librt.so.1|ld-linux-x86-64.so.2|ld-linux-aarch64.so.1) ;;
        *) echo "undeclared runtime library: $library" >&2; exit 2;;
    esac
done
export SOURCE_DATE_EPOCH=0
if [ "$kind" = rpm ]; then
    mkdir -p "$work/rpm/SOURCES" "$work/rpm/SPECS"
    cp "$archive" "$work/rpm/SOURCES/native.tar.gz"
    cp "$recipe/positron.service" "$work/rpm/SOURCES/positron.service"
    cp "$recipe/README.md" "$work/rpm/SOURCES/linux-packages.md"
    rpmbuild -bb --target "$arch" --define "_topdir $work/rpm" --define "positron_version $version" "$recipe/positron.spec"
    cp "$work/rpm/RPMS/$arch/positron-$version-1.$arch.rpm" "$output/"
else
    root=$work/root
    install -d "$root/DEBIAN" "$root/usr/bin" "$root/usr/lib/systemd/system" "$root/usr/share/positron" "$root/usr/share/doc/positron" "$root/etc/positron"
    cp "$payload/bin/positron" "$root/usr/bin/positron"
    cp "$payload/etc/positron.toml.example" "$root/etc/positron/positron.toml"
    cp "$payload/share/config.schema.json" "$payload/share/configuration.md" "$root/usr/share/positron/"
    cp -R "$payload/docs/operations" "$root/usr/share/doc/positron/"
    cp "$payload/LICENSE" "$root/usr/share/doc/positron/copyright"
    cp "$recipe/README.md" "$root/usr/share/doc/positron/"
    cp "$recipe/positron.service" "$root/usr/lib/systemd/system/"
    sed -e "s/@VERSION@/$version/g" -e "s/@ARCH@/$debarch/g" "$recipe/debian/control" > "$root/DEBIAN/control"
    cp "$recipe/debian/postinst" "$recipe/debian/prerm" "$recipe/debian/postrm" "$root/DEBIAN/"
    printf '/etc/positron/positron.toml\n' > "$root/DEBIAN/conffiles"
    chmod 0755 "$root/DEBIAN/postinst" "$root/DEBIAN/prerm" "$root/DEBIAN/postrm" "$root/usr/bin/positron"
    chmod 0750 "$root/etc/positron"
    chmod 0640 "$root/etc/positron/positron.toml"
    find "$root" -print0 | xargs -0 touch -h -d @0
    dpkg-deb --root-owner-group --uniform-compression -Zgzip -z9 --build "$root" "$output/positron_${version}_${debarch}.deb"
fi
