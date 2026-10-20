Name: positron
Version: %{positron_version}
Release: 1
Summary: Standalone observability database
License: MIT
URL: https://github.com/vicotrbb/positron
Source0: native.tar.gz
Source1: positron.service
Source2: linux-packages.md
ExclusiveArch: x86_64 aarch64
Requires: glibc >= 2.34, glibc-common, libgcc, coreutils, ca-certificates, systemd, util-linux
Requires(pre): shadow-utils
AutoReqProv: no
# Preserve the exact executable already covered by native Release Trust.
%global debug_package %{nil}
%global __os_install_post %{nil}
%global _build_id_links none
%global _binary_payload w9.gzdio
%global use_source_date_epoch_as_buildtime 1
%global clamp_mtime_to_source_date_epoch 1
%global _buildhost positron-builder

%description
Same Positron executable and generated Configuration Contract as native archives.

%prep
%setup -q -c -T
 tar -xzf %{SOURCE0}

%build

%install
install -D -m 0755 positron/bin/positron %{buildroot}/usr/bin/positron
install -D -m 0644 %{SOURCE1} %{buildroot}/usr/lib/systemd/system/positron.service
install -d -m 0750 %{buildroot}/etc/positron
install -m 0640 positron/etc/positron.toml.example %{buildroot}/etc/positron/positron.toml
install -d %{buildroot}/usr/share/positron %{buildroot}/usr/share/doc/positron
cp positron/share/config.schema.json positron/share/configuration.md %{buildroot}/usr/share/positron/
cp -R positron/docs/operations %{buildroot}/usr/share/doc/positron/
cp positron/LICENSE %{SOURCE2} %{buildroot}/usr/share/doc/positron/
find %{buildroot} -print0 | xargs -0 touch -h -d @0

%pre
set -eu
if ! getent group positron >/dev/null; then groupadd --system positron; fi
if ! getent passwd positron >/dev/null; then
    useradd --system --gid positron --home-dir /var/lib/positron --no-create-home --shell /sbin/nologin positron
fi
if [ "$(id -u positron)" -eq 0 ] || [ "$(id -g positron)" -eq 0 ] ||
   [ "$(id -gn positron)" != positron ] || [ "$(id -G positron)" != "$(id -g positron)" ]; then
    echo 'Positron requires a dedicated non-root service identity.' >&2
    exit 1
fi
uid=$(id -u positron) gid=$(id -g positron)
accounts=$(getent passwd)
printf '%s\n' "$accounts" | while IFS=: read -r name password account_uid account_gid rest; do
    if [ "$name" != positron ] && { [ "$account_uid" = "$uid" ] || [ "$account_gid" = "$gid" ]; }; then
        echo 'Positron service UID and primary group must not be shared.' >&2
        exit 1
    fi
done || exit 1
group=$(getent group positron)
case "${group##*:}" in
    ''|positron) ;;
    *) echo 'Positron service group must not contain other accounts.' >&2; exit 1;;
esac
case "$(getent passwd positron)" in
    *:/usr/sbin/nologin|*:/sbin/nologin|*:/usr/bin/false|*:/bin/false) ;;
    *) echo 'Positron service identity must have a non-login shell.' >&2; exit 1;;
esac
if [ -d /run/systemd/system ] && systemctl is-active --quiet positron.service; then
    echo 'Stop Positron after its explicit verified Upgrade workflow before replacing this package.' >&2
    exit 1
fi

%post
set -eu
install -d -o positron -g positron -m 0700 /var/lib/positron /var/lib/positron-secrets
if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi

%preun
set -eu
if [ "$1" -eq 0 ] && [ -d /run/systemd/system ]; then
    systemctl stop positron.service
    systemctl disable positron.service
fi

%postun
set -eu
if [ -d /run/systemd/system ]; then systemctl daemon-reload; fi

%files
%attr(0755,root,root) /usr/bin/positron
%attr(0644,root,root) /usr/lib/systemd/system/positron.service
%dir %attr(0750,root,positron) /etc/positron
%config(noreplace) %attr(0640,root,positron) /etc/positron/positron.toml
/usr/share/positron
%dir /usr/share/doc/positron
%license /usr/share/doc/positron/LICENSE
/usr/share/doc/positron/linux-packages.md
/usr/share/doc/positron/operations
