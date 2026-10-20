# One GNU executable per architecture for the native archive and both packages.
FROM rust:1.96-bookworm@sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663 AS rust
RUN rustup toolchain install 1.96.0 --profile minimal --component clippy,rustfmt && rustup default 1.96.0 && rustup toolchain uninstall 1.96.1
FROM rockylinux/rockylinux:9.6@sha256:91bbb8eb52ca462611c1f9ce5c4cede4172a31bfe64f336e82f29648694a3cfe
# Use the frozen distribution repository, never the moving 9.x mirror.
RUN dnf --setopt=install_weak_deps=False --disablerepo='*' \
    --repofrompath=baseline-baseos,https://dl.rockylinux.org/vault/rocky/9.6/BaseOS/$(uname -m)/os/ \
    --repofrompath=baseline-appstream,https://dl.rockylinux.org/vault/rocky/9.6/AppStream/$(uname -m)/os/ \
    --setopt=baseline-baseos.gpgcheck=1 --setopt=baseline-appstream.gpgcheck=1 \
    --setopt=baseline-baseos.gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9 \
    --setopt=baseline-appstream.gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9 \
    install -y gcc make perl-interpreter binutils git-core && dnf clean all
COPY --from=rust /usr/local/rustup /usr/local/rustup
COPY --from=rust /usr/local/cargo/bin /usr/local/cargo/bin
ENV RUSTUP_HOME=/usr/local/rustup RUSTUP_TOOLCHAIN=1.96.0 PATH=/usr/local/cargo/bin:$PATH
WORKDIR /source
