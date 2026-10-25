# The input archive is the existing, verified GNU native distribution for this
# exact architecture. This recipe does not compile or modify its executable.
FROM rockylinux/rockylinux:9.6@sha256:91bbb8eb52ca462611c1f9ce5c4cede4172a31bfe64f336e82f29648694a3cfe AS runtime
ADD native.tar.gz /payload/
# Mozilla roots converted by curl on 2026-10-20; public MPL-2.0 input.
ADD --checksum=sha256:796f1389bfea13c0ed78f663b765baaff54a508e5483786bd6ece73c5e3e3cbe https://curl.se/ca/cacert-2026-10-20.pem /ca/cacert.pem
RUN set -eu; \
    mkdir -p /rootfs/usr/bin /rootfs/usr/share/positron /rootfs/etc/ssl/certs /rootfs/lib64 /rootfs/lib /rootfs/var/lib/positron /rootfs/var/lib/positron-secrets /rootfs/etc/positron /rootfs/run/positron; \
    cp /payload/positron/bin/positron /rootfs/usr/bin/positron; \
    cp /payload/positron/share/config.schema.json /payload/positron/share/configuration.md /rootfs/usr/share/positron/; \
    cp /payload/positron/etc/positron.toml.example /rootfs/usr/share/positron/; \
    cp /payload/positron/LICENSE /rootfs/usr/share/positron/; \
    cp /ca/cacert.pem /rootfs/etc/ssl/certs/ca-certificates.crt; \
    chmod 0644 /rootfs/etc/ssl/certs/ca-certificates.crt; \
    for library in libc.so.6 libm.so.6 libgcc_s.so.1 libpthread.so.0 libdl.so.2 librt.so.1; do cp -L "/lib64/$library" /rootfs/lib64/; done; \
    case "$(uname -m)" in \
      x86_64) cp -L /lib64/ld-linux-x86-64.so.2 /rootfs/lib64/ ;; \
      aarch64) cp -L /lib/ld-linux-aarch64.so.1 /rootfs/lib/ ;; \
      *) exit 2 ;; \
    esac; \
    ln -s /run /rootfs/var/run; \
    chmod 0755 /rootfs/usr/bin/positron; \
    chmod 0700 /rootfs/var/lib/positron /rootfs/var/lib/positron-secrets /rootfs/run/positron; \
    chown 65532:65532 /rootfs/var/lib/positron /rootfs/var/lib/positron-secrets /rootfs/run/positron; \
    find /rootfs -exec touch -h -d @0 {} +

FROM scratch
# One uncompressed filesystem payload, independently compared before signing.
COPY --from=runtime /rootfs/ /
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt TMPDIR=/run/positron POSITRON__LISTENER__CONTROL_PATH=/run/positron/control.sock
USER 65532:65532
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/bin/positron"]
CMD ["serve", "--init-if-empty"]
