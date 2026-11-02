# The engine's container image, from a release's own binaries, one for each
# architecture, beside this file as `nitromta-amd64` and `nitromta-arm64`:
# distroless, with glibc and the certificate authorities MTA-STS verifies
# by, and nothing else. It runs as a user of its own, neither root nor in
# root's group, as the engine asks, with its store, configuration and admin
# socket where the systemd unit keeps them, each that user's.

# The directories, made where the build runs, as nothing runs in the image.
FROM --platform=$BUILDPLATFORM busybox:1.37@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec AS directories
RUN mkdir -p /out/var/lib/nitromta /out/etc/nitromta /out/run/nitromta \
    && chmod 0700 /out/var/lib/nitromta \
    && chown -R 65532:65532 /out

FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
ARG TARGETARCH
COPY --from=directories /out/ /
COPY --chmod=0755 nitromta-${TARGETARCH} /usr/bin/nitromta
USER 65532:65532
VOLUME ["/var/lib/nitromta", "/etc/nitromta"]
ENTRYPOINT ["/usr/bin/nitromta"]
CMD ["run", "--config", "/etc/nitromta/config.toml"]
