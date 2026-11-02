# Generates crates/engine-ses-v2: smithy-rs's server generator at the pinned
# release, on the pinned SES v2 model, then rustfmt from this repository's
# toolchain. Built from the repository root; `cargo xtask generate` runs it.
FROM rust:trixie
RUN apt-get update \
    && apt-get install -y --no-install-recommends openjdk-21-jdk-headless \
    && rm -rf /var/lib/apt/lists/*
ARG SMITHY_RS_TAG=release-2026-10-21
RUN git clone --quiet --depth 1 --branch "$SMITHY_RS_TAG" https://github.com/smithy-lang/smithy-rs /smithy-rs \
    && echo 'include(":engine-ses-v2")' >> /smithy-rs/settings.gradle.kts
WORKDIR /smithy-rs
COPY rust-toolchain.toml /toolchain/rust-toolchain.toml
RUN cd /toolchain && rustup toolchain install && rustup component add rustfmt
COPY models/generate/build.gradle.kts models/generate/smithy-build.json engine-ses-v2/
# The generator's own build, done once in the image.
RUN ./gradlew :codegen-server:assemble --no-daemon --quiet
COPY models/sesv2-2019-09-27.json engine-ses-v2/model/sesv2.json
COPY models/generate/generate /usr/local/bin/generate
CMD ["generate"]
