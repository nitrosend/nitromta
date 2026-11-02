# check=skip=InvalidDefaultArgInFrom
# (The base images come from the recipe, so the ARGs below have no defaults.)
# The component ceilings, built from this repository with the
# toolchain its rust-toolchain.toml names.
ARG BUILD_BASE
ARG RUNTIME_BASE

FROM ${BUILD_BASE} AS build
WORKDIR /src
COPY rust-toolchain.toml .
RUN rustup toolchain install
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release --package ceilings \
    && cp target/release/ceilings /ceilings

FROM ${RUNTIME_BASE}
COPY --from=build /ceilings /usr/local/bin/ceilings
# Built from this repository, whose commit each result records itself.
RUN mkdir -p /etc/harness && touch /etc/harness/sources
CMD ["ceilings"]
