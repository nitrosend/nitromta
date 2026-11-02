# check=skip=InvalidDefaultArgInFrom
# (The base images come from the recipe, so the ARGs below have no defaults.)
# The engine, built from this repository with the toolchain its
# rust-toolchain.toml names.
ARG BUILD_BASE
ARG RUNTIME_BASE

FROM ${BUILD_BASE} AS build
WORKDIR /src
COPY rust-toolchain.toml .
RUN rustup toolchain install
COPY . .
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release --package engine \
    && cp target/release/nitromta /nitromta

FROM ${RUNTIME_BASE}
# `ip` and `arping`, for the second egress address of a production-shaped
# run; and the certificate authorities MTA-STS verifies by, which the engine
# will not start without while it honours MTA-STS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates iproute2 iputils-arping \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /nitromta /usr/local/bin/nitromta
# The engine runs without root, as its service unit runs it.
RUN useradd --system --no-create-home --shell /usr/sbin/nologin nitromta
# Built from this repository, whose commit each result records itself.
RUN mkdir -p /etc/harness && touch /etc/harness/sources
COPY bench/harness/images/nitromta/config.toml /etc/nitromta/config.toml
COPY bench/harness/images/nitromta/start /usr/local/bin/start
CMD ["start"]
