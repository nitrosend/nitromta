# check=skip=InvalidDefaultArgInFrom
# (The base images come from the recipe, so the ARGs below have no defaults.)
# KumoMTA, from source, with the build dependencies its
# get-deps.sh names, and its traffic-shaping automation daemon and policy
# helpers, which the throttled profile runs as KumoMTA's deployments do.
ARG BUILD_BASE
ARG RUNTIME_BASE

FROM ${BUILD_BASE} AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake libclang-dev libssl-dev libzstd-dev pkg-config
ARG KUMOMTA_URL
ARG KUMOMTA_TAG
RUN git clone --quiet --depth 1 --branch "$KUMOMTA_TAG" "$KUMOMTA_URL" /src \
    && echo "kumomta $(git -C /src rev-parse HEAD)" > /sources
WORKDIR /src
RUN rustup toolchain install
# One compile job per 2 GiB of memory, at most one per CPU: some of KumoMTA's
# crates take more than a gigabyte each to compile, and a job per CPU can
# exhaust a container runtime's virtual machine.
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    jobs=$(awk -v cpus="$(nproc)" '/MemTotal/ { j = int($2 / 2097152); if (j < 1) j = 1; if (j > cpus) j = cpus; print j }' /proc/meminfo) \
    && cargo build --locked --release --package kumod --package tsa-daemon --jobs "$jobs" \
    && cp target/release/kumod target/release/tsa-daemon /

FROM ${RUNTIME_BASE}
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates libssl3t64 libzstd1 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home kumod
COPY --from=build /kumod /tsa-daemon /usr/local/bin/
COPY --from=build /src/assets/policy-extras /opt/kumomta/share/policy-extras
COPY --from=build /sources /etc/harness/sources
COPY init.lua tsa_init.lua /etc/kumomta/
COPY start /usr/local/bin/start
CMD ["start"]
