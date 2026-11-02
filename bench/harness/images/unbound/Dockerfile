# check=skip=InvalidDefaultArgInFrom
# (The base images come from the recipe, so the ARGs below have no defaults.)
# unbound, the resolver every system under test uses, from source.
ARG BUILD_BASE
ARG RUNTIME_BASE

FROM ${BUILD_BASE} AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends bison flex libexpat1-dev libssl-dev
ARG UNBOUND_URL
ARG UNBOUND_TAG
RUN git clone --quiet --depth 1 --branch "$UNBOUND_TAG" "$UNBOUND_URL" /src \
    && echo "unbound $(git -C /src rev-parse HEAD)" > /sources
WORKDIR /src
RUN ./configure --prefix=/usr --sysconfdir=/etc --without-pythonmodule --without-pyunbound \
    && make -j"$(nproc)" \
    && make install DESTDIR=/out

FROM ${RUNTIME_BASE}
RUN apt-get update \
    && apt-get install -y --no-install-recommends libexpat1 libssl3t64 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/ /
COPY --from=build /sources /etc/harness/sources
RUN mkdir -p /etc/unbound && ldconfig
# The harness writes the zone into /etc/unbound/unbound.conf before start.
CMD ["unbound", "-d", "-c", "/etc/unbound/unbound.conf"]
