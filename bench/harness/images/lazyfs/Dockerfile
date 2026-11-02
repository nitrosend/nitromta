# check=skip=InvalidDefaultArgInFrom
# (The base images come from the recipe and the harness, so the ARGs below
# have no defaults.)
# A system under test on LazyFS: a FUSE file system that keeps
# every write not yet synced in its own memory, and discards it when told
# to. The system's spool is mounted through it, over the real volume, so a
# crash loses exactly what the system had not synced.
ARG BUILD_BASE
ARG BASE

FROM ${BUILD_BASE} AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake libfuse3-dev
ARG LAZYFS_URL
ARG LAZYFS_TAG
# LazyFS leaves out two operations a mail system needs of its spool: creating
# a FIFO or a socket's node, which Postfix keeps in its queue directory, and
# reporting free space, which KumoMTA checks before it accepts. The patch
# passes both through to the disk beneath; neither touches what LazyFS
# caches. LazyFS links its page cache as a shared library, which its build
# leaves in the build tree rather than installing.
COPY mknod-statfs.patch /mknod-statfs.patch
RUN git clone --quiet --depth 1 --branch "$LAZYFS_TAG" "$LAZYFS_URL" /src \
    && git -C /src apply /mknod-statfs.patch \
    && cd /src/libs/libpcache && ./build.sh \
    && cd /src/lazyfs && ./build.sh \
    && cp /src/lazyfs/build/lazyfs /lazyfs \
    && mkdir /lazyfs-lib \
    && find /src/libs/libpcache/build -name '*.so*' -exec cp -P {} /lazyfs-lib/ \; \
    && echo "lazyfs $(git -C /src rev-parse HEAD)" > /lazyfs.sources

FROM ${BASE}
RUN apt-get update \
    && apt-get install -y --no-install-recommends fuse3 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /lazyfs /usr/local/bin/lazyfs
COPY --from=build /lazyfs-lib/ /usr/local/lib/
# Every library LazyFS needs is here, or the image is not built.
RUN ldconfig && ! ldd /usr/local/bin/lazyfs | grep "not found"
# The system's own sources, and LazyFS's.
COPY --from=build /lazyfs.sources /tmp/lazyfs.sources
RUN cat /tmp/lazyfs.sources >> /etc/harness/sources && rm /tmp/lazyfs.sources
COPY lazyfs.toml /etc/lazyfs.toml
COPY start-on-lazyfs /usr/local/bin/start-on-lazyfs
CMD ["start-on-lazyfs"]
