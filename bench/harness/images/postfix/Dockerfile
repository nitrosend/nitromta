# check=skip=InvalidDefaultArgInFrom
# (The base images come from the recipe, so the ARGs below have no defaults.)
# Postfix with the OpenDKIM milter, both from source. Postfix as deployed in
# practice signs through a milter, whose processes count against Postfix's
# budget.
ARG BUILD_BASE
ARG RUNTIME_BASE

FROM ${BUILD_BASE} AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       autoconf automake libbsd-dev liblmdb-dev libmilter-dev libsasl2-dev libssl-dev libtool m4 pkg-config
ARG POSTFIX_URL
ARG POSTFIX_TAG
ARG OPENDKIM_URL
ARG OPENDKIM_TAG
RUN git clone --quiet --depth 1 --branch "$POSTFIX_TAG" "$POSTFIX_URL" /src/postfix \
    && git clone --quiet --depth 1 --branch "$OPENDKIM_TAG" "$OPENDKIM_URL" /src/opendkim \
    && { echo "postfix $(git -C /src/postfix rev-parse HEAD)"; \
         echo "opendkim $(git -C /src/opendkim rev-parse HEAD)"; } > /sources
# LMDB in place of Berkeley DB, which Debian no longer ships for building.
WORKDIR /src/postfix/postfix
RUN make makefiles shared=no dynamicmaps=no \
       CCARGS='-DUSE_TLS -DUSE_SASL_AUTH -DUSE_CYRUS_SASL -I/usr/include/sasl -DHAS_LMDB -DNO_DB -DNO_NIS -DDEF_DB_TYPE=\"lmdb\" -DDEF_CACHE_DB_TYPE=\"lmdb\"' \
       AUXLIBS='-lssl -lcrypto -lsasl2' AUXLIBS_LMDB='-llmdb' \
    && make -j"$(nproc)" \
    && sh postfix-install -non-interactive -package install_root=/out manpage_directory=/usr/share/man
WORKDIR /src/opendkim
RUN autoreconf -fi \
    && ./configure --prefix=/usr --sysconfdir=/etc --disable-static \
    && make -j"$(nproc)" \
    && make install DESTDIR=/out

FROM ${RUNTIME_BASE}
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       libbsd0 libicu76 liblmdb0 libmilter1.0.1 libpcre2-8-0 libsasl2-2 libsasl2-modules libsasl2-modules-db libssl3t64 sasl2-bin \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system postdrop \
    && useradd --system --no-create-home opendkim \
    && useradd --system --no-create-home --home-dir /var/spool/postfix --groups opendkim postfix
COPY --from=build /out/ /
COPY --from=build /sources /etc/harness/sources
RUN ldconfig
COPY main.cf master.cf /etc/postfix/
COPY smtpd.conf /etc/postfix/sasl/smtpd.conf
COPY opendkim.conf /etc/opendkim.conf
COPY start /usr/local/bin/start
CMD ["start"]
