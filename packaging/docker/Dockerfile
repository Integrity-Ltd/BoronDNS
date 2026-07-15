ARG ALPINE_BASE_IMAGE=alpine:3.22@sha256:7c8cb692ae09657cbc4a3f3cbd0e8d5a2690ba38386aaaf252dbb060bf5eb2e6
FROM ${ALPINE_BASE_IMAGE}

ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG SOURCE_CLEAN=unknown
ARG RELEASE_ELIGIBLE=unknown
ARG BORONDNS_UID=53053
ARG BORONDNS_GID=53053

LABEL org.opencontainers.image.title="BoronDNS" \
      org.opencontainers.image.description="Secondary-only authoritative DNS server" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      io.borondns.source-clean="${SOURCE_CLEAN}" \
      io.borondns.release-eligible="${RELEASE_ELIGIBLE}" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

RUN addgroup -S -g "${BORONDNS_GID}" borondns \
    && adduser -S -D -H -u "${BORONDNS_UID}" -G borondns -s /sbin/nologin borondns \
    && install -d -m 0750 -o root -g borondns /etc/borondns-secondary

COPY --chown=root:root borondns /usr/local/bin/borondns
COPY --chown=root:borondns borondns.example.toml /etc/borondns-secondary/config.toml

RUN chmod 0755 /usr/local/bin/borondns \
    && chmod 0640 /etc/borondns-secondary/config.toml

USER borondns:borondns
EXPOSE 5300/udp 5300/tcp 8080/tcp
ENTRYPOINT ["/usr/local/bin/borondns"]
CMD ["serve", "--config", "/etc/borondns-secondary/config.toml"]
