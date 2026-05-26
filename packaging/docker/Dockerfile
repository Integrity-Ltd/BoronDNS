ARG ALPINE_VERSION=3.22
FROM alpine:${ALPINE_VERSION}

ARG VERSION=dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG OXIDEDNS_UID=53053
ARG OXIDEDNS_GID=53053

LABEL org.opencontainers.image.title="OxideDNS" \
      org.opencontainers.image.description="Secondary-only authoritative DNS server" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

RUN addgroup -S -g "${OXIDEDNS_GID}" oxidedns \
    && adduser -S -D -H -u "${OXIDEDNS_UID}" -G oxidedns -s /sbin/nologin oxidedns \
    && install -d -m 0750 -o root -g oxidedns /etc/oxidedns-secondary

COPY --chown=root:root oxidedns /usr/local/bin/oxidedns
COPY --chown=root:oxidedns oxidedns.example.toml /etc/oxidedns-secondary/config.toml

RUN chmod 0755 /usr/local/bin/oxidedns \
    && chmod 0640 /etc/oxidedns-secondary/config.toml

USER oxidedns:oxidedns
EXPOSE 5300/udp 5300/tcp 8080/tcp
ENTRYPOINT ["/usr/local/bin/oxidedns"]
CMD ["serve", "--config", "/etc/oxidedns-secondary/config.toml"]

