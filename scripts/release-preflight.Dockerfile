FROM ubuntu:24.04@sha256:786a8b558f7be160c6c8c4a54f9a57274f3b4fb1491cf65146521ae77ff1dc54

ARG RUST_TOOLCHAIN_VERSION=1.96.1
ARG CARGO_CYCLONEDX_VERSION=0.5.9
ARG SYFT_VERSION=v1.45.1
ARG SYFT_LINUX_AMD64_SHA256=20c84195e24927f50a3b2269946be51f4c4abc9d2f145fee7388b4199149f716

ENV DEBIAN_FRONTEND=noninteractive \
    RUSTUP_HOME=/opt/rustup \
    CARGO_HOME=/opt/cargo \
    PATH=/opt/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        bash build-essential ca-certificates curl docker.io file git jq \
        musl-tools python3 ripgrep shellcheck xz-utils \
    && rm -rf /var/lib/apt/lists/*

RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --profile minimal --default-toolchain "$RUST_TOOLCHAIN_VERSION" \
    && rustup target add --toolchain "$RUST_TOOLCHAIN_VERSION" x86_64-unknown-linux-musl \
    && cargo install --locked cargo-cyclonedx --version "$CARGO_CYCLONEDX_VERSION"

RUN syft_version="${SYFT_VERSION#v}" \
    && archive="syft_${syft_version}_linux_amd64.tar.gz" \
    && curl -sSfL \
        "https://github.com/anchore/syft/releases/download/$SYFT_VERSION/$archive" \
        -o "/tmp/$archive" \
    && printf '%s  %s\n' "$SYFT_LINUX_AMD64_SHA256" "/tmp/$archive" | sha256sum -c - \
    && tar -C /usr/local/bin -xzf "/tmp/$archive" syft \
    && rm -f "/tmp/$archive"

RUN apt-get update \
    && apt-get install -y --no-install-recommends gh \
    && rm -rf /var/lib/apt/lists/*

COPY scripts/release-preflight-inner.sh /usr/local/bin/borondns-release-preflight
RUN chmod 0555 /usr/local/bin/borondns-release-preflight

ENTRYPOINT ["/usr/local/bin/borondns-release-preflight"]
