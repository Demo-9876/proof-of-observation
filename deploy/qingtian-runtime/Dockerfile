# QingTian Enclave runtime image for proof-of-observation.
#
# Build context: repository root.
# Required input: Huawei QingTian SDK checked out at QTSM_SDK_DIR, defaulting to
# third_party/qingtian-sdk. The directory must contain enclave/qtsm/lib/Makefile.
#
# Example:
#   docker build --no-cache \
#     --build-arg QTSM_SDK_DIR=third_party/qingtian-sdk \
#     --build-arg APT_MIRROR=https://repo.huaweicloud.com/debian \
#     --build-arg CARGO_REGISTRY_MIRROR=sparse+https://rsproxy.cn/index/ \
#     --build-arg POO_PARENT_CIDS=3 \
#     -f deploy/qingtian-runtime/Dockerfile \
#     -t proof-observation-qingtian:dev .

FROM rust:1-bookworm AS builder

ARG QTSM_SDK_DIR=third_party/qingtian-sdk
ARG APT_MIRROR=
ARG CARGO_REGISTRY_MIRROR=
ARG POO_PARENT_CIDS=3

WORKDIR /src

ENV SOURCE_DATE_EPOCH=0 \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS="--remap-path-prefix=/src=/src --remap-path-prefix=/usr/local/cargo=/cargo -L native=/opt/qingtian/qtsm/lib" \
    CFLAGS="-O2 -g0 -ffile-prefix-map=/src=/src -ffile-prefix-map=/usr/local/cargo=/cargo" \
    CXXFLAGS="-O2 -g0 -ffile-prefix-map=/src=/src -ffile-prefix-map=/usr/local/cargo=/cargo" \
    POO_PARENT_CIDS=${POO_PARENT_CIDS}

RUN if [ -n "$APT_MIRROR" ]; then \
      sed -i "s|http://deb.debian.org/debian|$APT_MIRROR|g; s|http://security.debian.org/debian-security|$APT_MIRROR-security|g" /etc/apt/sources.list.d/debian.sources; \
    fi && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      clang \
      cmake \
      gcc \
      libcbor-dev \
      libclang-dev \
      libssl-dev \
      make \
      pkg-config && \
    rm -rf /var/lib/apt/lists/*

RUN if [ -n "$CARGO_REGISTRY_MIRROR" ]; then \
      mkdir -p /usr/local/cargo && \
      printf '[source.crates-io]\nreplace-with = "mirror"\n\n[source.mirror]\nregistry = "%s"\n\n[net]\ngit-fetch-with-cli = true\n' "$CARGO_REGISTRY_MIRROR" > /usr/local/cargo/config.toml; \
    fi

COPY ${QTSM_SDK_DIR}/enclave/qtsm /opt/qingtian/qtsm
RUN cd /opt/qingtian/qtsm/lib && \
    mkdir -p ../output && \
    make && \
    install -m 0755 libqtsm.so /usr/local/lib/libqtsm.so && \
    ldconfig

COPY enclave/Cargo.toml enclave/Cargo.lock /src/enclave/
COPY enclave/src /src/enclave/src
WORKDIR /src/enclave
RUN cargo build --release --locked --no-default-features --features qingtian

FROM debian:bookworm-slim

ARG APT_MIRROR=
ARG POO_PARENT_CIDS=3

RUN if [ -n "$APT_MIRROR" ]; then \
      sed -i "s|http://deb.debian.org/debian|$APT_MIRROR|g; s|http://security.debian.org/debian-security|$APT_MIRROR-security|g" /etc/apt/sources.list.d/debian.sources; \
    fi && \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      ca-certificates \
      libcbor0.8 \
      libssl3 && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/libqtsm.so /usr/local/lib/libqtsm.so
COPY --from=builder /src/enclave/target/release/attest /attest

ENV TEE_PROFILE=qingtian \
    POO_EVIDENCE_PROFILE=qingtian \
    POO_PARENT_CIDS=${POO_PARENT_CIDS} \
    LD_LIBRARY_PATH=/usr/local/lib

RUN ldconfig && \
    ldd /attest && \
    ldd /usr/local/lib/libqtsm.so && \
    find / -xdev -exec touch -hcd "@0" {} + 2>/dev/null || true

CMD ["/attest"]
