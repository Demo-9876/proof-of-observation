ARG ALIYUN_ENCLAVE_PLATFORM=linux/amd64
ARG GO_BUILDER_IMAGE=docker.io/library/golang@sha256:98d673f18a1aac43da744209873cb79323e11706f909251bcfb131828b95559d
ARG RUST_BUILDER_IMAGE=docker.io/library/rust@sha256:64d9b7f60e3abb08d477cad983d0a3743acc53a19369ba4482510184c9c807e5

FROM --platform=${ALIYUN_ENCLAVE_PLATFORM} ${GO_BUILDER_IMAGE} AS go-builder

WORKDIR /src/aliyun-enclave

COPY aliyun-enclave/go.mod aliyun-enclave/go.sum ./
RUN go mod download

COPY aliyun-enclave/. ./
RUN CGO_ENABLED=0 go build -tags aliyun_enclave -trimpath -ldflags="-s -w" -o /out/aliyun-proof-helper ./cmd/aliyun-proof-helper

FROM --platform=${ALIYUN_ENCLAVE_PLATFORM} ${RUST_BUILDER_IMAGE} AS rust-builder

WORKDIR /src/enclave

ENV SOURCE_DATE_EPOCH=0 \
    CARGO_INCREMENTAL=0 \
    RUSTFLAGS="--remap-path-prefix=/src=/src --remap-path-prefix=/usr/local/cargo=/cargo"

RUN apt-get update && apt-get install -y --no-install-recommends cmake clang libclang-dev && rm -rf /var/lib/apt/lists/*

ENV CFLAGS="-O2 -g0 -ffile-prefix-map=/src=/src -ffile-prefix-map=/usr/local/cargo=/cargo" \
    CXXFLAGS="-O2 -g0 -ffile-prefix-map=/src=/src -ffile-prefix-map=/usr/local/cargo=/cargo"

COPY enclave/Cargo.toml enclave/Cargo.lock ./
COPY enclave/src ./src

RUN cargo build --release --locked

FROM --platform=${ALIYUN_ENCLAVE_PLATFORM} alibaba-cloud-linux-2-registry.cn-hangzhou.cr.aliyuncs.com/alinux2/alinux2@sha256:2af515d7e03e94ca394d78cdeb3aa337f2fa6c5f71053a1f567dd91c86cc3938

COPY --from=rust-builder /src/enclave/target/release/attest /attest
COPY --from=go-builder /out/aliyun-proof-helper /usr/bin/aliyun-proof-helper
COPY deploy/aliyun-vtpm-runtime/run.sh /run.sh

RUN chmod 0755 /attest /usr/bin/aliyun-proof-helper /run.sh

ENV TEE_PROFILE=aliyun-vtpm \
    ALIYUN_PROOF_HELPER_SOCKET=/run/aliyun-proof-helper.sock

CMD ["/run.sh"]
