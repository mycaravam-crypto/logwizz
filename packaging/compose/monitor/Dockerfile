# Standalone, additive container image. Does not change production systemd packaging.
FROM rust:1.90-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY build.rs ./
RUN cargo build --release --locked --bin logwizz

FROM alpine:3.22
RUN addgroup -S logwizz && adduser -S -G logwizz logwizz
COPY --from=builder /src/target/release/logwizz /usr/local/bin/logwizz
COPY packaging/compose/monitor/portable.toml /etc/logwizz/portable.toml
USER logwizz
ENTRYPOINT ["/usr/local/bin/logwizz", "--config", "/etc/logwizz/portable.toml"]
