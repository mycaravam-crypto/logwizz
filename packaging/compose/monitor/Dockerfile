# Standalone, additive container image. Does not change production systemd packaging.
FROM rust:1.90-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY build.rs ./
COPY build ./build
COPY benches ./benches
RUN cargo build --release --locked --bin logwizz

FROM alpine:3.22
RUN addgroup -S logwizz && adduser -S -G logwizz logwizz
COPY --from=builder /src/target/release/logwizz /usr/local/bin/logwizz
RUN mkdir -p /data && chown logwizz:logwizz /data
COPY packaging/compose/monitor/portable.toml /etc/logwizz/portable.toml
COPY packaging/compose/monitor/run.sh /usr/local/bin/run-monitor
USER logwizz
ENTRYPOINT ["/usr/local/bin/run-monitor"]
