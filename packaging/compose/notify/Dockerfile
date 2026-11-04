# Experimental: the unmodified logwizz-notify binary in its own container, so the
# network access and the bot token stay away from the log-reading monitor.
FROM rust:1.90-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY build.rs ./
COPY build ./build
COPY benches ./benches
RUN cargo build --release --locked --bin logwizz-notify

FROM alpine:3.22
RUN apk add --no-cache curl jq ca-certificates
RUN addgroup -S logwizz && adduser -S -G logwizz logwizz
RUN mkdir -p /var/lib/logwizz-notify && chown logwizz:logwizz /var/lib/logwizz-notify
COPY --from=builder /src/target/release/logwizz-notify /usr/local/bin/logwizz-notify
COPY packaging/compose/notify/journalctl /usr/local/bin/journalctl
USER logwizz
ENTRYPOINT ["/usr/local/bin/logwizz-notify"]
