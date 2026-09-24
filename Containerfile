# Build stage - only exists to compile; not part of the shipped image.
FROM docker.io/library/rust:1-slim AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

# Runtime stage - just the binary.
FROM debian:12-slim
COPY --from=builder /src/target/release/join /usr/local/bin/join

# Unlike podwatch, join needs no host access, so it runs unprivileged.
USER 65532:65532

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/join"]
