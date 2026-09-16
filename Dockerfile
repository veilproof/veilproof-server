# Build stage
FROM rust:1-slim AS build
WORKDIR /app
# Cache dependencies first.
COPY Cargo.toml Cargo.lock ./
COPY migrations ./migrations
RUN mkdir src && echo "fn main() {}" > src/main.rs && echo "" > src/lib.rs \
    && cargo build --release --quiet 2>/dev/null || true
# Now the real sources.
COPY src ./src
RUN touch src/main.rs src/lib.rs && cargo build --release

# Runtime stage
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=build /app/target/release/veilproof-server /usr/local/bin/veilproof-server
COPY migrations ./migrations
ENV VEILPROOF_BIND=0.0.0.0:8080
EXPOSE 8080
CMD ["veilproof-server"]
