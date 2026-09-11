# syntax=docker/dockerfile:1

FROM rust:1-slim-bookworm AS build
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN cargo build --release -p lb-server

FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN useradd --system --no-create-home --shell /usr/sbin/nologin lb
COPY --from=build /build/target/release/lb-server /usr/local/bin/lb-server
COPY config.example.toml /etc/lb-server/config.toml
USER lb
WORKDIR /etc/lb-server
ENTRYPOINT ["/usr/local/bin/lb-server"]
CMD ["config.toml"]
