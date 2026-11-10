# syntax=docker/dockerfile:1

# Build stage: the toolchain version is pinned so an image build is
# reproducible; bump it deliberately.
ARG RUST_VERSION=1.99
# The runtime base. Distroless "cc" carries glibc, libgcc and CA
# certificates and nothing else: no shell, no package manager.
ARG RUNTIME_IMAGE=gcr.io/distroless/cc-debian12:nonroot

FROM rust:${RUST_VERSION}-slim-bookworm AS build
WORKDIR /src

# Dependencies first, so they are cached across source-only changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src \
 && echo 'fn main() {}' > src/main.rs \
 && touch src/lib.rs \
 && cargo build --release --locked \
 && rm -rf src

COPY src ./src
RUN touch src/main.rs src/lib.rs \
 && cargo build --release --locked --bin mpc-relay \
 && ./target/release/mpc-relay --version

FROM ${RUNTIME_IMAGE}
COPY --from=build /src/target/release/mpc-relay /usr/local/bin/mpc-relay
# 65532 is distroless's "nonroot"; stated numerically so the image runs as
# non-root on any base and Kubernetes can verify runAsNonRoot.
USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/mpc-relay"]
