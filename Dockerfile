FROM lukemathwalker/cargo-chef:latest-rust-slim-bookworm as chef
WORKDIR /app

FROM chef as planner
COPY . .
RUN cargo chef prepare  --recipe-path recipe.json

FROM chef as builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin shush-rs

FROM frolvlad/alpine-glibc AS runtime
COPY --from=builder /app/target/release/shush-rs /usr/bin/shush-rs
ENTRYPOINT ["shush-rs"]