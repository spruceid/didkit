FROM clux/muslrust:stable AS chef
USER root
RUN cargo install cargo-chef
WORKDIR /app

FROM chef AS planner
COPY ./defaults.toml ./
COPY ./Cargo.toml ./
COPY ./src/ ./src/
RUN sed -i -e 's/path .*,//g' ./Cargo.toml
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --target x86_64-unknown-linux-musl --recipe-path recipe.json
COPY --from=planner /app/ ./
RUN cargo build --release --target x86_64-unknown-linux-musl --bin didkit-http

FROM alpine AS runtime
RUN addgroup -S didkit-http && adduser -S didkit-http -G didkit-http
COPY --from=builder /app/target/x86_64-unknown-linux-musl/release/didkit-http /usr/local/bin/didkit-http
USER didkit-http
EXPOSE 3000
ENV DIDKIT_HTTP_HTTP_ADDRESS=[0,0,0,0]
CMD ["didkit-http"]
HEALTHCHECK --interval=5s --timeout=3s \
  CMD wget --no-verbose --tries=1 --spider http://localhost:3000/healthz || exit 1
LABEL org.opencontainers.image.source https://github.com/spruceid/didkit
