# ------------------------------------------------------------------------------
# Cargo Build Stage
# ------------------------------------------------------------------------------
FROM rust:alpine as cargo-build

WORKDIR /usr/src/user
RUN apk update && \
    apk upgrade
RUN apk add protoc protobuf-dev
RUN apk add build-base
RUN apk add clang llvm
RUN apk add openssl openssl-dev 
RUN apk add pkgconfig
RUN apk add --no-cache musl-dev
RUN rustup target add x86_64-unknown-linux-musl

RUN mkdir -p /usr/src/common
COPY ./common ../common
COPY ./user .

RUN RUSTFLAGS="-Ctarget-feature=-crt-static" cargo build --release --target=x86_64-unknown-linux-musl
RUN RUSTFLAGS="-Ctarget-feature=-crt-static" cargo install --path .

# ------------------------------------------------------------------------------
# Final Stage
# ------------------------------------------------------------------------------

FROM alpine:latest

COPY --from=cargo-build /usr/local/cargo/bin/user /usr/local/bin/user

CMD ["user"]
