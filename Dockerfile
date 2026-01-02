FROM rust:latest AS builder

RUN apt-get update && apt-get install -y libclang-dev

WORKDIR /usr/src/pastebin
COPY . .

RUN cargo install --path .

FROM debian:trixie-slim
COPY --from=builder /usr/local/cargo/bin/pastebin /usr/local/bin/pastebin

RUN apt-get update && apt-get install -y adduser
RUN adduser --system --uid 820 --group pastebin

USER pastebin

ENTRYPOINT ["pastebin"]
CMD ["--help"]
