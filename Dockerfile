FROM rustlang/rust:nightly as builder

RUN apt-get update && apt-get install -y apt-utils software-properties-common lsb-release clang

WORKDIR /usr/src/pastebin
COPY . .

RUN cargo install --path .

FROM debian:bookworm-slim
COPY --from=builder /usr/local/cargo/bin/pastebin /usr/local/bin/pastebin

RUN adduser --system --uid 820 --group pastebin

USER pastebin

ENTRYPOINT ["pastebin"]
CMD ["--help"]
