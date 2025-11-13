# FROM ubuntu:24.04
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
      libbpf1 libelf1 zlib1g ca-certificates libzstd1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY daemon trace.bpf.o /app/
RUN chmod +x /app/daemon

CMD ["./daemon"]
