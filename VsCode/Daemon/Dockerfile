# FROM ubuntu:24.04
FROM debian:bookworm-slim

# 1. Add backports repository
RUN echo "deb http://deb.debian.org/debian bookworm-backports main" >> /etc/apt/sources.list.d/backports.list

# 2. Update package lists
RUN apt-get update

# 3. CRITICAL: Use the -t flag to target the backports repository specifically for libbpf1
RUN apt-get install -y --no-install-recommends \
      libelf1 zlib1g ca-certificates libzstd1 \
      libbpf1/bookworm-backports \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY daemon trace.bpf.o /app/
RUN chmod +x /app/daemon

CMD ["./daemon"]

# Dynamic linking the libbpf libraries to the compiled binary

