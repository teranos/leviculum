FROM debian:bookworm-slim

# System dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    iproute2 iputils-ping net-tools iptables \
    && rm -rf /var/lib/apt/lists/*

# Create reticulum config directory
RUN mkdir -p /root/.reticulum/storage

# Copy entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
