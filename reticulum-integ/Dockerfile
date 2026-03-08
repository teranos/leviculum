FROM debian:bookworm-slim

# System dependencies
RUN apt-get update && apt-get install -y \
    python3 python3-pip python3-venv \
    iproute2 iputils-ping net-tools iptables \
    && rm -rf /var/lib/apt/lists/*

# Install Python RNS from vendor directory at build time.
# This makes rnstatus/rnpath/rnprobe available in all containers
# without runtime pip install (eliminates startup I/O contention).
COPY vendor/Reticulum /tmp/rns-src
RUN pip3 install --break-system-packages /tmp/rns-src && rm -rf /tmp/rns-src

# Create reticulum config directory
RUN mkdir -p /root/.reticulum/storage

# Copy entrypoint
COPY reticulum-integ/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
