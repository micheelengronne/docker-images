FROM docker.io/ubuntu:24.04

LABEL org.opencontainers.image.description="Tinyproxy image"

RUN apt-get update \
    && apt-get install -y tinyproxy --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

CMD ["tinyproxy -d -c /usr/local/etc/tinyproxy.conf"]
