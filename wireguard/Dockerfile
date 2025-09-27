FROM docker.io/ubuntu:24.04

LABEL org.opencontainers.image.description Wireguard image to run mesh networks

RUN apt-get update \
    && apt-get install -y wireguard --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
