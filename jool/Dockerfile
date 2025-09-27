FROM docker.io/ubuntu:24.04

LABEL org.opencontainers.image.description Jool image for nat64

RUN apt-get update \
    && apt-get install -y linux-headers-generic jool-dkms jool-tools --no-install-recommends \
    && apt-get purge -y linux-headers-generic \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
