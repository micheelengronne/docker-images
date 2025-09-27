FROM docker.io/ubuntu:24.04

LABEL org.opencontainers.image.description="Jool image for nat64"

# datasource=github-releases depName=NICMx/Jool
ENV JOOL_VERSION=4.1.14

ADD "https://github.com/NICMx/Jool/releases/download/v${JOOL_VERSION}/jool-dkms_${JOOL_VERSION}-1_all.deb" /usr/local/src/jool-dkms.deb

RUN apt-get update \
    && apt-get install -y linux-headers-generic /usr/local/src/jool-dkms.deb jool-tools --no-install-recommends \
    && apt-get purge -y linux-headers-generic \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
