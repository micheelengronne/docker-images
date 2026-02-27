FROM docker.io/ubuntu:24.04

LABEL org.opencontainers.image.description="Jool image for nat64 and siit"

# datasource=github-releases depName=NICMx/Jool
ENV JOOL_VERSION=4.1.15

ADD "https://github.com/NICMx/Jool/releases/download/v${JOOL_VERSION}/jool-dkms_${JOOL_VERSION}-1_all.deb" /usr/local/src/jool-dkms.deb
ADD "https://github.com/NICMx/Jool/releases/download/v${JOOL_VERSION}/jool-tools_${JOOL_VERSION}-1_amd64.deb" /usr/local/src/jool-tools.deb

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y libc6 libnl-3-200 libnl-genl-3-200 /usr/local/src/jool-dkms.deb /usr/local/src/jool-tools.deb --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=555 jool_ubuntu_2404/entrypoint.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT [ "entrypoint.sh" ]
