FROM docker.io/debian:13.3-slim

LABEL org.opencontainers.image.description="Jool image for nat64 and siit"

# datasource=github-releases depName=NICMx/Jool
ENV JOOL_VERSION=4.1.15

ADD "https://github.com/NICMx/Jool/releases/download/v${JOOL_VERSION}/jool-${JOOL_VERSION}.tar.gz" /usr/local/src/jool-dkms.tar.gz

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y jool-tools dkms zstd gcc-13 libnl-genl-3-dev libxtables-dev pkg-config build-essential --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/local/src/build \
    && tar xzf /usr/local/src/jool-dkms.tar.gz -C /usr/local/src/build \
    && mv /usr/local/src/build/jool-* /usr/local/src/build/jool

COPY --chmod=555 jool/entrypoint.sh /usr/local/bin/entrypoint.sh

ENTRYPOINT [ "entrypoint.sh" ]
