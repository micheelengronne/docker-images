FROM docker.io/python:3.13.7-trixie

LABEL org.opencontainers.image.description="Jool exporter image for monitoring"

# datasource=github-releases depName=NICMx/Jool
ENV JOOL_VERSION=4.1.15

ADD "https://github.com/NICMx/Jool/releases/download/v${JOOL_VERSION}/jool-tools_${JOOL_VERSION}-1_amd64.deb" /usr/local/src/jool-tools.deb

WORKDIR /usr/local/src

RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y /usr/local/src/jool-tools.deb --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY jool_prom_exporter/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

CMD [ "/usr/local/bin/jool-exporter", "-p", "6971" ]
