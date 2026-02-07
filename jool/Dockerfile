FROM docker.io/python:3.13.7-trixie

LABEL org.opencontainers.image.description="Jool image for nat64 and siit"

# datasource=github-releases depName=NICMx/Jool
ENV JOOL_VERSION=4.1.15

ADD "https://github.com/NICMx/Jool/releases/download/v${JOOL_VERSION}/jool-dkms_${JOOL_VERSION}-1_all.deb" /usr/local/src/jool-dkms.deb

RUN apt-get update \
    && apt-get install -y /usr/local/src/jool-dkms.deb jool-tools --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY --chmod=555 jool/entrypoint.sh /usr/local/bin/entrypoint.sh
COPY --chmod=555 jool/jool_eam_manager.py /usr/local/bin/jool_eam_manager.py

COPY jool/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

ENTRYPOINT [ "entrypoint.sh" ]
