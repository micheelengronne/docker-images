FROM docker.io/python:3.13.7-trixie

WORKDIR /usr/local/src

RUN apt-get update \
    && apt-get install -y jool-tools --no-install-recommends \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

COPY jool_prom_exporter/requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

CMD [ "/usr/local/bin/jool-exporter", "-p", "6971" ]
