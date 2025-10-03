FROM docker.io/python:3.13.7-alpine3.22

WORKDIR /usr/local/src

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

CMD [ "/usr/local/bin/jool-exporter", "-p", "6971" ]
