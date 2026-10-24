FROM golang:1.25.7-bookworm AS nuclei-builder

RUN go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.8.0

FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    NUCLEI_PATH=/usr/local/bin/nuclei \
    SSLYZE_PATH=/usr/local/bin/sslyze \
    WHATWEB_PATH=/opt/whatweb/whatweb

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        nmap \
        ruby-full \
    && gem install bundler --no-document \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY backend/requirements.txt backend/requirements-docker.txt ./
RUN pip install --no-cache-dir -r requirements-docker.txt

ADD https://github.com/urbanadventurer/WhatWeb/archive/d279d93042d034f3fd29d5a893d44ccc0595d3f8.tar.gz /tmp/whatweb.tar.gz
RUN mkdir -p /opt/whatweb && tar -xzf /tmp/whatweb.tar.gz --strip-components=1 -C /opt/whatweb && rm /tmp/whatweb.tar.gz
RUN cd /opt/whatweb \
    && bundle config set without "development test mongo rchardet" \
    && bundle install \
    && chmod +x /opt/whatweb/whatweb

COPY --from=nuclei-builder /go/bin/nuclei /usr/local/bin/nuclei
COPY backend /app

RUN mkdir -p /app/generated_reports /app/uploads/avatars

EXPOSE 5000

CMD ["sh", "-c", "python docker_entrypoint.py && exec gunicorn --bind 0.0.0.0:5000 --workers 2 --threads 4 --timeout 900 app:app"]
