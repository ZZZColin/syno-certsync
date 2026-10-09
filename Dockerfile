FROM python:3.12-alpine

# acme.sh is a single script; keep it outside /config (a bind mount) and keep its state in /config.
# Pin ACME_REF to a release tag for reproducible builds: --build-arg ACME_REF=<tag>
ARG ACME_REF=master
RUN apk add --no-cache openssl curl socat util-linux-misc bash \
    && curl -fsSL "https://raw.githubusercontent.com/acmesh-official/acme.sh/${ACME_REF}/acme.sh" -o /usr/local/bin/acme.sh \
    && chmod +x /usr/local/bin/acme.sh

WORKDIR /app
COPY syno_certsync ./syno_certsync
COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV HOME=/config \
    LE_WORKING_DIR=/config/.acme.sh \
    CERTSYNC_CONF=/config/config.ini \
    CERTSYNC_OUT=/config/certs \
    CERTSYNC_NSENTER=1 \
    SYNC_INTERVAL_HOURS=24 \
    PYTHONUNBUFFERED=1

ENTRYPOINT ["/entrypoint.sh"]
