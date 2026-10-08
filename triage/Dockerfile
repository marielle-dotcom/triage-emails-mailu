# Filtre de triage After-Queue (aiosmtpd). Base alpine locale : Docker Hub
# n'est pas joignable depuis le lab, les dépôts Alpine et PyPI le sont.
FROM alpine:latest

RUN apk add --no-cache python3 py3-pip \
 && adduser -D -H -u 1100 -s /sbin/nologin triage

WORKDIR /app
COPY requirements.txt .
RUN python3 -m venv /venv && /venv/bin/pip install --no-cache-dir -r requirements.txt
COPY app/ /app/
COPY referentiels/ /app/referentiels/

USER triage
EXPOSE 10035
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD /venv/bin/python -c "import socket; socket.create_connection(('127.0.0.1', 10035), 3).close()"
CMD ["/venv/bin/python", "-u", "/app/server.py"]
