# Outil de quarantaine du système de triage (étape 5) : consultation, validation,
# libération et suppression des messages N3/N4, avec journal des actions.
# Base alpine locale : Docker Hub n'est pas joignable depuis le lab.
FROM alpine:latest
RUN apk add --no-cache python3 py3-pip tzdata \
 && adduser -D -H -u 1100 -s /sbin/nologin triage
WORKDIR /app
COPY requirements.txt .
RUN python3 -m venv /venv && /venv/bin/pip install --no-cache-dir -r requirements.txt
COPY app/ /app/
USER triage
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD /venv/bin/python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/sante', timeout=3)"
CMD ["/venv/bin/uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
