# Base des décisions du système de triage (métadonnées uniquement).
# Base alpine locale : Docker Hub n'est pas joignable depuis le lab.
FROM alpine:latest
RUN apk add --no-cache postgresql17 postgresql17-client su-exec tzdata
COPY entrypoint.sh /entrypoint.sh
COPY schema.sql /init/schema.sql
RUN chmod 755 /entrypoint.sh
EXPOSE 5432
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD su-exec postgres pg_isready -q -d triage || exit 1
ENTRYPOINT ["/entrypoint.sh"]
