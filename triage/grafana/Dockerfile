# Tableau de bord du système de triage (étape 5).
# Base alpine locale : Docker Hub n'est pas joignable depuis le lab.
FROM alpine:latest
RUN apk add --no-cache grafana tzdata \
 && mkdir -p /var/lib/grafana /var/lib/grafana/plugins /var/log/grafana \
 && chown -R grafana:grafana /var/lib/grafana /var/log/grafana
COPY provisioning/ /etc/grafana/provisioning/
COPY dashboards/ /var/lib/grafana-dashboards/
USER grafana
EXPOSE 3000
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:3000/api/health || exit 1
CMD ["grafana", "server", "--homepath", "/usr/share/grafana", "--config", "/etc/grafana.ini"]
