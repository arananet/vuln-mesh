FROM nginx:1.27-alpine

# Build context is the repo root (Railway sets rootDirectory to /)
COPY vuln_mesh/dashboard/static/ /usr/share/nginx/html/
COPY services/frontend/nginx.conf /etc/nginx/conf.d/default.conf
COPY services/frontend/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80

ENTRYPOINT ["/entrypoint.sh"]
