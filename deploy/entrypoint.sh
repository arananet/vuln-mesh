#!/bin/sh
set -e

# Inject runtime config so the SPA knows where the backend lives.
# BACKEND_URL is set in the Railway frontend service environment.
cat > /usr/share/nginx/html/config.js <<CONFIG
window.APP_CONFIG = {
  backendUrl: "${BACKEND_URL:-}",
  version:    "0.1.0"
};
CONFIG

exec nginx -g "daemon off;"
