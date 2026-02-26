#!/usr/bin/env bash
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV_PY="${PROJECT_DIR}/.venv/bin/python"
ENV_FILE="${PROJECT_DIR}/.env"
ENV_EXAMPLE="${PROJECT_DIR}/.env.production.example"
APPLY_CHANGES=false

if [[ "${1:-}" == "--apply" ]]; then
  APPLY_CHANGES=true
fi

if [[ ! -x "${VENV_PY}" ]]; then
  echo "[ERROR] Python venv not found at ${VENV_PY}"
  echo "Create it with: cd ${PROJECT_DIR} && python3 -m venv .venv && .venv/bin/pip install -r requirements.txt"
  exit 1
fi

cd "${PROJECT_DIR}"

echo "== SMS Production Deployment Checklist =="
echo "Project: ${PROJECT_DIR}"

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "[WARN] ${ENV_FILE} not found."
  echo "Copy and edit: cp ${ENV_EXAMPLE} ${ENV_FILE}"
else
  echo "[OK] .env found"
fi

echo
echo "[1/6] Django deploy checks"
"${VENV_PY}" manage.py check --deploy

echo
echo "[2/6] Security static analysis (Bandit)"
if command -v bandit >/dev/null 2>&1; then
  bandit -r apps shop_management -x '**/migrations/**,**/.venv/**' -q
else
  echo "[SKIP] bandit not installed (install with: .venv/bin/pip install bandit)"
fi

echo
echo "[3/6] Dependency vulnerability scan (pip-audit)"
if "${VENV_PY}" -m pip_audit -r requirements.txt >/dev/null 2>&1; then
  echo "[OK] No known dependency vulnerabilities"
else
  echo "[WARN] pip-audit reported issues or is missing"
  echo "Install/upgrade: ${VENV_PY} -m pip install pip-audit && ${VENV_PY} -m pip_audit -r requirements.txt"
fi

echo
echo "[4/6] Migrations + static files"
if [[ "${APPLY_CHANGES}" == "true" ]]; then
  "${VENV_PY}" manage.py migrate --noinput
  "${VENV_PY}" manage.py collectstatic --noinput
  echo "[OK] Applied migrations and collected static files"
else
  "${VENV_PY}" manage.py migrate --plan >/dev/null
  echo "[OK] Migration plan generated (dry-run)"
  echo "Run with --apply to execute migrations and collectstatic"
fi

echo
echo "[5/6] Gunicorn systemd template"
cat <<'UNIT'
----- /etc/systemd/system/sms-gunicorn.service -----
[Unit]
Description=SMS Django Gunicorn
After=network.target

[Service]
User=www-data
Group=www-data
WorkingDirectory=/workspaces/sms/backend
EnvironmentFile=/workspaces/sms/backend/.env
ExecStart=/workspaces/sms/backend/.venv/bin/gunicorn \
  --workers 3 \
  --bind 127.0.0.1:8000 \
  shop_management.wsgi:application
Restart=always

[Install]
WantedBy=multi-user.target
-----------------------------------------------------
UNIT

echo
echo "[6/6] Nginx + HTTPS template"
cat <<'NGINX'
----- /etc/nginx/sites-available/sms -----
server {
  listen 80;
  server_name example.com www.example.com;

  location /static/ {
    alias /workspaces/sms/backend/staticfiles/;
  }

  location /media/ {
    alias /workspaces/sms/frontend/media/;
  }

  location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
  }
}
-----------------------------------------

Enable and secure:
  sudo ln -s /etc/nginx/sites-available/sms /etc/nginx/sites-enabled/sms
  sudo nginx -t && sudo systemctl reload nginx
  sudo apt-get install -y certbot python3-certbot-nginx
  sudo certbot --nginx -d example.com -d www.example.com
NGINX

echo
echo "Next commands on server:"
echo "  sudo systemctl daemon-reload"
echo "  sudo systemctl enable --now sms-gunicorn"
echo "  sudo systemctl status sms-gunicorn --no-pager"
echo
echo "Checklist complete."
