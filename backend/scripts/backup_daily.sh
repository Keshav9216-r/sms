#!/usr/bin/env bash
set -euo pipefail

cd /workspaces/top/backend
/workspaces/top/.venv/bin/python manage.py backup_data
