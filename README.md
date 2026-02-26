# Project Structure

- backend/: Django backend (manage.py, settings, apps)
- frontend/: Templates, static assets, and media uploads
- rest/: Documentation and reference files

Run the backend:
- cd backend
- .venv/bin/python manage.py runserver

## Production quick start

1. Copy the production environment template and fill real values:
	- `cp backend/.env.production.example backend/.env`
2. Run the production readiness checklist:
	- `cd backend && ./scripts/prod_deploy_checklist.sh`
3. On the deployment server, apply DB/static changes when ready:
	- `cd backend && ./scripts/prod_deploy_checklist.sh --apply`
