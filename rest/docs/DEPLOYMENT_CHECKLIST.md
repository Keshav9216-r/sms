# Pre-Deployment Checklist

## Readiness Assessment (Based on Current Repo State)

Status: READY AFTER INFRA STEPS

Reasons:
- backend/.env is present and must be filled with production values.
- Deployment must supply SECRET_KEY, ALLOWED_HOSTS, DB_* settings, and security toggles.
- Infrastructure steps (reverse proxy, migrations, collectstatic, backups) are still pending.

Assumptions:
- Production target requires HTTPS and a managed database.

---

## Production Environment Variables
- [ ] SECRET_KEY (required)
- [ ] DEBUG (should be False)
- [ ] ALLOWED_HOSTS (required)
- [ ] CSRF_TRUSTED_ORIGINS (required for HTTPS)
- [ ] DB_ENGINE, DB_NAME, DB_USER, DB_PASSWORD, DB_HOST, DB_PORT
- [ ] SECURE_SSL_REDIRECT, SESSION_COOKIE_SECURE, CSRF_COOKIE_SECURE
- [ ] SECURE_HSTS_SECONDS, SECURE_HSTS_INCLUDE_SUBDOMAINS, SECURE_HSTS_PRELOAD
- [ ] SECURE_REFERRER_POLICY, SECURE_CONTENT_TYPE_NOSNIFF, X_FRAME_OPTIONS
- [ ] SECURE_PROXY_SSL_HEADER (if behind reverse proxy)
- [ ] CELERY_BROKER_URL, CELERY_RESULT_BACKEND (if using background jobs)

## Security
- [ ] SECRET_KEY is set via environment and not committed.
- [ ] DEBUG is False in production.
- [ ] ALLOWED_HOSTS includes only production domains.
- [ ] HTTPS enforced (reverse proxy and app settings).
- [ ] Security headers enabled (HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy).
- [ ] Secure cookies (SESSION_COOKIE_SECURE, CSRF_COOKIE_SECURE).
- [ ] CSRF trusted origins set for production domains.
- [ ] Admin access restricted (IP allowlist or VPN).
- [ ] Dependency vulnerability scan run and reviewed.
- [ ] File upload limits set and validated.
- [ ] Sensitive logs redacted.

## Data & Database
- [ ] Production database configured (MySQL/Postgres, or sqlite only if acceptable).
- [ ] Database user has least privilege.
- [ ] Backups configured and tested.
- [ ] Migrations applied in production.
- [ ] Tenant DB provisioning verified (creation, migration, access).

## Availability & Reliability
- [ ] Gunicorn/uWSGI configured with proper workers.
- [ ] Reverse proxy configured (Nginx/Apache).
- [ ] Health check endpoint defined and monitored.
- [ ] Error monitoring enabled (Sentry or similar).
- [ ] Logging shipped to centralized store.

## Performance & Speed
- [ ] Static files served by CDN or Nginx.
- [ ] WhiteNoise verified for production if used.
- [ ] Database indexes reviewed for key queries.
- [ ] Caching configured where needed.
- [ ] Load test run for core flows.

## Background Jobs
- [ ] Celery broker configured (Redis/RabbitMQ).
- [ ] Celery worker and beat configured and monitored.
- [ ] Task retry and timeout policies validated.

## Assets & Media
- [ ] MEDIA storage configured for production (object storage or volume).
- [ ] collectstatic run and verified.
- [ ] Media access controls validated.

## API & Tenant Isolation
- [ ] Tenant resolution enforced for API routes.
- [ ] API access flags enforced per tenant.
- [ ] Rate limiting configured for API.
- [ ] Authentication and authorization reviewed.

## Operational
- [ ] .env or secrets manager configured in deployment pipeline.
- [ ] CI/CD pipeline runs tests and migrations safely.
- [ ] Rollback plan documented.
- [ ] Versioned releases tagged.
- [ ] Monitoring dashboards configured.

## Tests
- [ ] Critical flows covered (sales, inventory updates, reports).
- [ ] Tenant isolation tests pass.
- [ ] Smoke tests run in staging.
