# MHcheck Multi-Tenant Deployment and Credentials Rotation Guide

This document describes how to deploy the multi-tenant posture auditing platform and manage credentials rotation for MSP (Managed Service Providers) scenarios.

---

## 1. Multi-Tenant Architecture

MHcheck stores all user accounts, inventory assets, CVE caches, and audit records in a single database defined by `MHCHECK_DB_PATH` (defaults to `audit_history.db`). 

- **Tenant Scoping**: Every user belongs to a `tenant` (e.g. `default`, `client_a`, `client_b`). When listing or managing assets or checking audit history, results are automatically filtered by the current user's tenant context.
- **Role Permissions (RBAC)**:
  - `admin`: Can execute posture audits, manage all tenant assets, manage system users, view dashboards, and edit system configuration.
  - `auditor`: Can execute audits, manage tenant assets, and view dashboards.
  - `viewer`: Can view dashboards and reports (read-only).

---

## 2. Deploying a Multi-Tenant Environment

To deploy a multi-tenant environment under Docker:

1. **Build the container**:
   ```bash
   docker compose build
   ```

2. **Configure Environment Variables**:
   In your production deployment environment or `.env` file, specify:
   ```env
   # Enable auth wall in the dashboard
   MHCHECK_AUTH_ENABLED=true
   
   # Shared database location
   MHCHECK_DB_PATH=/app/data/audit_history.db
   
   # Secret key used to sign and verify Streamlit browser session cookies
   MHCHECK_SECRET_KEY=yoursupersecretproductionkeyhere
   ```

3. **Bootstrap the Admin User**:
   Before launching the services, set these temporary environment variables to seed the first admin account:
   ```env
   MHCHECK_ADMIN_USER=admin
   MHCHECK_ADMIN_PASSWORD=yoursecurepassword
   ```
   On initial boot, MHcheck will automatically create this user. Once booted, you can unset these environment variables.

4. **Start the Stack**:
   ```bash
   docker compose up -d
   ```
   This will spin up three hardened containers:
   - `mhcheck-dashboard`: Streamlit UI on port `8501`.
   - `mhcheck-api`: Headless REST API on port `8000`.
   - `mhcheck-scheduler`: Background fleet scheduler daemon auditing assets on a fixed interval.

---

## 3. Creating Tenant Accounts and Assets

Administrators can use the `cyber user create` and `cyber asset add` CLI commands inside the container or via the UI to set up tenants:

```bash
# Create a user for a new client (Tenant: client_acme)
docker exec -it mhcheck python cli.py user create acme_auditor --role auditor --tenant client_acme

# Register assets under that client tenant
docker exec -it mhcheck python cli.py asset add "Acme Public Domain" "acme.org" --type domain --tenant client_acme
```

---

## 4. Credentials and Secrets Rotation

### A. Rotating the Session Secret Key (`MHCHECK_SECRET_KEY`)
When rotating `MHCHECK_SECRET_KEY`:
1. Change the value in your deployment's environment settings.
2. Restart the containers (`docker compose restart`).
3. *Note*: This will instantly invalidate all active Streamlit browser sessions, requiring all users to log in again.

### B. Rotating Shodan and HIBP API Keys
1. **Shodan Key**: Store the new key in the `SHODAN_API_KEY` environment variable (the configuration file `config.json` is a deprecated fallback). Update the environment variable and restart the containers.
2. **HaveIBeenPwned Key**: Update the `HIBP_API_KEY` environment variable and restart.
