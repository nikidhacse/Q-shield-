# Q-Shield Backend

**Automated Crypto-Agility Auditing and Quantum-Risk Prioritization for Legacy Infrastructure**

Q-Shield helps organizations identify cryptographic technologies in their infrastructure, assess quantum migration risk, prioritize assets for migration, and generate actionable recommendations.

> **Security Note:** Q-Shield does NOT perform destructive testing, password cracking, exploitation, or unauthorized network attacks.

---

## Table of Contents

- [Technology Stack](#technology-stack)
- [Project Structure](#project-structure)
- [Quick Start – Local Development](#quick-start--local-development)
- [Quick Start – Docker](#quick-start--docker)
- [Environment Variables](#environment-variables)
- [Database Migrations](#database-migrations)
- [Demo Seed Data](#demo-seed-data)
- [Running Tests](#running-tests)
- [API Endpoints](#api-endpoints)
- [Sample API Responses](#sample-api-responses)
- [Roles & Permissions](#roles--permissions)

---

## Technology Stack

| Component | Technology |
|-----------|-----------|
| Runtime | Python 3.12 |
| Framework | FastAPI 0.115 |
| Validation | Pydantic v2 |
| ORM | SQLAlchemy 2.0 |
| Database | PostgreSQL 16 |
| Migrations | Alembic |
| Auth | JWT (python-jose + passlib/bcrypt) |
| API Docs | Swagger / OpenAPI (built-in) |
| Testing | Pytest + SQLite in-memory |
| Container | Docker + Docker Compose |

---

## Project Structure

```
qshield-backend/
├── app/
│   ├── main.py              ← FastAPI application entry point
│   ├── core/
│   │   ├── config.py        ← Settings from .env
│   │   ├── database.py      ← SQLAlchemy engine & session
│   │   └── security.py      ← JWT, bcrypt, auth dependencies
│   ├── models/              ← SQLAlchemy ORM models
│   ├── schemas/             ← Pydantic request/response schemas
│   ├── api/routes/          ← FastAPI routers (one per domain)
│   ├── services/            ← Business logic services
│   └── utils/               ← Shared utilities
├── tests/                   ← Pytest test suite (SQLite in-memory)
├── alembic/                 ← Database migration scripts
├── scripts/
│   └── seed_demo.py         ← Demo data seeder (AcmeCorp scenario)
├── requirements.txt
├── .env.example
├── Dockerfile
├── docker-compose.yml
└── README.md
```

---

## Quick Start – Local Development

### Prerequisites

- Python 3.12+
- PostgreSQL 16 running locally

### Steps

```bash
# 1. Clone and enter the project
cd "Q-Shield Backend"

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate   # Windows
# source venv/bin/activate   # macOS/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure environment
copy .env.example .env
# Edit .env with your PostgreSQL credentials

# 5. Create the database
# In psql or pgAdmin:
#   CREATE USER qshield_user WITH PASSWORD 'qshield_password';
#   CREATE DATABASE qshield_db OWNER qshield_user;

# 6. Run database migrations
alembic upgrade head

# 7. Seed demo data
python scripts/seed_demo.py

# 8. Start the development server
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

Open: http://localhost:8000/docs

---

## Quick Start – Docker

```bash
# 1. Copy environment file
copy .env.example .env

# 2. Start all services (PostgreSQL + API)
docker-compose up -d

# 3. Run migrations inside container
docker-compose exec api alembic upgrade head

# 4. Seed demo data
docker-compose exec api python scripts/seed_demo.py
```

Open: http://localhost:8000/docs

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `APP_ENV` | Environment name | `development` |
| `SECRET_KEY` | JWT signing secret (change in production!) | — |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql://...` |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | JWT expiry | `60` |
| `ALLOWED_ORIGINS` | CORS origins (comma-separated) | `http://localhost:3000,...` |
| `LOG_LEVEL` | Logging level | `INFO` |

---

## Database Migrations

```bash
# Apply all pending migrations
alembic upgrade head

# Create a new migration (after changing models)
alembic revision --autogenerate -m "describe your change"

# Roll back one migration
alembic downgrade -1

# View migration history
alembic history --verbose
```

---

## Demo Seed Data

The seed script creates a fictional **AcmeCorp** scenario with:

- **3 users** (admin, analyst, viewer)
- **12 assets** (applications, databases, services, network devices)
- **12 scans** (various types and statuses)
- **18 crypto findings** (RSA, 3DES, DES, MD5, ECDSA, DH, AES, SHA-1, etc.)
- **4 certificates** (including expiring-soon scenarios)
- **10 risk scores** (with transparent factor breakdown)
- **8 migration plans** (various statuses from NOT_STARTED to COMPLETED)

```bash
python scripts/seed_demo.py
```

**Demo credentials:**

| Role | Email | Password |
|------|-------|----------|
| Admin | admin@acmecorp.example.com | Admin@12345 |
| Analyst | analyst@acmecorp.example.com | Analyst@12345 |
| Viewer | viewer@acmecorp.example.com | Viewer@12345 |

---

## Running Tests

Tests use **SQLite in-memory** – no PostgreSQL required.

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=app --cov-report=term-missing

# Run a specific test file
pytest tests/test_auth.py -v
```

---

## API Endpoints

### Authentication
| Method | Path | Description | Auth Required |
|--------|------|-------------|---------------|
| POST | `/api/auth/register` | Register new user | No |
| POST | `/api/auth/login` | Login, get JWT token | No |
| GET | `/api/auth/me` | Current user profile | Yes |

### Assets
| Method | Path | Description | Min Role |
|--------|------|-------------|----------|
| GET | `/api/assets` | List all assets | viewer |
| POST | `/api/assets` | Create asset | analyst |
| GET | `/api/assets/{id}` | Get asset | viewer |
| PUT | `/api/assets/{id}` | Update asset | analyst |
| DELETE | `/api/assets/{id}` | Delete asset | admin |

### Scans
| Method | Path | Description | Min Role |
|--------|------|-------------|----------|
| GET | `/api/scans` | List scans | viewer |
| POST | `/api/scans` | Create scan | analyst |
| GET | `/api/scans/{id}` | Get scan | viewer |
| POST | `/api/scans/{id}/start` | Start scan | analyst |

### Crypto Findings
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/crypto/findings` | List findings (filterable) |
| GET | `/api/crypto/findings/{id}` | Get finding detail |
| PATCH | `/api/crypto/findings/{id}` | Mark false-positive / add notes |

### Risk
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/risk/summary` | Portfolio risk overview |
| GET | `/api/risk/assets` | All asset risk scores |
| GET | `/api/risk/assets/{asset_id}` | Asset risk score |

### Migration
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/migration/roadmap` | Full migration roadmap |
| POST | `/api/migration/plans` | Create migration plan |
| PUT | `/api/migration/plans/{id}` | Update plan status |

### Reports & Dashboard
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/reports/summary` | Portfolio summary report |
| GET | `/api/dashboard/overview` | Frontend dashboard data |
| GET | `/health` | Service health check |

---

## Sample API Responses

### Dashboard Overview
```json
{
  "total_assets": 12,
  "scanned_assets": 10,
  "critical_assets": 5,
  "high_risk_assets": 7,
  "crypto_findings": 18,
  "quantum_vulnerable_assets": 8,
  "migration_in_progress": 2,
  "risk_distribution": {
    "LOW": 0,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 5
  },
  "top_priority_assets": [
    {
      "asset_id": 4,
      "asset_name": "Legacy Payment Gateway",
      "asset_type": "service",
      "criticality": "CRITICAL",
      "risk_score": 95.0,
      "risk_level": "CRITICAL"
    }
  ]
}
```

### JWT Login Response
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "expires_in": 3600
}
```

---

## Roles & Permissions

| Endpoint Action | viewer | security_analyst | admin |
|----------------|--------|-----------------|-------|
| Read assets / scans / findings | ✅ | ✅ | ✅ |
| Create / update assets | ❌ | ✅ | ✅ |
| Create / start scans | ❌ | ✅ | ✅ |
| Create migration plans | ❌ | ✅ | ✅ |
| Delete assets | ❌ | ❌ | ✅ |
| Mark false positives | ❌ | ✅ | ✅ |

---

## What's Coming in Phase 2

- Real crypto detection engine (source code AST analysis)
- Certificate file upload and parsing
- Risk engine with automated scoring
- Priority engine
- Recommendation engine
- Async scan execution (Celery/RQ)
- Background scheduler for periodic scans
