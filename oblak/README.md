# Oblak

A platform for running user-provided Python code on a server (FaaS, in the style of
AWS Lambda or Google Cloud Functions). The user uploads code through the CDK CLI
client to the server, which stores, verifies and prepares it and exposes it via a
URL. Execution happens in an isolated Firecracker MicroVM.

## Repository structure

```
oblak/
├── README.md                      # this file
├── .gitignore
├── dokumentacija/
│   ├── 01_bezbednosni_zahtevi.md  # system analysis and security requirements (M1)
│   ├── 02_threat_model_STRIDE.md  # DFD, threat model, STRIDE (M1)
│   └── 03_skladistenje_verifikacija.md  # storage, verification, preparation (M2)
├── server/                        # FastAPI server (M1: auth, upload, audit)
│   ├── app/
│   │   ├── main.py                # entrypoint, security headers
│   │   ├── config.py              # configuration from env (no hard-coded secrets)
│   │   ├── database.py
│   │   ├── models.py
│   │   ├── schemas.py
│   │   ├── security.py            # Argon2 hashing and JWT (HMAC-SHA256)
│   │   ├── audit.py               # audit logging mechanism (non-repudiation)
│   │   ├── rate_limit.py          # login brute-force protection
│   │   ├── storage.py             # safe intake and storage (zip-slip, integrity)
│   │   ├── deps.py                # authentication (Bearer token)
│   │   ├── code_verifier.py       # 4-stage code verification (M2)
│   │   ├── preparation.py         # isolated dependency/artifact preparation (M2)
│   │   └── routers/
│   │       ├── auth.py
│   │       ├── functions.py
│   │       └── verification.py    # verify + invoke-URL endpoints (M2)
│   ├── tests/                     # pytest: auth and upload (benign and malicious)
│   ├── seed.sql                   # schema and seed (instead of a front-end)
│   ├── requirements.txt
│   └── .env.example
├── cli/                           # CDK CLI (M1, Typer)
│   ├── cdk/
│   │   ├── main.py
│   │   ├── config.py
│   │   ├── api_client.py
│   │   └── packaging.py
│   └── requirements.txt
└── examples/
    ├── hello_function/            # benign example function
    └── evil_function/             # malicious example (must be REJECTED)
```

The Code Storage, Code Verifier and Preparation/URL components (member 2) live in
`code_verifier.py`, `preparation.py` and `routers/verification.py`. The Firecracker
execution (member 3) is wired into `GET /invoke/{token}`, which is currently a
placeholder returning 503.

> Note: the design documents in `dokumentacija/` are written in Serbian (the course
> language); only this README is in English.

## Running the server

```bash
cd server
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
# Generate a strong JWT secret and put it into .env:
python -c "import secrets; print('OBLAK_JWT_SECRET=' + secrets.token_urlsafe(48))"

uvicorn app.main:app --reload
# API docs: http://127.0.0.1:8000/docs
```

Schema note: the server creates tables on startup but does not run migrations.
If the data model changes (for example new columns), delete the local
`server/oblak.db` and restart so a fresh schema is created. Proper migrations
(for example Alembic) are an open item.

## Using the CDK CLI

```bash
cd cli
pip install -r requirements.txt

python -m cdk.main configure --server http://127.0.0.1:8000
python -m cdk.main register -u vuk
python -m cdk.main login -u vuk
python -m cdk.main deploy ../examples/hello_function --name hello   # uploads + verifies
python -m cdk.main list
```

The token is stored in `~/.oblak/credentials.json` with `0600` permissions
(requirement ZR-K3).

`cdk deploy` uploads the code and then automatically runs the verification pipeline
(antivirus, static analysis, LLM, dependency preparation), printing the resulting
status and invoke URL. Use `--no-verify` to upload only, and `cdk verify --name NAME`
to run it later. The `POST /functions/{name}/verify` endpoint also remains available
for direct re-verification.

## Tests and static analysis

```bash
cd server
pip install -r requirements.txt
pytest -q                 # auth, upload and verification tests
bandit -r app             # static security analysis of the code
```

The suite covers auth, upload (incl. zip-slip and rate-limit) and the full
verification pipeline (benign and malicious code).

## What is done (member 1)

Phase 1 of the application lifecycle:

- Security analysis: requirements (whole system and VM isolation), threat model and
  STRIDE analysis mapped to mitigations (`dokumentacija/`).
- CDK CLI: `configure`, `register`, `login`, `logout`, `deploy`, `list`, `whoami`,
  with locally stored credentials using restrictive permissions.
- Server (auth, upload, audit):
  - registration with Argon2id password hashing (ZR-A2),
  - login issuing a JWT (HMAC-SHA256) with an expiry, fail-closed signature
    verification (ZR-A3, A4),
  - login rate limiting (ZR-A5),
  - code upload with size and type validation and protection against zip-slip and
    path-traversal attacks (ZR-V2, V3),
  - audit mechanism: append-only JSON log and DB table, no sensitive data, with UTC
    timestamps (ZR-L1 to L4),
  - secrets sourced only from the environment (ZR-K2), security HTTP headers, no
    stack-trace leakage (T6).
- Data model and API contract that members 2 and 3 build on.

Threats this phase directly addresses: T1 to T9 (see the STRIDE table).

## What is done (member 2)

Phase 2 of the application lifecycle:

- Storage hardening: SHA-256 integrity check, source extraction with renewed
  zip-slip protection, per-user isolation (`storage.py`).
- Code Verifier: four stages - ClamAV antivirus, Bandit static analysis (rejects
  HIGH severity), AST scan of forbidden imports/calls, and LLM behavioural analysis
  (`code_verifier.py`). ClamAV and the LLM degrade gracefully when unavailable.
- Preparation: requirements.txt validation against supply-chain tricks and an
  isolated venv built with `--no-cache-dir` and an explicit PyPI index
  (`preparation.py`).
- Invoke URL: a unique, hard-to-guess token per function; `GET /invoke/{token}` is a
  placeholder for member 3.
- Documentation in `dokumentacija/03_skladistenje_verifikacija.md` and tests in
  `server/tests/test_verification.py`.

Threats this phase addresses: T10 to T14 (see the STRIDE table).

## Next phases

Member 3 adds Firecracker execution (wiring `GET /invoke/{token}`), isolation
hardening, the malicious test suite for execution, and the final documentation.
