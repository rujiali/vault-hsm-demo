# Vault HSM Demo

Demonstrates **Encryption as a Service** and **HSM integration** using two HashiCorp Vault Enterprise instances:

- `vault-hsm` — acts as the root of trust (mimics an HSM via Vault Transit seal)
- `vault-main` — auto-unseals via `vault-hsm`, runs the Transit EaaS engine for applications

## What this demo shows

- Vault auto-unsealing via Transit seal (HSM pattern — master key never leaves vault-hsm)
- Transit engine for Encryption as a Service
- Encryption key never exposed to applications
- Key rotation with backward compatibility
- Separation of duties via Vault policies

## Prerequisites

- Docker + Docker Compose
- HashiCorp Vault Enterprise license
- `vault` CLI installed locally

## Setup

```bash
# 1. Copy env file and add your license key
cp .env.example .env
# Edit .env and set VAULT_LICENSE=<your-license>

# 2. Start vault-hsm
docker compose up -d vault-hsm

# 3. Bootstrap vault-hsm (init, unseal, create Transit key, write token to .env)
./scripts/init-hsm.sh

# 4. Start vault-main (picks up VAULT_HSM_TOKEN from .env)
docker compose up -d vault-main

# 5. Initialise vault-main (auto-unseals via vault-hsm Transit seal)
./scripts/init.sh
```

## Run the demo

```bash
./scripts/demo.sh
```

## Architecture

```
App → vault-main (Transit EaaS)
              ↓  Transit seal
         vault-hsm (root of trust)
         master key lives here, never exported
```

| Instance  | Port | Role |
|-----------|------|------|
| vault-hsm  | 8201 | HSM mimic — holds master key via Transit seal |
| vault-main | 8200 | Application-facing — Encryption as a Service |
