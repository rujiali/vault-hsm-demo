# Vault HSM Demo

Demonstrates **Encryption as a Service** and **HSM integration** using:
- HashiCorp Vault Enterprise
- SoftHSM2 (PKCS#11 simulated HSM)

## What this demo shows

- Vault auto-unsealing via HSM (PKCS#11)
- Transit engine for encryption as a service
- Key never exposed to applications
- Key rotation with backward compatibility
- Separation of duties via Vault policies

## Prerequisites

- Docker + Docker Compose
- Vault Enterprise license

## Setup

```bash
# 1. Copy env file and add your license key
cp .env.example .env
# Edit .env and set VAULT_LICENSE=<your-license>

# 2. Start the stack
docker-compose up -d

# 3. Initialise Vault
./scripts/init.sh
```

## Run the demo

```bash
./scripts/demo.sh
```

## Architecture

```
App → Vault Transit (Encryption as a Service)
              ↓
         PKCS#11
              ↓
          SoftHSM (master key lives here, never exported)
```
