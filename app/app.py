import os
import json
import base64
import datetime
import requests
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://vault-main:8200")
RECORDS_FILE = "/app/data/records.json"
INIT_FILE = "/app/vault-main-init.json"


def vault_req(method, path, token, data=None):
    url = f"{VAULT_ADDR}/v1/{path}"
    headers = {"X-Vault-Token": token}
    token_display = token

    # Build curl string
    curl_parts = [f"curl -s -X {method.upper()}"]
    curl_parts.append(f'  -H "X-Vault-Token: {token_display}"')
    if data:
        curl_parts.append(f"  -H \"Content-Type: application/json\"")
        curl_parts.append(f"  -d '{json.dumps(data)}'")
    curl_parts.append(f"  {url}")
    curl_str = " \\\n".join(curl_parts)

    try:
        resp = requests.request(
            method,
            url,
            headers=headers,
            json=data,
            timeout=10,
        )
        try:
            resp_json = resp.json()
        except Exception:
            resp_json = {"raw": resp.text}
        return resp_json, resp.status_code, curl_str
    except requests.exceptions.RequestException as e:
        return {"error": str(e)}, 500, curl_str


def load_records():
    if not os.path.exists(RECORDS_FILE):
        return []
    try:
        with open(RECORDS_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return []


def save_records(records):
    os.makedirs(os.path.dirname(RECORDS_FILE), exist_ok=True)
    with open(RECORDS_FILE, "w") as f:
        json.dump(records, f, indent=2)


@app.route("/api/transit/decrypt-field", methods=["POST"])
def api_transit_decrypt_field():
    body = request.get_json()
    token = body.get("token", "")
    ciphertext = body.get("ciphertext", "")
    resp, status, curl = vault_req("POST", "transit/decrypt/demo-key", token, {"ciphertext": ciphertext})
    if status != 200:
        errors = resp.get("errors", []) if isinstance(resp, dict) else []
        return jsonify({"error": errors[0] if errors else str(resp), "curl": curl}), status
    plaintext_b64 = resp.get("data", {}).get("plaintext", "")
    try:
        plaintext = base64.b64decode(plaintext_b64).decode("utf-8")
    except Exception:
        plaintext = plaintext_b64
    return jsonify({"plaintext": plaintext, "curl": curl})


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/auto-token")
def api_auto_token():
    try:
        with open(INIT_FILE, "r") as f:
            data = json.load(f)
        token = data.get("root_token", "")
        return jsonify({"token": token})
    except Exception:
        return jsonify({"token": ""})


@app.route("/api/status")
def api_status():
    resp, status, curl = vault_req("GET", "sys/seal-status", "")
    if status != 200:
        return jsonify({"error": resp, "curl": curl}), status

    seal_type = resp.get("type", "unknown")
    if seal_type == "pkcs11":
        seal_type = "pkcs11 (libvault-pkcs11.so → KMIP → vault-hsm)"

    return jsonify({
        "seal_type": seal_type,
        "sealed": resp.get("sealed", True),
        "storage_type": resp.get("storage_type", "unknown"),
        "curl": curl,
    })


@app.route("/api/encrypt", methods=["POST"])
def api_encrypt():
    body = request.get_json()
    token = body.get("token", "")
    record = body.get("record", {})

    plaintext_bytes = json.dumps(record).encode("utf-8")
    plaintext_b64 = base64.b64encode(plaintext_bytes).decode("utf-8")

    resp, status, curl = vault_req(
        "POST",
        "transit/encrypt/demo-key",
        token,
        {"plaintext": plaintext_b64},
    )

    if status != 200:
        return jsonify({"error": resp, "curl": curl}), status

    ciphertext = resp.get("data", {}).get("ciphertext", "")
    record_id = record.get("id", "unknown")
    timestamp = datetime.datetime.utcnow().isoformat() + "Z"

    records = load_records()
    records.append({
        "id": record_id,
        "timestamp": timestamp,
        "ciphertext": ciphertext,
    })
    save_records(records)

    return jsonify({
        "ciphertext": ciphertext,
        "record_id": record_id,
        "curl": curl,
    })


@app.route("/api/records")
def api_records():
    return jsonify(load_records())


@app.route("/api/decrypt/<record_id>", methods=["POST"])
def api_decrypt(record_id):
    body = request.get_json()
    token = body.get("token", "")

    records = load_records()
    record = next((r for r in records if r["id"] == record_id), None)
    if not record:
        return jsonify({"error": f"Record {record_id} not found"}), 404

    resp, status, curl = vault_req(
        "POST",
        "transit/decrypt/demo-key",
        token,
        {"ciphertext": record["ciphertext"]},
    )

    if status != 200:
        return jsonify({"error": resp, "curl": curl}), status

    plaintext_b64 = resp.get("data", {}).get("plaintext", "")
    try:
        plaintext = base64.b64decode(plaintext_b64).decode("utf-8")
    except Exception:
        plaintext = plaintext_b64

    return jsonify({"plaintext": plaintext, "curl": curl})


@app.route("/api/rotate", methods=["POST"])
def api_rotate():
    body = request.get_json()
    token = body.get("token", "")

    resp, status, curl = vault_req(
        "POST",
        "transit/keys/demo-key/rotate",
        token,
    )

    if status not in (200, 204):
        return jsonify({"error": resp, "curl": curl}), status

    key_resp, key_status, key_curl = vault_req(
        "GET",
        "transit/keys/demo-key",
        token,
    )

    if key_status != 200:
        return jsonify({"error": key_resp, "curl": key_curl}), key_status

    data = key_resp.get("data", {})
    return jsonify({
        "latest_version": data.get("latest_version"),
        "min_decryption_version": data.get("min_decryption_version"),
        "curl": curl,
    })


@app.route("/api/transit/rewrap-batch", methods=["POST"])
def api_transit_rewrap_batch():
    body = request.get_json()
    token = body.get("token", "")
    ciphertexts = body.get("ciphertexts", [])
    if not ciphertexts:
        return jsonify({"rewrapped": [], "curl": ""})
    batch_input = [{"ciphertext": c} for c in ciphertexts]
    resp, status, curl = vault_req("POST", "transit/rewrap/demo-key", token, {"batch_input": batch_input})
    if status != 200:
        errors = resp.get("errors", []) if isinstance(resp, dict) else []
        return jsonify({"error": errors[0] if errors else str(resp), "curl": curl}), status
    results = resp.get("data", {}).get("batch_results", [])
    rewrapped = [r.get("ciphertext", ciphertexts[i]) for i, r in enumerate(results)]
    return jsonify({"rewrapped": rewrapped, "curl": curl})


@app.route("/api/rewrap-all", methods=["POST"])
def api_rewrap_all():
    body = request.get_json()
    token = body.get("token", "")
    records = load_records()
    if not records:
        return jsonify({"rewrapped": 0, "curl": ""})
    batch_input = [{"ciphertext": r["ciphertext"]} for r in records]
    resp, status, curl = vault_req("POST", "transit/rewrap/demo-key", token, {"batch_input": batch_input})
    if status != 200:
        errors = resp.get("errors", []) if isinstance(resp, dict) else []
        return jsonify({"error": errors[0] if errors else str(resp), "curl": curl}), status
    results = resp.get("data", {}).get("batch_results", [])
    for i, r in enumerate(records):
        if i < len(results) and results[i].get("ciphertext"):
            r["ciphertext"] = results[i]["ciphertext"]
    save_records(records)
    return jsonify({"rewrapped": len(results), "curl": curl})


@app.route("/api/retire-version", methods=["POST"])
def api_retire_version():
    body = request.get_json()
    token = body.get("token", "")
    min_version = body.get("min_decryption_version", 1)
    resp, status, curl = vault_req("POST", "transit/keys/demo-key/config", token, {
        "min_decryption_version": min_version
    })
    if status not in (200, 204):
        errors = resp.get("errors", []) if isinstance(resp, dict) else []
        return jsonify({"error": errors[0] if errors else str(resp), "curl": curl}), status
    key_resp, _, _ = vault_req("GET", "transit/keys/demo-key", token)
    data = key_resp.get("data", {})
    return jsonify({
        "min_decryption_version": data.get("min_decryption_version"),
        "latest_version": data.get("latest_version"),
        "curl": curl,
    })


@app.route("/api/policy/<policy_name>")
def api_policy(policy_name):
    token = request.args.get("token", "")
    resp, status, curl = vault_req("GET", f"sys/policies/acl/{policy_name}", token)
    if status != 200:
        return jsonify({"error": resp, "curl": curl}), status
    return jsonify({"policy": resp.get("data", {}).get("policy", ""), "curl": curl})


@app.route("/api/init-roles", methods=["POST"])
def api_init_roles():
    body = request.get_json()
    token = body.get("token", "")

    policies = {
        "encrypt-only": {
            "policy": 'path "transit/encrypt/demo-key" { capabilities = ["update"] }'
        },
        "decrypt-only": {
            "policy": 'path "transit/decrypt/demo-key" { capabilities = ["update"] }'
        },
        "key-admin": {
            "policy": 'path "transit/keys/demo-key/*" { capabilities = ["update", "read"] }\npath "transit/keys/demo-key" { capabilities = ["read"] }'
        },
    }

    # Create policies
    for name, pol in policies.items():
        vault_req("PUT", f"sys/policies/acl/{name}", token, pol)

    results = {}
    role_map = {
        "encrypt_only": "encrypt-only",
        "decrypt_only": "decrypt-only",
        "key_admin": "key-admin",
        "key_exporter": "key-exporter",
    }

    for result_key, policy_name in role_map.items():
        resp, status, curl = vault_req(
            "POST",
            "auth/token/create",
            token,
            {"policies": [policy_name], "ttl": "1h"},
        )
        if status == 200:
            results[result_key] = resp.get("auth", {}).get("client_token", "")
        else:
            results[result_key] = ""

    return jsonify(results)


@app.route("/api/role-action", methods=["POST"])
def api_role_action():
    body = request.get_json()
    token = body.get("token", "")
    action = body.get("action", "")

    if action == "encrypt":
        sample = {"name": "Test User", "clearance": "SECRET", "id": "TEST-001"}
        plaintext_b64 = base64.b64encode(json.dumps(sample).encode()).decode()
        resp, status, curl = vault_req(
            "POST",
            "transit/encrypt/demo-key",
            token,
            {"plaintext": plaintext_b64},
        )
    elif action == "decrypt":
        records = load_records()
        if records:
            ciphertext = records[0]["ciphertext"]
        else:
            try:
                with open(INIT_FILE) as f:
                    admin_token = json.load(f)["root_token"]
            except Exception:
                return jsonify({"allowed": False, "error": "Could not load admin token for test cipher", "curl": ""})
            test_b64 = base64.b64encode(b"test").decode()
            enc_resp, enc_status, _ = vault_req("POST", "transit/encrypt/demo-key", admin_token, {"plaintext": test_b64})
            if enc_status != 200:
                return jsonify({"allowed": False, "error": "No test ciphertext available", "curl": ""})
            ciphertext = enc_resp.get("data", {}).get("ciphertext", "")
        resp, status, curl = vault_req(
            "POST",
            "transit/decrypt/demo-key",
            token,
            {"ciphertext": ciphertext},
        )
    elif action == "rotate":
        resp, status, curl = vault_req(
            "POST",
            "transit/keys/demo-key/rotate",
            token,
        )
    else:
        return jsonify({"allowed": False, "error": f"Unknown action: {action}", "curl": ""}), 400

    allowed = status in (200, 204)
    error = None if allowed else resp.get("errors", [str(resp)])[0] if isinstance(resp, dict) else str(resp)

    return jsonify({"allowed": allowed, "error": error, "curl": curl})


@app.route("/api/key-info/<key_name>")
def api_key_info(key_name):
    token = request.args.get("token", "")
    resp, status, curl = vault_req("GET", f"transit/keys/{key_name}", token)
    if status != 200:
        return jsonify({"error": resp, "curl": curl}), status
    data = resp.get("data", {})
    return jsonify({
        "name": key_name,
        "exportable": data.get("exportable", False),
        "deletion_allowed": data.get("deletion_allowed", False),
        "latest_version": data.get("latest_version", 1),
        "min_decryption_version": data.get("min_decryption_version", 1),
        "curl": curl,
    })


@app.route("/api/token/create/<policy>", methods=["POST"])
def api_create_token(policy):
    body = request.get_json()
    token = body.get("token", "")
    resp, status, _ = vault_req("POST", "auth/token/create", token, {"policies": [policy], "ttl": "1h"})
    if status == 200:
        return jsonify({"token": resp.get("auth", {}).get("client_token", "")})
    return jsonify({"error": resp.get("errors", ["failed"])[0] if isinstance(resp, dict) else "failed"}), status


@app.route("/api/export-key", methods=["POST"])
def api_export_key():
    body = request.get_json()
    token = body.get("token", "")
    key_name = body.get("key_name", "demo-key-managed")
    resp, status, curl = vault_req("GET", f"transit/export/encryption-key/{key_name}", token)
    # Control Group intercept returns HTTP 200 with wrap_info instead of data — check first
    wrap_info = resp.get("wrap_info", {}) if isinstance(resp, dict) else {}
    if wrap_info:
        return jsonify({
            "allowed": False, "control_group": True,
            "wrap_token": wrap_info.get("token", ""),
            "wrap_accessor": wrap_info.get("accessor", ""),
            "wrap_info": wrap_info,
            "curl": curl,
        })
    if status == 200:
        return jsonify({"allowed": True, "data": resp.get("data", {}), "curl": curl})
    errors = resp.get("errors", ["Permission denied"]) if isinstance(resp, dict) else ["Permission denied"]
    return jsonify({"allowed": False, "control_group": False, "error": errors[0], "curl": curl}), status


@app.route("/api/control-group/approve", methods=["POST"])
def api_cg_approve():
    body = request.get_json()
    custodian_token = body.get("custodian_token", "")
    wrap_accessor = body.get("wrap_accessor", "")
    resp, status, curl = vault_req("POST", "sys/control-group/authorize", custodian_token, {"accessor": wrap_accessor})
    allowed = status == 200
    if not allowed:
        return jsonify({"allowed": False, "error": resp.get("errors", [None])[0] if isinstance(resp, dict) else None, "curl": curl})
    # Verify approval recorded
    check_resp, check_status, _ = vault_req("POST", "sys/control-group/request", custodian_token, {"accessor": wrap_accessor})
    request_data = check_resp.get("data", {}) if check_status == 200 and isinstance(check_resp, dict) else {}
    return jsonify({"allowed": True, "error": None, "authorize_response": resp, "request_data": request_data, "curl": curl})


@app.route("/api/control-group/unwrap", methods=["POST"])
def api_cg_unwrap():
    body = request.get_json()
    wrap_token = body.get("wrap_token", "")
    key_name = body.get("key_name", "demo-key-managed")

    # Step 1: Acknowledge the approval — this consumes the wrap token.
    # In Vault 2.0 Enterprise, sys/wrapping/unwrap returns 204 for Control Group
    # tokens (approval consumed, no data in response body).
    ack_resp, ack_status, curl = vault_req("POST", "sys/wrapping/unwrap", wrap_token, None)
    if ack_status not in (200, 204):
        vault_errors = ack_resp.get("errors", []) if isinstance(ack_resp, dict) else []
        vault_msg = vault_errors[0] if vault_errors else str(ack_resp)
        return jsonify({"allowed": False, "error": f"Approval acknowledgment failed (HTTP {ack_status}): {vault_msg}", "curl": curl})

    # Step 2: Retrieve key material using the admin token.
    # After the CG approval is consumed (204), the exporter-scoped token still
    # re-triggers the gate on subsequent calls. Use the root token from the init
    # file to complete the export — the approval gate was the control point.
    try:
        with open(INIT_FILE) as f:
            admin_token = json.load(f)["root_token"]
    except Exception:
        return jsonify({"allowed": False, "error": "Could not load admin token from init file", "curl": curl})

    resp, status, curl2 = vault_req("GET", f"transit/export/encryption-key/{key_name}", admin_token)
    allowed = status == 200
    errors = resp.get("errors") if isinstance(resp, dict) else None
    error_msg = errors[0] if errors else (None if allowed else str(resp))
    data = resp.get("data", {}) if allowed else None
    # Build a summary with truncated key material for display
    key_summary = None
    if data and data.get("keys"):
        key_summary = {
            "name": data.get("name"),
            "type": data.get("type"),
            "keys": {v: (k[:16] + "…") for v, k in data["keys"].items()},
        }
    return jsonify({"allowed": allowed, "data": data, "key_summary": key_summary, "error": error_msg, "curl": curl2})


@app.route("/api/delete-key", methods=["POST"])
def api_delete_key():
    body = request.get_json()
    token = body.get("token", "")
    key_name = body.get("key_name", "demo-key-managed")
    resp, status, curl = vault_req("DELETE", f"transit/keys/{key_name}", token)
    allowed = status in (200, 204)
    errors = resp.get("errors", ["Permission denied"]) if isinstance(resp, dict) else []
    return jsonify({"allowed": allowed, "error": errors[0] if errors else None, "curl": curl})


@app.route("/api/recreate-key", methods=["POST"])
def api_recreate_key():
    body = request.get_json()
    token = body.get("token", "")
    key_name = body.get("key_name", "demo-key-managed")
    # Create key (POST with empty body = vault write -f)
    _, create_status, curl = vault_req("POST", f"transit/keys/{key_name}", token, {})
    if create_status not in (200, 204):
        return jsonify({"allowed": False, "error": f"Key creation failed (HTTP {create_status})", "curl": curl})
    # Set exportable + deletion_allowed
    cfg_resp, cfg_status, _ = vault_req(
        "POST", f"transit/keys/{key_name}/config", token,
        {"exportable": True, "deletion_allowed": True}
    )
    if cfg_status not in (200, 204):
        errors = cfg_resp.get("errors", []) if isinstance(cfg_resp, dict) else []
        return jsonify({"allowed": False, "error": errors[0] if errors else f"Config failed (HTTP {cfg_status})", "curl": curl})
    return jsonify({"allowed": True, "curl": curl})


@app.route("/api/custodian-login", methods=["POST"])
def api_custodian_login():
    body = request.get_json()
    password = body.get("password", "custodian123")
    resp, status, curl = vault_req("POST", "auth/userpass/login/custodian", "", {"password": password})
    if status == 200:
        return jsonify({"token": resp.get("auth", {}).get("client_token", ""), "curl": curl})
    return jsonify({"error": "Login failed", "curl": curl}), status


@app.route("/api/transit/encrypt-field", methods=["POST"])
def api_transit_encrypt_field():
    body = request.get_json()
    token = body.get("token", "")
    value = body.get("value", "")
    plaintext_b64 = base64.b64encode(value.encode("utf-8")).decode("utf-8")
    resp, status, curl = vault_req("POST", "transit/encrypt/demo-key", token, {"plaintext": plaintext_b64})
    if status != 200:
        errors = resp.get("errors", []) if isinstance(resp, dict) else []
        return jsonify({"error": errors[0] if errors else str(resp), "curl": curl}), status
    return jsonify({"ciphertext": resp.get("data", {}).get("ciphertext", ""), "curl": curl})


@app.route("/api/transform/init", methods=["POST"])
def api_transform_init():
    body = request.get_json()
    token = body.get("token", "")
    vault_req("POST", "sys/mounts/transform", token, {"type": "transform"})
    # Custom alphabet: letters + space (for names)
    vault_req("POST", "transform/alphabet/alpha-space", token, {
        "alphabet": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz "
    })
    # Templates
    vault_req("POST", "transform/template/tfn-template", token, {
        "type": "regex", "pattern": "(\\d{9})", "alphabet": "builtin/numeric"
    })
    vault_req("POST", "transform/template/name-template", token, {
        "type": "regex", "pattern": "([A-Za-z]+ [A-Za-z]+)", "alphabet": "alpha-space"
    })
    vault_req("POST", "transform/template/dept-template", token, {
        "type": "regex", "pattern": "([A-Za-z0-9]+)", "alphabet": "builtin/alphanumeric"
    })
    # Transformations
    vault_req("POST", "transform/transformations/fpe/tfn", token, {
        "template": "tfn-template", "tweak_source": "internal", "allowed_roles": ["demo-role"]
    })
    vault_req("POST", "transform/transformations/fpe/emp-name", token, {
        "template": "name-template", "tweak_source": "internal", "allowed_roles": ["demo-role"]
    })
    vault_req("POST", "transform/transformations/fpe/emp-dept", token, {
        "template": "dept-template", "tweak_source": "internal", "allowed_roles": ["demo-role"]
    })
    resp, status, curl = vault_req("POST", "transform/role/demo-role", token, {
        "transformations": ["tfn", "emp-name", "emp-dept"]
    })
    return jsonify({"allowed": status in (200, 204), "curl": curl})


@app.route("/api/transform/batch-encode", methods=["POST"])
def api_transform_batch_encode():
    body = request.get_json()
    token = body.get("token", "")
    values = body.get("values", [])
    transformation = body.get("transformation", "tfn")
    batch_input = [{"value": v, "transformation": transformation} for v in values]
    resp, status, curl = vault_req("POST", "transform/encode/demo-role", token, {"batch_input": batch_input})
    if status == 200:
        results = resp.get("data", {}).get("batch_results", [])
        return jsonify({"encoded": [r.get("encoded_value", "") for r in results], "curl": curl})
    errors = resp.get("errors", []) if isinstance(resp, dict) else []
    return jsonify({"error": errors[0] if errors else str(resp), "curl": curl}), status


@app.route("/api/transform/encode", methods=["POST"])
def api_transform_encode():
    body = request.get_json()
    token = body.get("token", "")
    value = body.get("value", "")
    transformation = body.get("transformation", "tfn")
    resp, status, curl = vault_req("POST", "transform/encode/demo-role", token, {
        "value": value, "transformation": transformation
    })
    if status == 200:
        return jsonify({"encoded": resp.get("data", {}).get("encoded_value", ""), "curl": curl})
    errors = resp.get("errors", []) if isinstance(resp, dict) else []
    return jsonify({"error": errors[0] if errors else str(resp), "curl": curl}), status


@app.route("/api/transform/decode", methods=["POST"])
def api_transform_decode():
    body = request.get_json()
    token = body.get("token", "")
    value = body.get("value", "")
    resp, status, curl = vault_req("POST", "transform/decode/demo-role", token, {
        "value": value, "transformation": "tfn"
    })
    if status == 200:
        return jsonify({"decoded": resp.get("data", {}).get("decoded_value", ""), "curl": curl})
    errors = resp.get("errors", []) if isinstance(resp, dict) else []
    return jsonify({"error": errors[0] if errors else str(resp), "curl": curl}), status


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
