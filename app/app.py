import os
import json
import base64
import datetime
import requests
from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://vault-main:8200")
RECORDS_FILE = "/app/data/records.json"


def vault_req(method, path, token, data=None):
    url = f"{VAULT_ADDR}/v1/{path}"
    headers = {"X-Vault-Token": token}
    token_display = token[:8] + "..." if len(token) > 8 else token

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


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    resp, status, curl = vault_req("GET", "sys/seal-status", "")
    if status != 200:
        return jsonify({"error": resp, "curl": curl}), status

    seal_type = resp.get("type", "unknown")
    if seal_type == "transit":
        seal_type = "transit (vault-hsm as root of trust)"

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
        if not records:
            return jsonify({"allowed": False, "error": "No records to decrypt", "curl": ""})
        ciphertext = records[0]["ciphertext"]
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


@app.route("/api/export-key", methods=["POST"])
def api_export_key():
    body = request.get_json()
    token = body.get("token", "")
    key_name = body.get("key_name", "demo-key-managed")
    resp, status, curl = vault_req("GET", f"transit/export/encryption-key/{key_name}", token)
    if status == 200:
        return jsonify({"allowed": True, "data": resp.get("data", {}), "curl": curl})
    # Check for control group wrap token
    wrap_token = resp.get("wrap_info", {}).get("token", "") if isinstance(resp, dict) else ""
    if wrap_token:
        return jsonify({"allowed": False, "control_group": True, "wrap_token": wrap_token, "curl": curl})
    errors = resp.get("errors", ["Permission denied"]) if isinstance(resp, dict) else ["Permission denied"]
    return jsonify({"allowed": False, "control_group": False, "error": errors[0], "curl": curl}), status


@app.route("/api/control-group/approve", methods=["POST"])
def api_cg_approve():
    body = request.get_json()
    custodian_token = body.get("custodian_token", "")
    wrap_token = body.get("wrap_token", "")
    resp, status, curl = vault_req("POST", "sys/control-group/authorize", custodian_token, {"token": wrap_token})
    allowed = status == 200
    return jsonify({"allowed": allowed, "error": resp.get("errors", [None])[0] if not allowed and isinstance(resp, dict) else None, "curl": curl})


@app.route("/api/control-group/unwrap", methods=["POST"])
def api_cg_unwrap():
    body = request.get_json()
    requestor_token = body.get("requestor_token", "")
    wrap_token = body.get("wrap_token", "")
    resp, status, curl = vault_req("POST", "sys/wrapping/unwrap", requestor_token, {"token": wrap_token})
    allowed = status == 200
    return jsonify({"allowed": allowed, "data": resp.get("data", {}) if allowed else None, "error": resp.get("errors", [None])[0] if not allowed and isinstance(resp, dict) else None, "curl": curl})


@app.route("/api/delete-key", methods=["POST"])
def api_delete_key():
    body = request.get_json()
    token = body.get("token", "")
    key_name = body.get("key_name", "demo-key-managed")
    resp, status, curl = vault_req("DELETE", f"transit/keys/{key_name}", token)
    allowed = status in (200, 204)
    errors = resp.get("errors", ["Permission denied"]) if isinstance(resp, dict) else []
    return jsonify({"allowed": allowed, "error": errors[0] if errors else None, "curl": curl})


@app.route("/api/custodian-login", methods=["POST"])
def api_custodian_login():
    body = request.get_json()
    password = body.get("password", "custodian123")
    resp, status, curl = vault_req("POST", "auth/userpass/login/custodian", "", {"password": password})
    if status == 200:
        return jsonify({"token": resp.get("auth", {}).get("client_token", ""), "curl": curl})
    return jsonify({"error": "Login failed", "curl": curl}), status


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
