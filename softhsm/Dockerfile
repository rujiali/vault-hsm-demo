FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    softhsm2 \
    opensc \
    && rm -rf /var/lib/apt/lists/*

# Initialise SoftHSM token
RUN softhsm2-util --init-token --slot 0 --label "vault-hsm" \
    --pin 1234 --so-pin 1234

# Expose PKCS#11 library path via shared volume
VOLUME ["/var/lib/softhsm/tokens", "/var/run/pkcs11"]

CMD ["tail", "-f", "/dev/null"]
