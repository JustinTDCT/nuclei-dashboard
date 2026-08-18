import os
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

DATA_DIR = Path(os.environ.get("AGENT_DATA_DIR", "/data"))
PRIV_PATH = DATA_DIR / "agent.key"
PUB_PATH = DATA_DIR / "agent.pub"


def load_or_create_keypair() -> tuple[Ed25519PrivateKey, str]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if PRIV_PATH.exists():
        private = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(PRIV_PATH.read_text().strip()))
    else:
        private = Ed25519PrivateKey.generate()
        PRIV_PATH.write_text(private.private_bytes_raw().hex())
        PRIV_PATH.chmod(0o600)
    public_hex = private.public_key().public_bytes_raw().hex()
    PUB_PATH.write_text(public_hex)
    return private, public_hex


def sign(private: Ed25519PrivateKey, message: str) -> str:
    return private.sign(message.encode()).hex()
