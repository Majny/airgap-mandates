"""EIP-191 personal_sign verification (pure). CONTRACTS.md v2 §6, §4.3 step 5. Owner: WS-C."""
from __future__ import annotations

import re

from eth_account import Account
from eth_account.messages import encode_defunct

_SIG_RE = re.compile(r"^(0x)?[0-9a-fA-F]{130}$")


def verify_eip191(text: str, sig: str) -> str:
    """Recovered lowercase address for `sig` ('0x' + 130 hex) over `text`; raises ValueError on a bad signature.
    eth_account.Account.recover_message(encode_defunct(text=text), signature=sig).lower()."""
    if not isinstance(text, str) or not isinstance(sig, str):
        raise ValueError("text and sig must be str")
    if not _SIG_RE.match(sig):
        raise ValueError("signature must be 65 bytes hex")
    try:
        text.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("text must be ASCII (the device only ever signs canonical ASCII)") from None
    raw = bytes.fromhex(sig[2:] if sig.startswith("0x") else sig)
    if raw[64] in (0, 1):  # some signers emit v in {0,1}; EIP-191 recovery expects {27,28}
        raw = raw[:64] + bytes([raw[64] + 27])
    if raw[64] not in (27, 28):
        raise ValueError("signature v must be 27 or 28")
    try:
        addr = Account.recover_message(encode_defunct(text=text), signature=raw)
    except Exception as e:  # eth_keys raises BadSignature / ValidationError on malformed r, s
        raise ValueError(f"bad signature: {e}") from None
    return addr.lower()
