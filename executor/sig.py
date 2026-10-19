"""EIP-191 personal_sign verification (pure). CONTRACTS.md v2 §6, §4.3 step 5. Owner: WS-C."""
from __future__ import annotations


def verify_eip191(text: str, sig: str) -> str:
    """Recovered lowercase address for `sig` ('0x' + 130 hex) over `text`; raises ValueError on a bad signature.
    eth_account.Account.recover_message(encode_defunct(text=text), signature=sig).lower()."""
    raise NotImplementedError("TODO WS-C")
