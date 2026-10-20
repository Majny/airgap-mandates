"""Lambda entry for executor/tools: executor.handler.lambda_handler plus CloudWatch lines for every botocore
ClientError (operation + error code + message, never request payloads), and the explained ops log (executor.oplog:
one line per audit leaf / refused request, a traceback + error_id per 500; plain text, no colour). Owner: WS-E."""
from __future__ import annotations

from typing import Any

import botocore.exceptions as _bex

_init = _bex.ClientError.__init__


def _logged_init(self: Any, error_response: dict, operation_name: str) -> None:
    _init(self, error_response, operation_name)
    err = (error_response or {}).get("Error", {})
    if err.get("Code") not in ("ConditionalCheckFailedException", "TransactionCanceledException"):
        print(f"AIRGAP_CLIENT_ERROR op={operation_name} code={err.get('Code')} msg={str(err.get('Message'))[:300]}")


_bex.ClientError.__init__ = _logged_init

try:  # cold start; never fail the function over logging
    from executor import oplog

    oplog.configure()
except Exception as _e:  # noqa: BLE001
    print(f"AIRGAP_OPLOG_DISABLED {type(_e).__name__}: {_e}"[:300])


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    from executor.handler import lambda_handler

    return lambda_handler(event, context)
