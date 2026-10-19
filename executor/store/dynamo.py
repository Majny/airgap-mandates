"""DynamoDB Store backend (boto3; moto in tests). Implements CONTRACTS.md v2 §3.1–§3.3 (real DynamoDB in the demo,
moto in CI). Convert Decimal -> int at this boundary.

Entities of the single table `main` get pk = "<MAIN_PK_PREFIX>#<id>" and sk = str(<sort attr>) (or "0"); both are
stripped again on read (except a natural sort attribute that is itself called "sk"). AWS_ENDPOINT_URL is honoured
by boto3 itself.

Owner: WS-A.
"""
from __future__ import annotations

from decimal import Decimal
from typing import Any

import boto3
from boto3.dynamodb.types import TypeDeserializer, TypeSerializer
from botocore.exceptions import ClientError

from executor import config
from executor.store import INDEXES, KEY_SCHEMA, MISSING, AnyOf, IncrementBounded, Put, UpdateIf

_SER = TypeSerializer()
_DESER = TypeDeserializer()


def _to_native(v: Any) -> Any:
    if isinstance(v, Decimal):
        return int(v) if v == v.to_integral_value() else float(v)
    if isinstance(v, dict):
        return {k: _to_native(x) for k, x in v.items()}
    if isinstance(v, list):
        return [_to_native(x) for x in v]
    if isinstance(v, set):
        return {_to_native(x) for x in v}
    return v


def _ser(item: dict[str, Any]) -> dict[str, Any]:
    return {k: _SER.serialize(v) for k, v in item.items()}


def _deser(item: dict[str, Any]) -> dict[str, Any]:
    return {k: _to_native(_DESER.deserialize(v)) for k, v in item.items()}


class _Expr:
    """Collects ExpressionAttributeNames / Values placeholders."""

    def __init__(self) -> None:
        self.names: dict[str, str] = {}
        self.values: dict[str, Any] = {}

    def n(self, attr: str) -> str:
        for ph, a in self.names.items():
            if a == attr:
                return ph
        ph = f"#n{len(self.names)}"
        self.names[ph] = attr
        return ph

    def v(self, value: Any) -> str:
        ph = f":v{len(self.values)}"
        self.values[ph] = _SER.serialize(value)
        return ph

    def expect(self, expect: dict[str, Any]) -> list[str]:
        clauses = []
        for attr, want in expect.items():
            alts = []
            for a in (want.values if isinstance(want, AnyOf) else (want,)):
                alts.append(f"attribute_not_exists({self.n(attr)})" if a is MISSING else f"{self.n(attr)} = {self.v(a)}")
            clauses.append(alts[0] if len(alts) == 1 else "(" + " OR ".join(alts) + ")")
        return clauses

    def kwargs(self, condition: list[str] | None = None) -> dict[str, Any]:
        out: dict[str, Any] = {}
        if condition:
            out["ConditionExpression"] = " AND ".join(condition)
        if self.names:
            out["ExpressionAttributeNames"] = dict(self.names)
        if self.values:
            out["ExpressionAttributeValues"] = dict(self.values)
        return out


class _Impossible(Exception):
    """An IncrementBounded whose increment alone exceeds its bound (condition can never hold)."""


class DynamoStore:
    """Implements executor.store.Store."""

    def __init__(self, settings: Any, client: Any = None) -> None:
        self.settings = settings
        self.client = client or boto3.client("dynamodb", region_name=settings.aws_region)

    # ------------------------------------------------------------ key mapping

    def _tn(self, table: str) -> str:
        return config.physical_table(self.settings, table)

    @staticmethod
    def _is_main(table: str) -> bool:
        return config.LOGICAL_TABLES[table] == "main"

    def _pkey(self, table: str, key: dict[str, Any]) -> dict[str, Any]:
        """Natural key -> physical key (plain dict, not serialised)."""
        pk, sk = KEY_SCHEMA[table]
        if self._is_main(table):
            return {"pk": f"{config.MAIN_PK_PREFIX[table]}#{key[pk]}", "sk": "0" if sk is None else str(key[sk])}
        return {pk: key[pk]} if sk is None else {pk: key[pk], sk: key[sk]}

    def _to_item(self, table: str, item: dict[str, Any]) -> dict[str, Any]:
        return _ser({**item, **self._pkey(table, item)}) if self._is_main(table) else _ser(item)

    def _from_item(self, table: str, raw: dict[str, Any]) -> dict[str, Any]:
        item = _deser(raw)
        if self._is_main(table):
            item.pop("pk", None)
            if KEY_SCHEMA[table][1] != "sk":
                item.pop("sk", None)
        return item

    def _settable(self, table: str, key: dict[str, Any], set_: dict[str, Any]) -> dict[str, Any]:
        """Attributes to SET in an update: never physical key attrs; in `main` also the natural key attrs."""
        phys = set(self._pkey(table, key))
        out = {k: v for k, v in key.items() if k not in phys} if self._is_main(table) else {}
        out.update({k: v for k, v in set_.items() if k not in phys})
        return out

    # ------------------------------------------------------------ op builders

    def _put_params(self, op: Put) -> dict[str, Any]:
        e = _Expr()
        cond = [f"attribute_not_exists({e.n(op.if_absent_key)})"] if op.if_absent_key else None
        return {"TableName": self._tn(op.table), "Item": self._to_item(op.table, op.item), **e.kwargs(cond)}

    def _update_params(self, op: UpdateIf | IncrementBounded) -> dict[str, Any]:
        e = _Expr()
        cond = e.expect(op.expect)
        parts = []
        if isinstance(op, UpdateIf):
            sets = self._settable(op.table, op.key, op.set_)
        else:
            sets = self._settable(op.table, op.key, {})
            adds = [f"{e.n(a)} {e.v(by)}" for a, by in op.by.items()]
            parts.append("ADD " + ", ".join(adds))
            for attr, limit in op.max_after.items():
                room = limit - int(op.by.get(attr, 0))
                if room < 0:
                    raise _Impossible
                cond.append(f"(attribute_not_exists({e.n(attr)}) OR {e.n(attr)} <= {e.v(room)})")
        if sets:
            parts.insert(0, "SET " + ", ".join(f"{e.n(a)} = {e.v(v)}" for a, v in sets.items()))
        if not parts:
            raise ValueError(f"empty update on {op.table}")
        return {"TableName": self._tn(op.table), "Key": _ser(self._pkey(op.table, op.key)),
                "UpdateExpression": " ".join(parts), **e.kwargs(cond)}

    @staticmethod
    def _code(err: ClientError) -> str:
        return err.response.get("Error", {}).get("Code", "")

    # ------------------------------------------------------------ Store API

    def get(self, table: str, key: dict[str, Any]) -> dict[str, Any] | None:
        resp = self.client.get_item(TableName=self._tn(table), Key=_ser(self._pkey(table, key)), ConsistentRead=True)
        return self._from_item(table, resp["Item"]) if "Item" in resp else None

    def put(self, table: str, item: dict[str, Any]) -> None:
        self.client.put_item(**self._put_params(Put(table, item)))

    def put_if_absent(self, table: str, item: dict[str, Any], key_attr: str) -> bool:
        try:
            self.client.put_item(**self._put_params(Put(table, item, if_absent_key=key_attr)))
            return True
        except ClientError as err:
            if self._code(err) == "ConditionalCheckFailedException":
                return False
            raise

    def update_if(self, table: str, key: dict[str, Any], set_: dict[str, Any], expect: dict[str, Any]) -> bool:
        try:
            self.client.update_item(**self._update_params(UpdateIf(table, key, set_, expect)))
            return True
        except ClientError as err:
            if self._code(err) == "ConditionalCheckFailedException":
                return False
            raise

    def increment(self, table: str, key: dict[str, Any], attr: str, by: int = 1) -> int:
        params = self._update_params(IncrementBounded(table, key, {attr: by}))
        resp = self.client.update_item(**params, ReturnValues="ALL_NEW")
        return int(_to_native(_DESER.deserialize(resp["Attributes"][attr])))

    def query(self, table: str, pk: tuple[str, Any], index: str | None = None, sk_range: tuple[Any, Any] | None = None,
              limit: int | None = None, reverse: bool = False) -> list[dict[str, Any]]:
        attr, value = pk
        main = self._is_main(table)
        e = _Expr()
        filt: str | None = None
        if index is None:
            hash_attr, range_attr = KEY_SCHEMA[table]
            if attr != hash_attr:
                raise ValueError(f"query on {table}: partition attr is {hash_attr!r}, not {attr!r}")
            if main:
                key_cond = f"{e.n('pk')} = {e.v(f'{config.MAIN_PK_PREFIX[table]}#{value}')}"
                range_phys = "sk" if range_attr is not None else None
                conv = str
            else:
                key_cond = f"{e.n(attr)} = {e.v(value)}"
                range_phys = range_attr
                conv = (lambda x: x)
        else:
            hash_attr, range_attr = INDEXES[(table, index)]
            if attr != hash_attr:
                raise ValueError(f"query on {table}/{index}: partition attr is {hash_attr!r}, not {attr!r}")
            key_cond = f"{e.n(attr)} = {e.v(value)}"
            range_phys, conv = range_attr, (lambda x: x)
            if main:
                filt = f"begins_with({e.n('pk')}, {e.v(config.MAIN_PK_PREFIX[table] + '#')})"
        if sk_range is not None and range_phys is not None:
            lo, hi = sk_range
            key_cond += f" AND {e.n(range_phys)} BETWEEN {e.v(conv(lo))} AND {e.v(conv(hi))}"
        params: dict[str, Any] = {"TableName": self._tn(table), "KeyConditionExpression": key_cond,
                                  "ScanIndexForward": not reverse, **e.kwargs()}
        if index is not None:
            params["IndexName"] = index
        else:
            params["ConsistentRead"] = True
        if filt is not None:
            params["FilterExpression"] = filt
        elif limit is not None:
            params["Limit"] = limit
        out: list[dict[str, Any]] = []
        while True:
            resp = self.client.query(**params)
            out.extend(self._from_item(table, it) for it in resp.get("Items", []))
            if (limit is not None and len(out) >= limit) or "LastEvaluatedKey" not in resp:
                break
            params["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
        return out if limit is None else out[:limit]

    def scan(self, table: str) -> list[dict[str, Any]]:
        e = _Expr()
        params: dict[str, Any] = {"TableName": self._tn(table), "ConsistentRead": True}
        if self._is_main(table):
            params["FilterExpression"] = f"begins_with({e.n('pk')}, {e.v(config.MAIN_PK_PREFIX[table] + '#')})"
            params.update(e.kwargs())
        out: list[dict[str, Any]] = []
        while True:
            resp = self.client.scan(**params)
            out.extend(self._from_item(table, it) for it in resp.get("Items", []))
            if "LastEvaluatedKey" not in resp:
                return out
            params["ExclusiveStartKey"] = resp["LastEvaluatedKey"]

    def transact(self, ops: list[Any], client_request_token: str | None = None) -> bool:
        items: list[dict[str, Any]] = []
        try:
            for op in ops:
                if isinstance(op, Put):
                    items.append({"Put": self._put_params(op)})
                else:
                    items.append({"Update": self._update_params(op)})
        except _Impossible:
            return False
        kwargs: dict[str, Any] = {"TransactItems": items}
        if client_request_token is not None:
            kwargs["ClientRequestToken"] = client_request_token
        try:
            self.client.transact_write_items(**kwargs)
            return True
        except ClientError as err:
            code = self._code(err)
            if code == "IdempotentParameterMismatchException":
                from executor.store import IdempotencyMismatch

                raise IdempotencyMismatch(f"ClientRequestToken {client_request_token} reused with other parameters") from err
            if code == "TransactionCanceledException":
                reasons = err.response.get("CancellationReasons") or []
                if any(r.get("Code") == "ConditionalCheckFailed" for r in reasons):
                    return False
                if not reasons and "ConditionalCheckFailed" in str(err):
                    return False
            raise


def create_tables(settings: Any, client: Any = None) -> None:
    """Create every PHYSICAL_TABLES table (on-demand) with its GSIs; existing tables are left alone."""
    client = client or boto3.client("dynamodb", region_name=settings.aws_region)

    def gsi(name: str, h: tuple[str, str], r: tuple[str, str]) -> dict[str, Any]:
        return {"IndexName": name, "KeySchema": [{"AttributeName": h[0], "KeyType": "HASH"},
                                                 {"AttributeName": r[0], "KeyType": "RANGE"}],
                "Projection": {"ProjectionType": "ALL"}}

    specs: dict[str, tuple[list[tuple[str, str]], list[dict[str, Any]], list[tuple[str, str]]]] = {
        # physical: (key attrs [(name, type)], gsis, extra attribute definitions)
        "ledger": ([("tx_id", "S")], [gsi("by_vendor", ("vendor_id", "S"), ("executed_at", "S"))],
                   [("vendor_id", "S"), ("executed_at", "S")]),
        "mandates": ([("mandate_id", "S")], [gsi("by_status", ("status", "S"), ("mandate_no", "N"))],
                     [("status", "S"), ("mandate_no", "N")]),
        "audit": ([("log_id", "S"), ("seq", "N")], [], []),
        "registry": ([("vendor_id", "S")], [], []),
        "witness_state": ([("origin", "S")], [], []),
        "main": ([("pk", "S"), ("sk", "S")], [gsi("gsi1", ("gsi1pk", "S"), ("gsi1sk", "S"))],
                 [("gsi1pk", "S"), ("gsi1sk", "S")]),
        "portal": ([("ico", "S"), ("notif_id", "S")], [], []),
    }
    existing = set(client.list_tables().get("TableNames", []))
    for phys in config.PHYSICAL_TABLES:
        name = f"{settings.table_prefix}{phys}"
        if name in existing:
            continue
        keys, gsis, extra = specs[phys]
        params: dict[str, Any] = {
            "TableName": name,
            "BillingMode": "PAY_PER_REQUEST",
            "KeySchema": [{"AttributeName": a, "KeyType": "HASH" if i == 0 else "RANGE"} for i, (a, _) in
                          enumerate(keys)],
            "AttributeDefinitions": [{"AttributeName": a, "AttributeType": t} for a, t in keys + extra],
        }
        if gsis:
            params["GlobalSecondaryIndexes"] = gsis
        client.create_table(**params)
    for phys in config.PHYSICAL_TABLES:
        client.get_waiter("table_exists").wait(TableName=f"{settings.table_prefix}{phys}")
