from __future__ import annotations

import copy
import threading

import pytest

from mapit.aws_durable_tenants import DynamoDBTenantStore
from mapit.durable_tenants import DurableTenantError, DurableTenantRecord

TABLE = "arn:aws:dynamodb:eu-west-1:123456789012:table/honda-mapit-mcp-dev-tenants"
A, B = "tenant-" + "a" * 64, "tenant-" + "b" * 64
OK = {"ResponseMetadata": {"HTTPStatusCode": 200}}


class Conflict(Exception):
    response = {"Error": {"Code": "ConditionalCheckFailedException"},
                "ResponseMetadata": {"HTTPStatusCode": 400}}


class MemoryClient:
    def __init__(self):
        self.items = {}
        self.calls = []
        self.lock = threading.Lock()

    def get_item(self, **request):
        assert request["TableName"] == TABLE
        assert request["ConsistentRead"] is True
        assert request["ReturnConsumedCapacity"] == "NONE"
        with self.lock:
            self.calls.append(("get", request))
            item = self.items.get(request["Key"]["key"]["S"])
            return dict(OK, **({"Item": copy.deepcopy(item)} if item else {}))

    def put_item(self, **request):
        assert request["TableName"] == TABLE
        assert request["ReturnValues"] == "NONE"
        with self.lock:
            self.calls.append(("put", request))
            item = request["Item"]
            prior = self.items.get(item["key"]["S"])
            values = request.get("ExpressionAttributeValues")
            if values is None:
                if prior is not None:
                    raise Conflict()
            else:
                if prior is None or prior["revision"] != values[":revision"]:
                    raise Conflict()
                allowed = [values[":active"]] + ([values[":revoked"]] if ":revoked" in values else [])
                if prior["status"] not in allowed:
                    raise Conflict()
            self.items[item["key"]["S"]] = copy.deepcopy(item)
            return dict(OK)


def store(client, *, writable=True):
    return DynamoDBTenantStore(client, table_arn=TABLE, allowed_keys=(A, B),
                               writer=client if writable else None)


def test_strong_read_cas_and_terminal_revocation_across_instances():
    client = MemoryClient()
    first, reopened = store(client), store(client)
    assert first.get(A) is None
    assert first.cas(A, None, DurableTenantRecord(A, "active", 1))
    assert reopened.get(A) == DurableTenantRecord(A, "active", 1)
    assert not reopened.cas(A, None, DurableTenantRecord(A, "active", 1))
    assert reopened.cas(A, 1, DurableTenantRecord(A, "revoked", 2))
    assert not first.cas(A, 2, DurableTenantRecord(A, "active", 3))
    assert first.get(A).status == "revoked"
    assert reopened.cas(B, None, DurableTenantRecord(B, "active", 1))
    assert first.get(B).status == "active"


def test_two_workers_have_one_atomic_cas_winner():
    client = MemoryClient()
    first, second = store(client), store(client)
    assert first.cas(A, None, DurableTenantRecord(A, "active", 1))
    barrier, results = threading.Barrier(2), []
    def worker(selected):
        barrier.wait()
        results.append(selected.cas(A, 1, DurableTenantRecord(A, "revoked", 2)))
    workers = [threading.Thread(target=worker, args=(selected,)) for selected in (first, second)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join(timeout=2)
    assert all(not thread.is_alive() for thread in workers)
    assert sorted(results) == [False, True]


def test_unknown_key_and_readonly_writer_denied_before_client():
    client = MemoryClient()
    selected = store(client, writable=False)
    with pytest.raises(DurableTenantError):
        selected.get("tenant-" + "c" * 64)
    with pytest.raises(DurableTenantError):
        selected.cas(A, None, DurableTenantRecord(A, "active", 1))
    assert client.calls == []


@pytest.mark.parametrize("item", [
    {"key": {"S": B}, "status": {"S": "active"}, "revision": {"N": "1"}},
    {"key": {"S": A}, "status": {"S": "active"}, "revision": {"N": "1.0"}},
    {"key": {"S": A}, "status": {"S": "active"}, "revision": {"N": "0"}},
    {"key": {"S": A}, "status": {"S": "bad"}, "revision": {"N": "1"}},
    {"key": {"S": A}, "status": {"S": "active"}, "revision": {"N": "1"}, "secret": {"S": "canary"}},
])
def test_malformed_rows_fail_closed_without_raw_output(item):
    client = MemoryClient()
    client.items[A] = item
    with pytest.raises(DurableTenantError, match="^durable_store_failed$") as caught:
        store(client).get(A)
    assert "canary" not in str(caught.value) and A not in str(caught.value)


def test_ambiguous_writer_failure_has_one_attempt_and_safe_category():
    client = MemoryClient()
    calls = []
    class FailedWriter:
        def put_item(self, **request):
            calls.append(request)
            raise TimeoutError("private canary")
    selected = DynamoDBTenantStore(client, table_arn=TABLE, allowed_keys=(A,), writer=FailedWriter())
    with pytest.raises(DurableTenantError, match="^durable_store_failed$"):
        selected.cas(A, None, DurableTenantRecord(A, "active", 1))
    assert len(calls) == 1


@pytest.mark.parametrize("table,keys", [
    (TABLE.replace("eu-west-1", "us-east-1"), (A,)),
    (TABLE.replace("dev-tenants", "prod-tenants"), (A,)),
    (TABLE, (A, A)), (TABLE, ()),
    (TABLE, tuple("tenant-" + f"{number:064x}" for number in range(17))),
])
def test_fixed_dev_table_and_bounded_operator_allowlist(table, keys):
    with pytest.raises(DurableTenantError, match="durable_configuration_invalid"):
        DynamoDBTenantStore(MemoryClient(), table_arn=table, allowed_keys=keys)
