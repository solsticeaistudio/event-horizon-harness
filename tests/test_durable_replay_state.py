import multiprocessing
import queue
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from event_horizon.broker import CapabilityBroker, CapabilityError, CapabilityVerifier
from event_horizon.models import ActionRequest, IssuedCapability
from event_horizon.replay_state import (
    CapabilityConsumptionError,
    SqliteCapabilityConsumptionStore,
)
from scripts.capability_fixture_support import authority_context, issue_options, verify_options


FIXED_NOW = 1_767_225_600.0


def _replica_consume(
    database_path,
    public_key_pem,
    key_id,
    capability_payload,
    request_payload,
    options,
    start_event,
    results,
):
    store = None
    try:
        store = SqliteCapabilityConsumptionStore(
            database_path,
            namespace="replica-test",
            domain="broker",
            busy_timeout_ms=10_000,
        )
        verifier = CapabilityVerifier(public_key_pem, key_id, store)
        capability = IssuedCapability.from_dict(capability_payload)
        request = ActionRequest.from_dict(request_payload)
        start_event.wait(timeout=10)
        verifier.verify_and_consume(capability, request, now=FIXED_NOW, **options)
        results.put("accepted")
    except CapabilityError as exc:
        results.put("replay" if "replay detected" in str(exc) else f"denied:{exc}")
    except Exception as exc:
        results.put(f"error:{type(exc).__name__}:{exc}")
    finally:
        if store is not None:
            store.close()


def capability_fixture():
    request = ActionRequest(
        request_id="durable-request",
        session_id="durable-session",
        agent_id="durable-agent",
        operation="object.read",
        resource_id="durable-object",
        executor_id="durable-executor",
        arguments={"length": 32, "offset": 0},
        purpose="durable replay regression",
    )
    broker = CapabilityBroker(
        b"durable-capability-signing-seed!",
        ttl_seconds=60,
        consumption_store=SqliteCapabilityConsumptionStore(
            Path(tempfile.mkdtemp(prefix="eh-signer-replay-")) / "replay.sqlite3",
            namespace="signing",
            domain="authority-broker",
        ),
    )
    authority = authority_context(request, FIXED_NOW)
    options = verify_options(authority)
    capability = broker.issue(
        request,
        max_output_bytes=1024,
        now=FIXED_NOW,
        **issue_options(authority),
    )
    return broker, request, capability, options


class DurableReplayStateTests(unittest.TestCase):
    def test_capability_consumption_survives_restart(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "replay.sqlite3"
            broker, request, capability, options = capability_fixture()
            first = SqliteCapabilityConsumptionStore(
                database, namespace="restart-test", domain="executor:durable-executor"
            )
            CapabilityVerifier(broker.public_key_pem, broker.key_id, first).verify_and_consume(
                capability, request, now=FIXED_NOW, **options
            )
            first.close()

            second = SqliteCapabilityConsumptionStore(
                database, namespace="restart-test", domain="executor:durable-executor"
            )
            with self.assertRaisesRegex(CapabilityError, "replay detected"):
                CapabilityVerifier(broker.public_key_pem, broker.key_id, second).verify_and_consume(
                    capability, request, now=FIXED_NOW, **options
                )
            second.close()

    def test_concurrent_broker_replicas_accept_exactly_one_redemption(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "replay.sqlite3"
            broker, request, capability, options = capability_fixture()
            initializer = SqliteCapabilityConsumptionStore(
                database, namespace="replica-test", domain="broker"
            )
            initializer.close()
            context = multiprocessing.get_context("spawn")
            start_event = context.Event()
            results = context.Queue()
            processes = [
                context.Process(
                    target=_replica_consume,
                    args=(
                        str(database),
                        broker.public_key_pem,
                        broker.key_id,
                        capability.to_dict(),
                        request.canonical_payload(),
                        options,
                        start_event,
                        results,
                    ),
                )
                for _ in range(16)
            ]
            for process in processes:
                process.start()
            start_event.set()
            for process in processes:
                process.join(timeout=20)
                if process.is_alive():
                    process.terminate()
                    process.join(timeout=5)
                self.assertEqual(process.exitcode, 0)
            outcomes = []
            for _ in processes:
                try:
                    outcomes.append(results.get(timeout=5))
                except queue.Empty:
                    self.fail("a capability replica returned no result")
            self.assertEqual(outcomes.count("accepted"), 1)
            self.assertEqual(outcomes.count("replay"), 15)

    def test_broker_and_executor_domains_each_consume_once(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "replay.sqlite3"
            source_broker, request, capability, options = capability_fixture()
            broker_store = SqliteCapabilityConsumptionStore(
                database, namespace="domain-test", domain="broker"
            )
            broker = CapabilityBroker(
                b"durable-capability-signing-seed!",
                ttl_seconds=60,
                consumption_store=broker_store,
            )
            broker.verify_and_consume(capability, request, now=FIXED_NOW, **options)
            executor_store = SqliteCapabilityConsumptionStore(
                database,
                namespace="domain-test",
                domain="executor:durable-executor",
            )
            verifier = CapabilityVerifier(
                source_broker.public_key_pem,
                source_broker.key_id,
                executor_store,
            )
            verifier.verify_and_consume(capability, request, now=FIXED_NOW, **options)
            with self.assertRaisesRegex(CapabilityError, "replay detected"):
                verifier.verify_and_consume(capability, request, now=FIXED_NOW, **options)
            broker_store.close()
            executor_store.close()

    def test_namespaces_are_isolated_and_must_be_configured_consistently(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "replay.sqlite3"
            broker, request, capability, options = capability_fixture()
            for namespace in ("population-a", "population-b"):
                store = SqliteCapabilityConsumptionStore(
                    database, namespace=namespace, domain="broker"
                )
                CapabilityVerifier(broker.public_key_pem, broker.key_id, store).verify_and_consume(
                    capability, request, now=FIXED_NOW, **options
                )
                store.close()

    def test_closed_corrupt_and_colliding_state_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "replay.sqlite3"
            broker, request, capability, options = capability_fixture()
            closed = SqliteCapabilityConsumptionStore(
                database, namespace="failure-test", domain="broker"
            )
            closed.close()
            with self.assertRaisesRegex(CapabilityError, "state unavailable"):
                CapabilityVerifier(broker.public_key_pem, broker.key_id, closed).verify_and_consume(
                    capability, request, now=FIXED_NOW, **options
                )

            collision = SqliteCapabilityConsumptionStore(
                database, namespace="collision-test", domain="broker"
            )
            self.assertTrue(collision.consume("cap_" + "a" * 24, "b" * 64, 10, 1))
            with self.assertRaisesRegex(CapabilityConsumptionError, "collided"):
                collision.consume("cap_" + "a" * 24, "c" * 64, 10, 2)
            collision.close()

            corrupt = Path(temporary) / "corrupt.sqlite3"
            corrupt.write_bytes(b"not a sqlite database")
            with self.assertRaisesRegex(CapabilityConsumptionError, "initialization"):
                SqliteCapabilityConsumptionStore(
                    corrupt, namespace="failure-test", domain="broker"
                )

            schema_path = Path(temporary) / "schema.sqlite3"
            schema_store = SqliteCapabilityConsumptionStore(
                schema_path, namespace="failure-test", domain="broker"
            )
            schema_store.close()
            with closing(sqlite3.connect(schema_path)) as schema_database:
                schema_database.execute(
                    """
                    UPDATE event_horizon_replay_schema SET version = 2
                    WHERE component = 'capability-consumption'
                    """
                )
                schema_database.commit()
            with self.assertRaisesRegex(CapabilityConsumptionError, "schema version"):
                SqliteCapabilityConsumptionStore(
                    schema_path, namespace="failure-test", domain="broker"
                )


if __name__ == "__main__":
    unittest.main()
