"""atlas-rule-engine stream consumer — listens for graph-ready events.

Consumes ``atlas.graph.ready``, deserializes the CICDGraph, runs the
full rule engine, and publishes FindingsEvent to ``atlas.findings``.
"""

import json
import logging
import os
import sys

from atlas_rule_engine.engine import RuleEngine
from atlas_sdk.events import FindingsEvent
from atlas_sdk.models.graph import CICDGraph

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(name)s %(levelname)s %(message)s",
)
logger = logging.getLogger("atlas_rule_engine")


def main() -> None:
    redis_url = os.environ.get("REDIS_URL", "redis://localhost:6379")

    try:
        import redis as _redis
    except ImportError:
        logger.error("redis package is required: pip install redis")
        sys.exit(1)

    logger.info("Connecting to Redis at %s ...", redis_url)
    client = _redis.from_url(redis_url, decode_responses=True)

    stream_in = "atlas.graph.ready"
    stream_out = "atlas.findings"
    group = "atlas-rule-engine"
    consumer = "rules-1"

    try:
        client.xgroup_create(stream_in, group, id="0", mkstream=True)
    except _redis.exceptions.ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise

    logger.info("Listening on '%s' (group=%s)...", stream_in, group)
    engine = RuleEngine()

    while True:
        try:
            messages = client.xreadgroup(
                group, consumer, {stream_in: ">"}, count=1, block=5000
            )
            if not messages:
                continue

            for _stream_name, entries in messages:
                for msg_id, fields in entries:
                    try:
                        payload = json.loads(fields.get("payload", "{}"))
                        scan_request_id = payload.get("scan_request_id", "")
                        graph_id = payload.get("graph_id", "")
                        graph_json = payload.get("graph", "")

                        graph = CICDGraph.model_validate_json(graph_json)
                        logger.info(
                            "Running rules on graph %s (%d nodes)",
                            graph_id, len(graph.nodes),
                        )

                        findings = engine.run(graph)
                        logger.info("Found %d findings", len(findings))

                        event = FindingsEvent(
                            scan_request_id=scan_request_id,
                            graph_id=graph_id,
                            findings=[
                                f.model_dump(mode="json") for f in findings
                            ],
                        )
                        client.xadd(stream_out, {"payload": event.model_dump_json()})
                        logger.info("Published findings to '%s'", stream_out)

                    except Exception as exc:  # noqa: BLE001
                        logger.error("Failed to process %s: %s", msg_id, exc)
                    finally:
                        client.xack(stream_in, group, msg_id)

        except KeyboardInterrupt:
            logger.info("Shutting down rule-engine consumer.")
            break


if __name__ == "__main__":
    main()
