from __future__ import annotations

import hashlib
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any
from urllib.parse import unquote_plus

import boto3

from validation import validate_file


logger = logging.getLogger()
logger.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())

SAMPLE_RANGE = "bytes=0-8191"


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    processed = 0
    failures: list[str] = []

    for sqs_record in event.get("Records", []):
        message_id = sqs_record.get("messageId", "unknown")

        try:
            for s3_event in parse_s3_events(sqs_record):
                process_s3_event(s3_event)
                processed += 1
        except Exception:
            logger.exception("Failed to process SQS message %s", message_id)
            failures.append(message_id)

    if failures:
        failed_ids = ", ".join(failures)
        raise RuntimeError(f"Failed to process SQS messages: {failed_ids}")

    return {
        "statusCode": 200,
        "body": json.dumps({"processed": processed, "failed": 0}),
    }


def parse_s3_events(sqs_record: dict[str, Any]) -> list[dict[str, Any]]:
    body = json.loads(sqs_record.get("body", "{}"))

    if body.get("Event") == "s3:TestEvent":
        logger.info("Ignoring S3 test event")
        return []

    return body.get("Records", [])


def process_s3_event(s3_event: dict[str, Any]) -> None:
    bucket = s3_event["s3"]["bucket"]["name"]
    key = unquote_plus(s3_event["s3"]["object"]["key"])

    s3_client = boto3.client("s3")
    head = s3_client.head_object(Bucket=bucket, Key=key)
    sample = read_object_sample(s3_client, bucket, key)

    metadata = normalize_metadata(head.get("Metadata", {}))
    filename = metadata.get("original-filename") or metadata.get("filename") or key.rsplit("/", 1)[-1]
    user_id = metadata.get("user-id", "anonymous")
    upload_id = metadata.get("upload-id") or stable_upload_id(bucket, key)

    result = validate_file(
        filename=filename,
        claimed_content_type=head.get("ContentType"),
        size_bytes=head.get("ContentLength", 0),
        content_sample=sample,
    )

    item = {
        "file_id": upload_id,
        "upload_id": upload_id,
        "user_id": user_id,
        "original_filename": filename,
        "s3_bucket": bucket,
        "s3_key": key,
        "size_bytes": head.get("ContentLength", 0),
        "etag": strip_quotes(head.get("ETag", "")),
        "validated_at": now_iso(),
        **result.to_dict(),
    }

    save_result(item)
    logger.info("Validated upload %s: %s - %s", upload_id, result.status, result.reason)


def read_object_sample(s3_client: Any, bucket: str, key: str) -> bytes:
    response = s3_client.get_object(Bucket=bucket, Key=key, Range=SAMPLE_RANGE)
    return response["Body"].read()


def save_result(item: dict[str, Any]) -> None:
    table_name = os.environ.get("UPLOADS_TABLE_NAME")

    if not table_name:
        logger.warning("UPLOADS_TABLE_NAME is not set; validation result was not persisted")
        return

    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(table_name)
    update_values = {key: value for key, value in item.items() if key != "file_id"}
    expression_names = {f"#{key}": key for key in update_values}
    expression_values = {f":{key}": value for key, value in update_values.items()}
    assignments = ", ".join(f"#{key} = :{key}" for key in update_values)

    table.update_item(
        Key={"file_id": item["file_id"]},
        UpdateExpression=f"SET {assignments}",
        ExpressionAttributeNames=expression_names,
        ExpressionAttributeValues=expression_values,
    )


def normalize_metadata(metadata: dict[str, str]) -> dict[str, str]:
    return {key.lower(): value for key, value in metadata.items()}


def stable_upload_id(bucket: str, key: str) -> str:
    return hashlib.sha256(f"{bucket}/{key}".encode("utf-8")).hexdigest()[:32]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def strip_quotes(value: str) -> str:
    return value.strip('"')
