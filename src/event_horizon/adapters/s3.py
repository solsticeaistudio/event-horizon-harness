"""S3-compatible object store adapter with two-phase commit."""
from __future__ import annotations

import hashlib
import threading
import uuid
from dataclasses import dataclass
from typing import Any, Mapping, Optional
from contextlib import contextmanager

import boto3
from botocore.exceptions import ClientError

from event_horizon.adapters.base import (
    ExternalWriteAdapter,
    PrepareResult,
    CommitResult,
    AbortResult,
    TransactionState,
)
from event_horizon.canonical import canonical_bytes, digest


@dataclass(frozen=True)
class S3Config:
    """S3 adapter configuration."""
    endpoint_url: Optional[str] = None  # None for AWS, set for MinIO/local
    region: str = "us-east-1"
    access_key_id: Optional[str] = None
    secret_access_key: Optional[str] = None
    bucket: str = "event-horizon"
    multipart_threshold: int = 100 * 1024 * 1024  # 100 MB
    max_concurrency: int = 10
    multipart_chunksize: int = 10 * 1024 * 1024  # 10 MB


class S3Adapter(ExternalWriteAdapter):
    """S3-compatible object store adapter with two-phase commit.

    Uses S3 multipart upload for 2PC:
    - Prepare: initiate multipart upload, upload parts, complete except final part
    - Commit: complete multipart upload (final part)
    - Abort: abort multipart upload
    """

    adapter_type = "s3"

    def __init__(self, config: S3Config) -> None:
        self.config = config
        self._lock = threading.Lock()
        self._client = boto3.client(
            "s3",
            endpoint_url=config.endpoint_url,
            region_name=config.region,
            aws_access_key_id=config.access_key_id,
            aws_secret_access_key=config.secret_access_key,
        )
        self._pending_uploads: dict[str, Mapping[str, Any]] = {}

    def _generate_upload_id(self, transaction_id: str) -> str:
        """Generate a unique upload ID for the transaction."""
        return f"eh-{transaction_id[:16]}"

    def _get_object_key(self, transaction_id: str, operation: Mapping[str, Any]) -> str:
        """Determine the S3 object key from the operation."""
        op_data = operation.get("data", {})
        # Use explicit key if provided, otherwise generate from transaction
        return op_data.get("key") or f"eh/{transaction_id[:16]}/{op_data.get('filename', 'data')}"

    def prepare(
        self,
        transaction_id: str,
        operation: Mapping[str, Any],
    ) -> PrepareResult:
        """Prepare phase: initiate multipart upload and upload all parts except the last."""
        try:
            op_type = operation.get("type")
            op_data = operation.get("data", {})

            if op_type not in ("put_object", "multipart_upload"):
                return PrepareResult(
                    transaction_id=transaction_id,
                    success=False,
                    error=f"Unsupported operation type: {op_type}",
                )

            bucket = op_data.get("bucket", self.config.bucket)
            key = op_data.get("key", self._get_object_key(transaction_id, operation))

            # Initiate multipart upload
            create_response = self._client.create_multipart_upload(
                Bucket=bucket,
                Key=key,
                ContentType=op_data.get("content_type", "application/octet-stream"),
                Metadata={
                    "eh-transaction-id": transaction_id[:64],
                    "eh-operation": "put_object",
                },
            )
            upload_id = response["UploadId"]

            # Upload data in parts
            data = op_data.get("body") or op_data.get("data")
            if isinstance(data, str):
                data = data.encode("utf-8")
            elif not isinstance(data, bytes):
                return PrepareResult(
                    transaction_id=transaction_id,
                    success=False,
                    error="Body must be bytes or string",
                )

            parts = self._upload_parts(bucket, key, upload_id, data)

            # Store upload state for commit/abort
            prepare_metadata = {
                "bucket": bucket,
                "key": key,
                "upload_id": upload_id,
                "parts": parts,
                "etag": parts[-1]["ETag"] if parts else None,
            }

            with self._lock:
                self._pending_uploads[transaction_id] = {
                    "bucket": bucket,
                    "key": key,
                    "upload_id": upload_id,
                    "parts": parts,
                }

            return PrepareResult(
                transaction_id=transaction_id,
                success=True,
                metadata={
                    "bucket": bucket,
                    "key": key,
                    "upload_id": upload_id,
                    "parts": parts,
                },
            )

        except Exception as e:
            return PrepareResult(
                transaction_id=transaction_id,
                success=False,
                error=str(e),
            )

    def _upload_parts(self, bucket: str, key: str, upload_id: str, data: bytes) -> list[Mapping[str, Any]]:
        """Upload data in parts using multipart upload."""
        parts = []
        part_size = self.config.multipart_chunksize
        num_parts = (len(data) + self.config.multipart_chunksize - 1) // self.config.multipart_chunksize

        for i in range(num_parts):
            start = i * part_size
            end = min(start + part_size, len(data))
            part_data = data[start:end]

            response = self._client.upload_part(
                Bucket=bucket,
                Key=key,
                PartNumber=i + 1,
                UploadId=upload_id,
                Body=part_data,
            )
            parts.append({
                "PartNumber": i + 1,
                "ETag": response["ETag"],
            })

        return parts

    def commit(
        self,
        transaction_id: str,
        prepare_metadata: Mapping[str, Any],
    ) -> CommitResult:
        """Commit phase: complete the multipart upload."""
        try:
            with self._lock:
                pending = self._pending_uploads.pop(transaction_id, None)

            if not pending:
                # Check if already committed
                # (In real implementation, would check S3 object existence)
                return CommitResult(
                    transaction_id=transaction_id,
                    success=False,
                    error="No pending upload found for transaction",
                )

            bucket = pending["bucket"]
            key = pending["key"]
            upload_id = pending["upload_id"]
            parts = pending["parts"]

            # Complete multipart upload
            self._client.complete_multipart_upload(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )

            # Get object ETag as external ID
            response = self._client.head_object(Bucket=bucket, Key=key)
            external_id = response.get("ETag", "").strip('"')

            return CommitResult(
                transaction_id=transaction_id,
                success=True,
                external_id=external_id,
            )

        except ClientError as e:
            return CommitResult(
                transaction_id=transaction_id,
                success=False,
                error=f"S3 error: {e.response['Error']['Message']}",
            )
        except Exception as e:
            return CommitResult(
                transaction_id=transaction_id,
                success=False,
                error=str(e),
            )

    def abort(
        self,
        transaction_id: str,
        prepare_metadata: Mapping[str, Any],
    ) -> AbortResult:
        """Abort phase: abort the multipart upload."""
        try:
            with self._lock:
                pending = self._pending_uploads.pop(transaction_id, None)

            if not pending:
                return AbortResult(
                    transaction_id=transaction_id,
                    success=True,
                    error="No pending upload (already completed or aborted)",
                )

            self._client.abort_multipart_upload(
                Bucket=pending["bucket"],
                Key=pending["key"],
                UploadId=pending["upload_id"],
            )

            return AbortResult(
                transaction_id=transaction_id,
                success=True,
            )

        except ClientError as e:
            return AbortResult(
                transaction_id=transaction_id,
                success=False,
                error=f"S3 error: {e.response['Error']['Message']}",
            )
        except Exception as e:
            return AbortResult(
                transaction_id=transaction_id,
                success=False,
                error=str(e),
            )

    def get_status(self, transaction_id: str) -> TransactionState:
        """Get the current state of a transaction."""
        with self._lock:
            if transaction_id in self._pending_uploads:
                return TransactionState.PREPARED
            # Would need to check S3 object existence for committed
            return TransactionState.FAILED

    def close(self) -> None:
        """Close the S3 client."""
        # boto3 client doesn't need explicit close
        pass

    @property
    def _client(self):
        """Lazy client creation."""
        if not hasattr(self, "_client"):
            self._client = boto3.client(
                "s3",
                endpoint_url=self.config.endpoint_url,
                region_name=self.config.region,
                aws_access_key_id=self.config.access_key_id,
                aws_secret_access_key=self.config.secret_access_key,
            )
        return self._client