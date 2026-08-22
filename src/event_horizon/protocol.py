from __future__ import annotations

import json
import math
import struct
import time
import unicodedata
from dataclasses import dataclass
from typing import Any, BinaryIO, Callable, Mapping

from .canonical import canonical_bytes


MAX_FRAME_BYTES = 65_536
MAX_NESTING = 8
MAX_STRING_BYTES = 16_384
MAX_COLLECTION_ITEMS = 256
MAX_DEADLINE_WINDOW_MS = 30_000
MAX_REQUESTS = 256


class ProtocolError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def _object_without_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProtocolError('duplicate_field', f'duplicate field: {key}')
        result[key] = value
    return result


def _reject_constant(value: str) -> None:
    raise ProtocolError('invalid_number', f'non-finite number: {value}')


def _reject_float(_value: str) -> None:
    raise ProtocolError('invalid_number', 'floating-point numbers are not permitted')


def validate_value(value: Any, *, depth: int = 0) -> None:
    if depth > MAX_NESTING:
        raise ProtocolError('nesting_limit', 'message nesting limit exceeded')
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, int):
        if abs(value) > 9_007_199_254_740_991:
            raise ProtocolError('number_limit', 'integer exceeds interoperable range')
        return
    if isinstance(value, float):
        raise ProtocolError('invalid_number', 'floating-point numbers are not permitted')
    if isinstance(value, str):
        if unicodedata.normalize('NFC', value) != value:
            raise ProtocolError('unicode_normalization', 'strings must already be Unicode NFC')
        if len(value.encode('utf-8')) > MAX_STRING_BYTES:
            raise ProtocolError('string_limit', 'string byte limit exceeded')
        return
    if isinstance(value, list):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise ProtocolError('collection_limit', 'array item limit exceeded')
        for item in value:
            validate_value(item, depth=depth + 1)
        return
    if isinstance(value, Mapping):
        if len(value) > MAX_COLLECTION_ITEMS:
            raise ProtocolError('collection_limit', 'object field limit exceeded')
        for key, item in value.items():
            if not isinstance(key, str):
                raise ProtocolError('invalid_field', 'object field names must be strings')
            validate_value(key, depth=depth + 1)
            validate_value(item, depth=depth + 1)
        return
    raise ProtocolError('invalid_type', f'unsupported JSON value: {type(value).__name__}')


def encode_frame(message: Mapping[str, Any], *, max_bytes: int = MAX_FRAME_BYTES) -> bytes:
    validate_value(message)
    payload = canonical_bytes(message)
    if not payload or len(payload) > max_bytes:
        raise ProtocolError('frame_limit', 'frame byte limit exceeded')
    return struct.pack('>I', len(payload)) + payload


def _read_exact(stream: BinaryIO, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = stream.read(remaining)
        if not chunk:
            raise EOFError('protocol stream closed')
        chunks.append(chunk)
        remaining -= len(chunk)
    return b''.join(chunks)


def read_frame(stream: BinaryIO, *, max_bytes: int = MAX_FRAME_BYTES) -> dict[str, Any]:
    header = stream.read(4)
    if not header:
        raise EOFError('protocol stream closed')
    if len(header) != 4:
        raise ProtocolError('truncated_frame', 'incomplete frame header')
    size = struct.unpack('>I', header)[0]
    if size == 0 or size > max_bytes:
        raise ProtocolError('frame_limit', 'frame byte limit exceeded')
    payload = _read_exact(stream, size)
    try:
        text = payload.decode('utf-8', errors='strict')
        message = json.loads(
            text,
            object_pairs_hook=_object_without_duplicates,
            parse_constant=_reject_constant,
            parse_float=_reject_float,
        )
    except UnicodeDecodeError as exc:
        raise ProtocolError('invalid_utf8', 'frame is not valid UTF-8') from exc
    except json.JSONDecodeError as exc:
        raise ProtocolError('invalid_json', 'frame is not valid JSON') from exc
    if not isinstance(message, dict):
        raise ProtocolError('invalid_envelope', 'frame must contain an object')
    validate_value(message)
    if canonical_bytes(message) != payload:
        raise ProtocolError('noncanonical_frame', 'frame must use canonical JSON')
    return message


def write_frame(stream: BinaryIO, message: Mapping[str, Any]) -> None:
    stream.write(encode_frame(message))
    stream.flush()


@dataclass(frozen=True)
class MessageSpec:
    body_fields: frozenset[str]
    handler: Callable[[dict[str, Any]], Mapping[str, Any]]
    authorizer: Callable[[Mapping[str, Any], Mapping[str, Any]], None] | None = None


def request_envelope(
    message_type: str,
    request_id: str,
    body: Mapping[str, Any],
    *,
    timeout_seconds: float = 5.0,
    authorization: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    envelope = {
        'type': message_type,
        'request_id': request_id,
        'deadline_ms': int((time.time() + timeout_seconds) * 1000),
        'body': dict(body),
    }
    if authorization is not None:
        envelope['authorization'] = dict(authorization)
    return envelope


def validate_request(
    message: Mapping[str, Any],
    specs: Mapping[str, MessageSpec],
    *,
    now_ms: int | None = None,
) -> tuple[str, str, dict[str, Any], MessageSpec]:
    required_envelope = {'type', 'request_id', 'deadline_ms', 'body'}
    if not required_envelope.issubset(message):
        raise ProtocolError('unknown_field', 'request envelope fields are invalid')
    message_type = message['type']
    request_id = message['request_id']
    deadline_ms = message['deadline_ms']
    body = message['body']
    if not isinstance(message_type, str) or not message_type:
        raise ProtocolError('invalid_type', 'message type must be a non-empty string')
    if not isinstance(request_id, str) or not request_id or len(request_id) > 128:
        raise ProtocolError('invalid_request_id', 'request_id is invalid')
    if not isinstance(deadline_ms, int) or isinstance(deadline_ms, bool):
        raise ProtocolError('invalid_deadline', 'deadline_ms must be an integer')
    if not isinstance(body, dict):
        raise ProtocolError('invalid_body', 'request body must be an object')
    spec = specs.get(message_type)
    if spec is None:
        raise ProtocolError('unknown_message_type', f'unknown message type: {message_type}')
    expected_envelope = set(required_envelope)
    if spec.authorizer is not None:
        expected_envelope.add('authorization')
    if set(message) != expected_envelope:
        code = 'authorization_required' if spec.authorizer is not None else 'unknown_field'
        raise ProtocolError(code, 'request envelope fields are invalid')
    if set(body) != spec.body_fields:
        raise ProtocolError('unknown_field', f'{message_type} body fields are invalid')
    current = int(time.time() * 1000) if now_ms is None else now_ms
    if deadline_ms < current:
        raise ProtocolError('deadline_exceeded', 'request deadline has expired')
    if deadline_ms > current + MAX_DEADLINE_WINDOW_MS:
        raise ProtocolError('deadline_limit', 'request deadline is too far in the future')
    if spec.authorizer is not None:
        authorization = message['authorization']
        if not isinstance(authorization, dict):
            raise ProtocolError('authorization_invalid', 'authorization must be an object')
        unsigned = {key: message[key] for key in ('type', 'request_id', 'deadline_ms', 'body')}
        spec.authorizer(unsigned, authorization)
    return message_type, request_id, body, spec


def success_response(request_id: str, body: Mapping[str, Any]) -> dict[str, Any]:
    return {'request_id': request_id, 'ok': True, 'body': dict(body), 'error': None}


def error_response(request_id: str, error: ProtocolError) -> dict[str, Any]:
    return {
        'request_id': request_id,
        'ok': False,
        'body': {},
        'error': {'code': error.code, 'message': str(error)[:512]},
    }


def validate_response(message: Mapping[str, Any], request_id: str) -> dict[str, Any]:
    if set(message) != {'request_id', 'ok', 'body', 'error'}:
        raise ProtocolError('invalid_response', 'response envelope fields are invalid')
    if message['request_id'] != request_id or not isinstance(message['ok'], bool):
        raise ProtocolError('invalid_response', 'response correlation is invalid')
    if not isinstance(message['body'], dict):
        raise ProtocolError('invalid_response', 'response body must be an object')
    if message['ok']:
        if message['error'] is not None:
            raise ProtocolError('invalid_response', 'successful response included an error')
        return dict(message['body'])
    error = message['error']
    if not isinstance(error, dict) or set(error) != {'code', 'message'}:
        raise ProtocolError('invalid_response', 'error response is malformed')
    raise ProtocolError(str(error['code']), str(error['message']))


class StrictRpcServer:
    def __init__(self, specs: Mapping[str, MessageSpec], *, max_requests: int = MAX_REQUESTS):
        if not specs or not 0 < max_requests <= MAX_REQUESTS:
            raise ValueError('invalid RPC server limits')
        self.specs = dict(specs)
        self.max_requests = max_requests

    def serve(self, source: BinaryIO, sink: BinaryIO) -> None:
        handled = 0
        while handled < self.max_requests:
            request_id = 'unavailable'
            try:
                message = read_frame(source)
                candidate = message.get('request_id')
                if isinstance(candidate, str) and candidate:
                    request_id = candidate[:128]
                _message_type, request_id, body, spec = validate_request(message, self.specs)
                handled += 1
                result = spec.handler(body)
                if int(time.time() * 1000) > message['deadline_ms']:
                    raise ProtocolError('deadline_exceeded', 'handler exceeded request deadline')
                if not isinstance(result, Mapping):
                    raise ProtocolError('invalid_handler_result', 'handler returned a non-object')
                write_frame(sink, success_response(request_id, result))
            except EOFError:
                return
            except ProtocolError as exc:
                write_frame(sink, error_response(request_id, exc))
                if exc.code in {'frame_limit', 'truncated_frame'}:
                    return
            except Exception:
                write_frame(
                    sink,
                    error_response(request_id, ProtocolError('service_failure', 'service failed closed')),
                )
        write_frame(
            sink,
            error_response('unavailable', ProtocolError('request_limit', 'service request limit reached')),
        )
