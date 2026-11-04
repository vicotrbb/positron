"""Generated bounded synchronous HTTPS client. No automatic effect retries."""
import http.client
import math
import re
import ssl
import socket
import threading
import time
from urllib.parse import urlsplit
from . import types
from .codec import CONTRACT, WireError, decode, encode, obj, require
from .errors import QueryError, query_error
from .query import decode_query, validate_request

class ClientError(Exception):
    retry_class = 'RETRY_CLASS_NEVER'

    def __init__(self, kind, status=None, refusal=None):
        super().__init__('Positron transport outcome is ambiguous' if kind == 'transport' else 'Positron request refused')
        self.kind, self.status, self.refusal = kind, status, refusal
        self.completion_state = 'COMPLETION_STATE_AMBIGUOUS' if kind == 'transport' else 'COMPLETION_STATE_REJECTED'

# The OS resolver cannot be interrupted by Python socket timeouts. Keep at
# most 16 unfinished connects process-wide, including cancelled DNS calls.
_CONNECT_SLOTS = threading.BoundedSemaphore(16)

def connect_bounded(connection, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0 or not _CONNECT_SLOTS.acquire(timeout=remaining):
        raise ClientError('transport')
    done, cancelled, result = threading.Event(), threading.Event(), []
    def connect():
        try:
            connection.connect()
            result.append(True)
        except Exception:
            result.append(False)
        finally:
            try:
                if cancelled.is_set():
                    connection.close()
            finally:
                done.set()
                _CONNECT_SLOTS.release()
    worker = threading.Thread(target=connect, name='positron-sdk-connect', daemon=True)
    try:
        worker.start()
    except BaseException:
        _CONNECT_SLOTS.release()
        raise
    try:
        if not done.wait(max(0, deadline - time.monotonic())):
            raise ClientError('transport')
    except BaseException:
        cancelled.set()
        connection.close()
        raise
    worker.join()
    if not result[0]:
        raise ClientError('transport')


class PositronClient:
    def __init__(self, endpoint: str, *, allow_plaintext: bool = False):
        try:
            parsed = urlsplit(endpoint)
            require(parsed.scheme == 'https' or parsed.scheme == 'http' and allow_plaintext)
            require(parsed.hostname is not None and parsed.username is None and parsed.password is None and not parsed.query and not parsed.fragment and parsed.path in ('', '/'))
            require(parsed.port is None or 0 < parsed.port < 65536)
        except (ValueError, AttributeError):
            raise WireError() from None
        self._endpoint = parsed

    def call(self, rpc: str, request, *, bearer: str | None = None, timeout: float = 5.0):
        route = next((route for route in CONTRACT['routes'] if route['rpc'] == rpc), None)
        require(route is not None)
        body = encode(route['request'], request).encode()
        query = rpc.startswith('positron.v1.LogQueryService/')
        input_value = obj(decode(route['request'], body.decode())) if query else {}
        if query:
            validate_request(rpc, input_value)
        require(len(body) <= route.get('max_request_bytes', 1024))
        require(bearer is None or isinstance(bearer, str) and len(bearer) <= 8192 and re.fullmatch(r'[\x21-\x7e]+', bearer) is not None)
        require(type(timeout) in (float, int) and math.isfinite(timeout) and 0 < timeout <= 30)
        deadline = time.monotonic() + timeout
        if query and not rpc.endswith('/Execute'):
            capability = 5 if 'tail' in input_value else 4
            response = obj(self.call('positron.v1.CapabilityService/Negotiate', dict(api_major=1, capability=capability), bearer=bearer, timeout=timeout))
            if not isinstance(response.get('schema_digest'), str) or re.fullmatch(r'[0-9a-f]{64}', response['schema_digest']) is None:
                raise ClientError('transport')
            if response.get('api_major') != 1 or response.get('capability') != capability or response.get('availability') != 1 or response.get('refusal') is not None:
                raise QueryError('UnsupportedFeature', 'RETRY_CLASS_NEVER', 'COMPLETION_STATE_REJECTED')
        connection = None
        timer = None
        try:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ClientError('transport')
            endpoint = self._endpoint
            if endpoint.scheme == 'https':
                connection = http.client.HTTPSConnection(endpoint.hostname, endpoint.port, timeout=remaining, context=ssl.create_default_context())
            else:
                connection = http.client.HTTPConnection(endpoint.hostname, endpoint.port, timeout=remaining)
            # A socket timeout bounds inactivity; this one joined timer also
            # bounds a peer that drips headers or response bytes continuously.
            connect_bounded(connection, deadline)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ClientError('transport')
            transport_socket = connection.sock
            def interrupt():
                try:
                    transport_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            timer = threading.Timer(remaining, interrupt)
            timer.daemon = True
            timer.start()
            headers = {'Content-Type': 'application/json'}
            if bearer is not None:
                headers['Authorization'] = 'Bearer ' + bearer
            connection.request('POST', route['path'], body=body, headers=headers)
            response = connection.getresponse()
            limit = route.get('max_response_bytes', 4096)
            parts, length = [], 0
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ClientError('transport')
                if connection.sock is not None:
                    connection.sock.settimeout(remaining)
                chunk = response.read1(min(8192, limit + 1 - length))
                if not chunk:
                    break
                parts.append(chunk)
                length += len(chunk)
                require(length <= limit)
            text = b''.join(parts).decode('utf-8')
            if not 200 <= response.status < 300:
                if query:
                    raise query_error(response.status, text, rpc.endswith('/Cancel'))
                from .codec import parse_json
                raise ClientError('refused', response.status, obj(parse_json(text)))
            if query and not rpc.endswith('/Cancel'):
                return decode_query(text, 'tail' if 'tail' in input_value else 'session' if rpc.endswith('/Session') else 'execute')
            value = decode(route['response'], text)
            if rpc.endswith('LogQueryService/Cancel'):
                require(obj(value).get('cancelled') is True)
            return value
        except (ClientError, QueryError):
            raise
        except Exception:
            raise ClientError('transport') from None
        finally:
            if timer is not None:
                timer.cancel()
                timer.join()
            if connection is not None:
                connection.close()

    def capability_negotiate(self, request: types.CapabilityRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.CapabilityResponse:
        return self.call("positron.v1.CapabilityService/Negotiate", request, bearer=bearer, timeout=timeout)

    def api_key_manage(self, request: types.ApiKeyRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.ApiKeyResponse:
        return self.call("positron.v1.ApiKeyService/Manage", request, bearer=bearer, timeout=timeout)

    def tenant_quota_update(self, request: types.TenantQuotaUpdateRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.TenantQuotaUpdateResponse:
        return self.call("positron.v1.TenantQuotaService/Update", request, bearer=bearer, timeout=timeout)

    def tenant_lifecycle_transition(self, request: types.TenantLifecycleTransitionRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.TenantLifecycleTransitionResponse:
        return self.call("positron.v1.TenantLifecycleService/Transition", request, bearer=bearer, timeout=timeout)

    def tenant_alias_bind(self, request: types.TenantAliasBindRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.TenantAliasBindResponse:
        return self.call("positron.v1.TenantAliasService/Bind", request, bearer=bearer, timeout=timeout)

    def tenant_create(self, request: types.TenantCreateRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.TenantCreateResponse:
        return self.call("positron.v1.TenantService/Create", request, bearer=bearer, timeout=timeout)

    def tenant_inspect(self, request: types.TenantInspectRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.TenantInspectResponse:
        return self.call("positron.v1.TenantService/Inspect", request, bearer=bearer, timeout=timeout)

    def tenant_list(self, request: types.TenantListRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.TenantListResponse:
        return self.call("positron.v1.TenantService/List", request, bearer=bearer, timeout=timeout)

    def tenant_update_display_name(self, request: types.TenantDisplayNameUpdateRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.TenantDisplayNameUpdateResponse:
        return self.call("positron.v1.TenantService/UpdateDisplayName", request, bearer=bearer, timeout=timeout)

    def tenant_retention_preview(self, request: types.TenantRetentionPreviewRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.TenantRetentionPreviewResponse:
        return self.call("positron.v1.TenantRetentionService/Preview", request, bearer=bearer, timeout=timeout)

    def tenant_retention_update(self, request: types.TenantRetentionUpdateRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.TenantRetentionUpdateResponse:
        return self.call("positron.v1.TenantRetentionService/Update", request, bearer=bearer, timeout=timeout)

    def maintenance_status(self, request: types.MaintenanceStatusRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.MaintenanceStatusResponse:
        return self.call("positron.v1.MaintenanceService/Status", request, bearer=bearer, timeout=timeout)

    def maintenance_explain(self, request: types.MaintenanceExplainRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.MaintenanceExplainResponse:
        return self.call("positron.v1.MaintenanceService/Explain", request, bearer=bearer, timeout=timeout)

    def maintenance_run(self, request: types.MaintenanceRunRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.MaintenanceRunResponse:
        return self.call("positron.v1.MaintenanceService/Run", request, bearer=bearer, timeout=timeout)

    def maintenance_pause(self, request: types.MaintenancePauseRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.MaintenanceControlResponse:
        return self.call("positron.v1.MaintenanceService/Pause", request, bearer=bearer, timeout=timeout)

    def maintenance_resume(self, request: types.MaintenanceResumeRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.MaintenanceControlResponse:
        return self.call("positron.v1.MaintenanceService/Resume", request, bearer=bearer, timeout=timeout)

    def maintenance_window(self, request: types.MaintenanceWindowRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.MaintenanceWindowResponse:
        return self.call("positron.v1.MaintenanceService/Window", request, bearer=bearer, timeout=timeout)

    def maintenance_verify(self, request: types.OnlineVerificationRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.OnlineVerificationReport:
        return self.call("positron.v1.MaintenanceService/Verify", request, bearer=bearer, timeout=timeout)

    def policy_validate(self, request: types.PolicyPreviewRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.PolicyValidateResponse:
        return self.call("positron.v1.PolicyService/Validate", request, bearer=bearer, timeout=timeout)

    def policy_test(self, request: types.PolicyTestRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.PolicyTestResponse:
        return self.call("positron.v1.PolicyService/Test", request, bearer=bearer, timeout=timeout)

    def policy_diff(self, request: types.PolicyDiffRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.PolicyDiffResponse:
        return self.call("positron.v1.PolicyService/Diff", request, bearer=bearer, timeout=timeout)

    def policy_explain(self, request: types.PolicyExplainRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.PolicyExplainResponse:
        return self.call("positron.v1.PolicyService/Explain", request, bearer=bearer, timeout=timeout)

    def policy_activate(self, request: types.PolicyActivateRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.PolicyActivateResponse:
        return self.call("positron.v1.PolicyService/Activate", request, bearer=bearer, timeout=timeout)

    def maintenance_abandon_segment(self, request: types.SegmentAbandonmentRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.SegmentAbandonmentResponse:
        return self.call("positron.v1.MaintenanceService/AbandonSegment", request, bearer=bearer, timeout=timeout)

    def provider_migration_manage(self, request: types.ProviderMigrationRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.ProviderMigrationResponse:
        return self.call("positron.v1.ProviderMigrationService/Manage", request, bearer=bearer, timeout=timeout)

    def repository_manage(self, request: types.RepositoryRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.RepositoryResponse:
        return self.call("positron.v1.RepositoryService/Manage", request, bearer=bearer, timeout=timeout)

    def backup_manage(self, request: types.BackupRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.BackupResponse:
        return self.call("positron.v1.BackupService/Manage", request, bearer=bearer, timeout=timeout)

    def backup_list(self, request: types.BackupListRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.BackupListResponse:
        return self.call("positron.v1.BackupService/List", request, bearer=bearer, timeout=timeout)

    def tenant_purge_manage(self, request: types.TenantPurgeRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.TenantPurgeResponse:
        return self.call("positron.v1.TenantPurgeService/Manage", request, bearer=bearer, timeout=timeout)

    def upgrade_manage(self, request: types.UpgradeRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.UpgradeResponse:
        return self.call("positron.v1.UpgradeService/Manage", request, bearer=bearer, timeout=timeout)

    def log_query_execute(self, request: types.LogQueryRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.LogQueryResponse:
        return self.call("positron.v1.LogQueryService/Execute", request, bearer=bearer, timeout=timeout)

    def log_query_session(self, request: types.LogQuerySessionRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.LogQueryResponse:
        return self.call("positron.v1.LogQueryService/Session", request, bearer=bearer, timeout=timeout)

    def log_query_cancel(self, request: types.LogQueryCancelRequest, *, bearer: str | None = None, timeout: float = 5.0) -> types.LogQueryCancelResponse:
        return self.call("positron.v1.LogQueryService/Cancel", request, bearer=bearer, timeout=timeout)
