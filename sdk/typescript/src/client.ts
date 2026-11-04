// Generated Public Interface transport. Never retries an uncertain effect.
import type * as types from './types.js';
import {decodeQuery, validateQueryRequest} from './query.js';
import {queryError, QueryError} from './errors.js';
import { routes } from './contract.js';
import { decode, encode, object, WireError } from './codec.js';
export type CallOptions = { readonly bearer?: string; readonly signal?: AbortSignal; readonly timeoutMs?: number };
export class ClientError extends Error {
  constructor(readonly kind: 'transport' | 'refused', readonly status?: number, readonly refusal?: unknown) { super(kind === 'transport' ? 'Positron transport outcome is ambiguous' : 'Positron request refused'); this.name = 'ClientError'; }
  readonly retryClass = 'RETRY_CLASS_NEVER';
  get completionState() { return this.kind === 'transport' ? 'COMPLETION_STATE_AMBIGUOUS' : 'COMPLETION_STATE_REJECTED'; }
}
export class PositronClient {
  readonly #endpoint: URL;
  constructor(options: {readonly endpoint: string; readonly allowPlaintext?: boolean}) {
    let endpoint: URL;
    try { endpoint = new URL(options.endpoint); } catch { throw new WireError(); }
    if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash || endpoint.pathname !== '/' || !(endpoint.protocol === 'https:' || endpoint.protocol === 'http:' && options.allowPlaintext === true)) throw new WireError();
    this.#endpoint = endpoint;
  }
  async call(rpc: string, request: unknown, options: CallOptions = {}): Promise<unknown> {
    const route = routes.find(route => route.rpc === rpc);
    if (!route) throw new WireError();
    const body = encode(route.request, request);
    const query = rpc.startsWith('positron.v1.LogQueryService/');
    const input = query ? object(decode(route.request,body)) : {};
    if (query) validateQueryRequest(rpc,input);
    if (query && !rpc.endsWith('/Execute')) {
      const capability = input.tail !== undefined ? 5 : 4;
      const response = object(await this.call('positron.v1.CapabilityService/Negotiate',{api_major:1,capability},options));
      if (typeof response.schema_digest !== 'string' || !/^[0-9a-f]{64}$/.test(response.schema_digest)) throw new ClientError('transport');
      if (response.api_major !== 1 || response.capability !== capability || response.availability !== 1 || response.refusal !== undefined && response.refusal !== null) throw new QueryError('UnsupportedFeature','RETRY_CLASS_NEVER','COMPLETION_STATE_REJECTED');
    }
    const requestLimit = 'max_request_bytes' in route ? route.max_request_bytes : 1024;
    const responseLimit = 'max_response_bytes' in route ? route.max_response_bytes : 4096;
    if (Buffer.byteLength(body) > requestLimit || options.bearer !== undefined && (!/^[\x21-\x7e]+$/.test(options.bearer) || options.bearer.length > 8192)) throw new WireError();
    const timeout = options.timeoutMs ?? 5000;
    if (!Number.isSafeInteger(timeout) || timeout <= 0 || timeout > 30000) throw new WireError();
    const signal = options.signal ? AbortSignal.any([options.signal, AbortSignal.timeout(timeout)]) : AbortSignal.timeout(timeout);
    try {
      const headers: Record<string,string> = {'content-type':'application/json'};
      if (options.bearer !== undefined) headers.authorization = `Bearer ${options.bearer}`;
      const response = await fetch(new URL(route.path, this.#endpoint), {method:'POST', body, headers, redirect:'error', signal});
      if (!response.body) throw new WireError();
      const reader = response.body.getReader();
      const parts: Uint8Array[] = [];
      let length = 0;
      try {
        while (true) {
          const {done, value} = await reader.read();
          if (done) break;
          length += value.length;
          if (length > responseLimit) throw new WireError();
          parts.push(value);
        }
      } finally { await reader.cancel(); reader.releaseLock(); }
      const text = new TextDecoder('utf-8', {fatal:true}).decode(Buffer.concat(parts));
      if (!response.ok) {
        if (query) throw queryError(response.status,text,rpc.endsWith('/Cancel'));
        const refusal: unknown = JSON.parse(text);
        object(refusal);
        throw new ClientError('refused', response.status, refusal);
      }
      if (query && !rpc.endsWith('/Cancel')) return decodeQuery(text, input.tail !== undefined ? 'tail' : rpc.endsWith('/Session') ? 'session' : 'execute');
      const value = decode(route.response, text);
      if (rpc.endsWith('LogQueryService/Cancel') && object(value).cancelled !== true) throw new WireError();
      return value;
    } catch (error) { if (error instanceof ClientError || error instanceof QueryError) throw error; throw new ClientError('transport'); }
  }
  async capabilityNegotiate(request: types.CapabilityRequest, options: CallOptions = {}): Promise<types.CapabilityResponse> { return this.call("positron.v1.CapabilityService/Negotiate", request, options) as Promise<types.CapabilityResponse>; }
  async apiKeyManage(request: types.ApiKeyRequest, options: CallOptions = {}): Promise<types.ApiKeyResponse> { return this.call("positron.v1.ApiKeyService/Manage", request, options) as Promise<types.ApiKeyResponse>; }
  async tenantQuotaUpdate(request: types.TenantQuotaUpdateRequest, options: CallOptions = {}): Promise<types.TenantQuotaUpdateResponse> { return this.call("positron.v1.TenantQuotaService/Update", request, options) as Promise<types.TenantQuotaUpdateResponse>; }
  async tenantLifecycleTransition(request: types.TenantLifecycleTransitionRequest, options: CallOptions = {}): Promise<types.TenantLifecycleTransitionResponse> { return this.call("positron.v1.TenantLifecycleService/Transition", request, options) as Promise<types.TenantLifecycleTransitionResponse>; }
  async tenantAliasBind(request: types.TenantAliasBindRequest, options: CallOptions = {}): Promise<types.TenantAliasBindResponse> { return this.call("positron.v1.TenantAliasService/Bind", request, options) as Promise<types.TenantAliasBindResponse>; }
  async tenantCreate(request: types.TenantCreateRequest, options: CallOptions = {}): Promise<types.TenantCreateResponse> { return this.call("positron.v1.TenantService/Create", request, options) as Promise<types.TenantCreateResponse>; }
  async tenantInspect(request: types.TenantInspectRequest, options: CallOptions = {}): Promise<types.TenantInspectResponse> { return this.call("positron.v1.TenantService/Inspect", request, options) as Promise<types.TenantInspectResponse>; }
  async tenantList(request: types.TenantListRequest, options: CallOptions = {}): Promise<types.TenantListResponse> { return this.call("positron.v1.TenantService/List", request, options) as Promise<types.TenantListResponse>; }
  async tenantUpdateDisplayName(request: types.TenantDisplayNameUpdateRequest, options: CallOptions = {}): Promise<types.TenantDisplayNameUpdateResponse> { return this.call("positron.v1.TenantService/UpdateDisplayName", request, options) as Promise<types.TenantDisplayNameUpdateResponse>; }
  async tenantRetentionPreview(request: types.TenantRetentionPreviewRequest, options: CallOptions = {}): Promise<types.TenantRetentionPreviewResponse> { return this.call("positron.v1.TenantRetentionService/Preview", request, options) as Promise<types.TenantRetentionPreviewResponse>; }
  async tenantRetentionUpdate(request: types.TenantRetentionUpdateRequest, options: CallOptions = {}): Promise<types.TenantRetentionUpdateResponse> { return this.call("positron.v1.TenantRetentionService/Update", request, options) as Promise<types.TenantRetentionUpdateResponse>; }
  async maintenanceStatus(request: types.MaintenanceStatusRequest, options: CallOptions = {}): Promise<types.MaintenanceStatusResponse> { return this.call("positron.v1.MaintenanceService/Status", request, options) as Promise<types.MaintenanceStatusResponse>; }
  async maintenanceExplain(request: types.MaintenanceExplainRequest, options: CallOptions = {}): Promise<types.MaintenanceExplainResponse> { return this.call("positron.v1.MaintenanceService/Explain", request, options) as Promise<types.MaintenanceExplainResponse>; }
  async maintenanceRun(request: types.MaintenanceRunRequest, options: CallOptions = {}): Promise<types.MaintenanceRunResponse> { return this.call("positron.v1.MaintenanceService/Run", request, options) as Promise<types.MaintenanceRunResponse>; }
  async maintenancePause(request: types.MaintenancePauseRequest, options: CallOptions = {}): Promise<types.MaintenanceControlResponse> { return this.call("positron.v1.MaintenanceService/Pause", request, options) as Promise<types.MaintenanceControlResponse>; }
  async maintenanceResume(request: types.MaintenanceResumeRequest, options: CallOptions = {}): Promise<types.MaintenanceControlResponse> { return this.call("positron.v1.MaintenanceService/Resume", request, options) as Promise<types.MaintenanceControlResponse>; }
  async maintenanceWindow(request: types.MaintenanceWindowRequest, options: CallOptions = {}): Promise<types.MaintenanceWindowResponse> { return this.call("positron.v1.MaintenanceService/Window", request, options) as Promise<types.MaintenanceWindowResponse>; }
  async maintenanceVerify(request: types.OnlineVerificationRequest, options: CallOptions = {}): Promise<types.OnlineVerificationReport> { return this.call("positron.v1.MaintenanceService/Verify", request, options) as Promise<types.OnlineVerificationReport>; }
  async policyValidate(request: types.PolicyPreviewRequest, options: CallOptions = {}): Promise<types.PolicyValidateResponse> { return this.call("positron.v1.PolicyService/Validate", request, options) as Promise<types.PolicyValidateResponse>; }
  async policyTest(request: types.PolicyTestRequest, options: CallOptions = {}): Promise<types.PolicyTestResponse> { return this.call("positron.v1.PolicyService/Test", request, options) as Promise<types.PolicyTestResponse>; }
  async policyDiff(request: types.PolicyDiffRequest, options: CallOptions = {}): Promise<types.PolicyDiffResponse> { return this.call("positron.v1.PolicyService/Diff", request, options) as Promise<types.PolicyDiffResponse>; }
  async policyExplain(request: types.PolicyExplainRequest, options: CallOptions = {}): Promise<types.PolicyExplainResponse> { return this.call("positron.v1.PolicyService/Explain", request, options) as Promise<types.PolicyExplainResponse>; }
  async policyActivate(request: types.PolicyActivateRequest, options: CallOptions = {}): Promise<types.PolicyActivateResponse> { return this.call("positron.v1.PolicyService/Activate", request, options) as Promise<types.PolicyActivateResponse>; }
  async maintenanceAbandonSegment(request: types.SegmentAbandonmentRequest, options: CallOptions = {}): Promise<types.SegmentAbandonmentResponse> { return this.call("positron.v1.MaintenanceService/AbandonSegment", request, options) as Promise<types.SegmentAbandonmentResponse>; }
  async providerMigrationManage(request: types.ProviderMigrationRequest, options: CallOptions = {}): Promise<types.ProviderMigrationResponse> { return this.call("positron.v1.ProviderMigrationService/Manage", request, options) as Promise<types.ProviderMigrationResponse>; }
  async repositoryManage(request: types.RepositoryRequest, options: CallOptions = {}): Promise<types.RepositoryResponse> { return this.call("positron.v1.RepositoryService/Manage", request, options) as Promise<types.RepositoryResponse>; }
  async backupManage(request: types.BackupRequest, options: CallOptions = {}): Promise<types.BackupResponse> { return this.call("positron.v1.BackupService/Manage", request, options) as Promise<types.BackupResponse>; }
  async backupList(request: types.BackupListRequest, options: CallOptions = {}): Promise<types.BackupListResponse> { return this.call("positron.v1.BackupService/List", request, options) as Promise<types.BackupListResponse>; }
  async tenantPurgeManage(request: types.TenantPurgeRequest, options: CallOptions = {}): Promise<types.TenantPurgeResponse> { return this.call("positron.v1.TenantPurgeService/Manage", request, options) as Promise<types.TenantPurgeResponse>; }
  async upgradeManage(request: types.UpgradeRequest, options: CallOptions = {}): Promise<types.UpgradeResponse> { return this.call("positron.v1.UpgradeService/Manage", request, options) as Promise<types.UpgradeResponse>; }
  async logQueryExecute(request: types.LogQueryRequest, options: CallOptions = {}): Promise<types.LogQueryResponse> { return this.call("positron.v1.LogQueryService/Execute", request, options) as Promise<types.LogQueryResponse>; }
  async logQuerySession(request: types.LogQuerySessionRequest, options: CallOptions = {}): Promise<types.LogQueryResponse> { return this.call("positron.v1.LogQueryService/Session", request, options) as Promise<types.LogQueryResponse>; }
  async logQueryCancel(request: types.LogQueryCancelRequest, options: CallOptions = {}): Promise<types.LogQueryCancelResponse> { return this.call("positron.v1.LogQueryService/Cancel", request, options) as Promise<types.LogQueryCancelResponse>; }

}
