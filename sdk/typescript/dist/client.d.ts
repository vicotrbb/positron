import type * as types from './types.js';
export type CallOptions = {
    readonly bearer?: string;
    readonly signal?: AbortSignal;
    readonly timeoutMs?: number;
};
export declare class ClientError extends Error {
    readonly kind: 'transport' | 'refused';
    readonly status?: number | undefined;
    readonly refusal?: unknown | undefined;
    constructor(kind: 'transport' | 'refused', status?: number | undefined, refusal?: unknown | undefined);
    readonly retryClass = "RETRY_CLASS_NEVER";
    get completionState(): "COMPLETION_STATE_REJECTED" | "COMPLETION_STATE_AMBIGUOUS";
}
export declare class PositronClient {
    #private;
    constructor(options: {
        readonly endpoint: string;
        readonly allowPlaintext?: boolean;
    });
    call(rpc: string, request: unknown, options?: CallOptions): Promise<unknown>;
    capabilityNegotiate(request: types.CapabilityRequest, options?: CallOptions): Promise<types.CapabilityResponse>;
    apiKeyManage(request: types.ApiKeyRequest, options?: CallOptions): Promise<types.ApiKeyResponse>;
    tenantQuotaUpdate(request: types.TenantQuotaUpdateRequest, options?: CallOptions): Promise<types.TenantQuotaUpdateResponse>;
    tenantLifecycleTransition(request: types.TenantLifecycleTransitionRequest, options?: CallOptions): Promise<types.TenantLifecycleTransitionResponse>;
    tenantAliasBind(request: types.TenantAliasBindRequest, options?: CallOptions): Promise<types.TenantAliasBindResponse>;
    tenantCreate(request: types.TenantCreateRequest, options?: CallOptions): Promise<types.TenantCreateResponse>;
    tenantInspect(request: types.TenantInspectRequest, options?: CallOptions): Promise<types.TenantInspectResponse>;
    tenantList(request: types.TenantListRequest, options?: CallOptions): Promise<types.TenantListResponse>;
    tenantUpdateDisplayName(request: types.TenantDisplayNameUpdateRequest, options?: CallOptions): Promise<types.TenantDisplayNameUpdateResponse>;
    tenantRetentionPreview(request: types.TenantRetentionPreviewRequest, options?: CallOptions): Promise<types.TenantRetentionPreviewResponse>;
    tenantRetentionUpdate(request: types.TenantRetentionUpdateRequest, options?: CallOptions): Promise<types.TenantRetentionUpdateResponse>;
    maintenanceStatus(request: types.MaintenanceStatusRequest, options?: CallOptions): Promise<types.MaintenanceStatusResponse>;
    maintenanceExplain(request: types.MaintenanceExplainRequest, options?: CallOptions): Promise<types.MaintenanceExplainResponse>;
    maintenanceRun(request: types.MaintenanceRunRequest, options?: CallOptions): Promise<types.MaintenanceRunResponse>;
    maintenancePause(request: types.MaintenancePauseRequest, options?: CallOptions): Promise<types.MaintenanceControlResponse>;
    maintenanceResume(request: types.MaintenanceResumeRequest, options?: CallOptions): Promise<types.MaintenanceControlResponse>;
    maintenanceWindow(request: types.MaintenanceWindowRequest, options?: CallOptions): Promise<types.MaintenanceWindowResponse>;
    maintenanceVerify(request: types.OnlineVerificationRequest, options?: CallOptions): Promise<types.OnlineVerificationReport>;
    policyValidate(request: types.PolicyPreviewRequest, options?: CallOptions): Promise<types.PolicyValidateResponse>;
    policyTest(request: types.PolicyTestRequest, options?: CallOptions): Promise<types.PolicyTestResponse>;
    policyDiff(request: types.PolicyDiffRequest, options?: CallOptions): Promise<types.PolicyDiffResponse>;
    policyExplain(request: types.PolicyExplainRequest, options?: CallOptions): Promise<types.PolicyExplainResponse>;
    policyActivate(request: types.PolicyActivateRequest, options?: CallOptions): Promise<types.PolicyActivateResponse>;
    maintenanceAbandonSegment(request: types.SegmentAbandonmentRequest, options?: CallOptions): Promise<types.SegmentAbandonmentResponse>;
    providerMigrationManage(request: types.ProviderMigrationRequest, options?: CallOptions): Promise<types.ProviderMigrationResponse>;
    repositoryManage(request: types.RepositoryRequest, options?: CallOptions): Promise<types.RepositoryResponse>;
    backupManage(request: types.BackupRequest, options?: CallOptions): Promise<types.BackupResponse>;
    backupList(request: types.BackupListRequest, options?: CallOptions): Promise<types.BackupListResponse>;
    tenantPurgeManage(request: types.TenantPurgeRequest, options?: CallOptions): Promise<types.TenantPurgeResponse>;
    upgradeManage(request: types.UpgradeRequest, options?: CallOptions): Promise<types.UpgradeResponse>;
    logQueryExecute(request: types.LogQueryRequest, options?: CallOptions): Promise<types.LogQueryResponse>;
    logQuerySession(request: types.LogQuerySessionRequest, options?: CallOptions): Promise<types.LogQueryResponse>;
    logQueryCancel(request: types.LogQueryCancelRequest, options?: CallOptions): Promise<types.LogQueryCancelResponse>;
}
