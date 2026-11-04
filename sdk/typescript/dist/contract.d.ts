export declare const apiVersion = "positron.v1";
export declare const schemaDigest = "413f1f3eb9cfef33bde9701c670dfa33808d4896042d14ca0713eabd151bdddf";
export declare const schemas: {
    readonly ApiKeyFailure: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly code: {
                readonly enum: readonly ["invalid_request", "authentication_rejected", "stale_generation", "idempotency_conflict", "key_unavailable", "administration_unavailable"];
                readonly type: "string";
            };
        };
        readonly required: readonly ["code"];
        readonly type: "object";
    };
    readonly ApiKeyRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly action: {
                readonly $ref: "#/components/schemas/KeyAction";
            };
            readonly expected_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly expires_at_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly idempotency_key: {
                readonly format: "uuid";
                readonly type: "string";
            };
            readonly principal: {
                readonly format: "uuid";
                readonly type: "string";
            };
            readonly scope: {
                readonly $ref: "#/components/schemas/KeyScope";
            };
            readonly target_tenant: {
                readonly description: "Explicit administrative target tenant for an API-key lifecycle action; never data-plane attribution.";
                readonly format: "uuid";
                readonly type: "string";
            };
        };
        readonly required: readonly ["action"];
        readonly type: "object";
    };
    readonly ApiKeyResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly keys: {
                readonly items: {
                    readonly $ref: "#/components/schemas/KeyDescriptor";
                };
                readonly maxItems: 48;
                readonly type: "array";
            };
            readonly principal: {
                readonly anyOf: readonly [{
                    readonly type: "string";
                }, {
                    readonly type: "null";
                }];
            };
            readonly secret: {
                readonly anyOf: readonly [{
                    readonly type: "string";
                }, {
                    readonly type: "null";
                }];
                readonly description: "Present only on the first successful create or rotate response. Never redisplayed on retry.";
            };
        };
        readonly required: readonly ["keys", "principal", "secret"];
        readonly type: "object";
    };
    readonly AuthenticatedTimeRange: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly earliest_unix_nanos: {
                readonly format: "int64-json";
                readonly type: "integer";
            };
            readonly latest_unix_nanos: {
                readonly format: "int64-json";
                readonly type: "integer";
            };
            readonly provenance: {
                readonly enum: readonly ["known", "missing_source_time", "invalid_source_time", "legacy_format", "unavailable"];
                readonly type: "string";
            };
        };
        readonly required: readonly ["provenance"];
        readonly type: "object";
    };
    readonly BackupListEntry: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly created_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly manifest_checksum: {
                readonly pattern: "^[0-9a-f]{64}$";
                readonly type: "string";
            };
            readonly retain_until_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly snapshot_id: {
                readonly pattern: "^[0-9a-f]{32}$";
                readonly type: "string";
            };
        };
        readonly required: readonly ["snapshot_id", "manifest_checksum", "created_unix_seconds", "retain_until_unix_seconds"];
        readonly type: "object";
    };
    readonly BackupListRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly cursor: {
                readonly maxLength: 176;
                readonly minLength: 176;
                readonly type: "string";
            };
            readonly limit: {
                readonly maximum: 128;
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly repository_id: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["repository_id", "limit"];
        readonly type: "object";
    };
    readonly BackupListResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly entries: {
                readonly items: {
                    readonly $ref: "#/components/schemas/BackupListEntry";
                };
                readonly maxItems: 128;
                readonly type: "array";
            };
            readonly next_cursor: {
                readonly maxLength: 176;
                readonly minLength: 176;
                readonly type: "string";
            };
            readonly registry_generation_checksum: {
                readonly pattern: "^[0-9a-f]{64}$";
                readonly type: "string";
            };
            readonly repository: {
                readonly $ref: "#/components/schemas/RepositoryIdentity";
            };
        };
        readonly required: readonly ["repository", "entries"];
        readonly type: "object";
    };
    readonly BackupRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly action: {
                readonly type: "string";
            };
            readonly aws_s3: {
                readonly $ref: "#/components/schemas/RepositoryAwsS3Target";
            };
            readonly azure_blob: {
                readonly $ref: "#/components/schemas/RepositoryAzureBlobTarget";
            };
            readonly expected_catalog_generation: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly expected_manifest_checksum: {
                readonly pattern: "^[0-9a-f]{64}$";
                readonly type: "string";
            };
            readonly expected_operation_revision: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly google_cloud_storage: {
                readonly $ref: "#/components/schemas/RepositoryGoogleCloudStorageTarget";
            };
            readonly idempotency_key: {
                readonly type: "string";
            };
            readonly locator: {
                readonly type: "string";
            };
            readonly operation_id: {
                readonly type: "string";
            };
            readonly repository_id: {
                readonly type: "string";
            };
            readonly retention_seconds: {
                readonly format: "uint64-json";
                readonly maximum: 315360000;
                readonly minimum: 60;
                readonly type: "integer";
            };
            readonly snapshot_id: {
                readonly pattern: "^[0-9a-f]{32}$";
                readonly type: "string";
            };
        };
        readonly required: readonly ["action"];
        readonly type: "object";
    };
    readonly BackupResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly cleanup_pending: {
                readonly type: "boolean";
            };
            readonly kind: {
                readonly enum: readonly ["snapshot", "retention", "verification"];
                readonly type: "string";
            };
            readonly operation: {
                readonly $ref: "#/components/schemas/RepositoryOperation";
            };
            readonly operation_revision: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly receipt: {
                readonly $ref: "#/components/schemas/BackupSnapshotReceipt";
            };
            readonly repository: {
                readonly $ref: "#/components/schemas/RepositoryIdentity";
            };
            readonly restored_publication: {
                readonly $ref: "#/components/schemas/BackupRestoredPublication";
            };
            readonly retention_receipt: {
                readonly $ref: "#/components/schemas/BackupRetentionReceipt";
            };
            readonly terminal_error_code: {
                readonly enum: readonly ["handler_rejected", "legacy_unknown", "backup_retention_not_due"];
                readonly type: "string";
            };
            readonly verification_report: {
                readonly maxLength: 2048;
                readonly pattern: "^[0-9a-f]+$";
                readonly type: "string";
            };
            readonly verification_report_checksum: {
                readonly pattern: "^[0-9a-f]{64}$";
                readonly type: "string";
            };
        };
        readonly required: readonly ["operation", "kind", "cleanup_pending", "operation_revision"];
        readonly type: "object";
    };
    readonly BackupRestoredPublication: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly capture_operation_id: {
                readonly type: "string";
            };
            readonly capture_request_digest: {
                readonly type: "string";
            };
            readonly current_registry_generation_checksum: {
                readonly type: "string";
            };
            readonly manifest_checksum: {
                readonly type: "string";
            };
            readonly restore_idempotency_key: {
                readonly type: "string";
            };
            readonly restore_intent_digest: {
                readonly type: "string";
            };
            readonly restore_origin_transaction: {
                readonly type: "string";
            };
            readonly retain_until_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly source_catalog_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly source_catalog_identity: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["manifest_checksum", "current_registry_generation_checksum", "source_catalog_identity", "source_catalog_generation", "retain_until_unix_seconds", "restore_origin_transaction", "restore_intent_digest", "capture_operation_id", "capture_request_digest", "restore_idempotency_key"];
        readonly type: "object";
    };
    readonly BackupRetentionReceipt: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly already_absent_objects: {
                readonly maximum: 4294967295;
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly deleted_objects: {
                readonly maximum: 4294967295;
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly manifest_checksum: {
                readonly pattern: "^[0-9a-f]{64}$";
                readonly type: "string";
            };
            readonly registry_generation_checksum: {
                readonly pattern: "^[0-9a-f]{64}$";
                readonly type: "string";
            };
            readonly retained_shared_objects: {
                readonly maximum: 4294967295;
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly snapshot_id: {
                readonly pattern: "^[0-9a-f]{32}$";
                readonly type: "string";
            };
        };
        readonly required: readonly ["snapshot_id", "manifest_checksum", "registry_generation_checksum", "deleted_objects", "already_absent_objects", "retained_shared_objects"];
        readonly type: "object";
    };
    readonly BackupSnapshotReceipt: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly catalog_generation: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly catalog_identity: {
                readonly pattern: "^[0-9a-f]{64}$";
                readonly type: "string";
            };
            readonly manifest_checksum: {
                readonly pattern: "^[0-9a-f]{64}$";
                readonly type: "string";
            };
            readonly registry_generation_checksum: {
                readonly pattern: "^[0-9a-f]{64}$";
                readonly type: "string";
            };
            readonly retain_until_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly reused_bytes: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly uploaded_bytes: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
        };
        readonly required: readonly ["manifest_checksum", "catalog_generation", "catalog_identity", "uploaded_bytes", "reused_bytes", "retain_until_unix_seconds", "registry_generation_checksum"];
        readonly type: "object";
    };
    readonly Capability: {
        readonly enum: readonly [0, 1, 2, 3, 4, 5];
        readonly type: "integer";
        readonly "x-enumDeprecated": readonly [false, false, false, false, false, false];
        readonly "x-enumNames": readonly ["UNSPECIFIED", "CANONICAL_PUBLIC_INTERFACE", "RELEASE_ONE_QUERY", "METRICS", "QUERY_SESSIONS", "QUERY_TAIL"];
    };
    readonly CapabilityAvailability: {
        readonly enum: readonly [0, 1, 2, 3, 4];
        readonly type: "integer";
        readonly "x-enumDeprecated": readonly [false, false, false, false, false];
        readonly "x-enumNames": readonly ["UNSPECIFIED", "IMPLEMENTED", "UNAVAILABLE", "UNSUPPORTED", "VERSION_INCOMPATIBLE"];
    };
    readonly CapabilityRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly api_major: {
                readonly deprecated: false;
                readonly maximum: 4294967295;
                readonly minimum: 0;
                readonly type: "integer";
                readonly "x-protobuf-field-number": 1;
            };
            readonly capability: {
                readonly $ref: "#/components/schemas/Capability";
                readonly deprecated: false;
                readonly "x-protobuf-field-number": 2;
            };
        };
        readonly type: "object";
    };
    readonly CapabilityResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly api_major: {
                readonly deprecated: false;
                readonly maximum: 4294967295;
                readonly minimum: 0;
                readonly type: "integer";
                readonly "x-protobuf-field-number": 1;
            };
            readonly availability: {
                readonly $ref: "#/components/schemas/CapabilityAvailability";
                readonly deprecated: false;
                readonly "x-protobuf-field-number": 3;
            };
            readonly capability: {
                readonly $ref: "#/components/schemas/Capability";
                readonly deprecated: false;
                readonly "x-protobuf-field-number": 6;
            };
            readonly deprecation: {
                readonly $ref: "#/components/schemas/DeprecationState";
                readonly deprecated: false;
                readonly "x-protobuf-field-number": 5;
            };
            readonly refusal: {
                readonly $ref: "#/components/schemas/PublicError";
                readonly deprecated: false;
                readonly nullable: true;
                readonly "x-protobuf-field-number": 4;
            };
            readonly schema_digest: {
                readonly deprecated: false;
                readonly type: "string";
                readonly "x-protobuf-field-number": 2;
            };
        };
        readonly type: "object";
    };
    readonly CompletionState: {
        readonly oneOf: readonly [{
            readonly enum: readonly [0, 1, 2];
            readonly type: "integer";
        }, {
            readonly enum: readonly ["COMPLETION_STATE_UNSPECIFIED", "COMPLETION_STATE_REJECTED", "COMPLETION_STATE_AMBIGUOUS"];
            readonly type: "string";
        }];
        readonly "x-enumDeprecated": readonly [false, false, false];
        readonly "x-enumNames": readonly ["UNSPECIFIED", "REJECTED", "AMBIGUOUS"];
    };
    readonly CompletionStateProtoJson: {
        readonly enum: readonly ["COMPLETION_STATE_UNSPECIFIED", "COMPLETION_STATE_REJECTED"];
        readonly type: "string";
    };
    readonly DeprecationState: {
        readonly enum: readonly [0, 1, 2];
        readonly type: "integer";
        readonly "x-enumDeprecated": readonly [false, false, false];
        readonly "x-enumNames": readonly ["UNSPECIFIED", "CURRENT", "DEPRECATED"];
    };
    readonly FailureSource: {
        readonly oneOf: readonly [{
            readonly enum: readonly [0, 1, 2, 3, 4];
            readonly type: "integer";
        }, {
            readonly enum: readonly ["FAILURE_SOURCE_UNSPECIFIED", "FAILURE_SOURCE_CAPABILITY_NEGOTIATION", "FAILURE_SOURCE_GRPC_DECODE", "FAILURE_SOURCE_HTTP_DECODE", "FAILURE_SOURCE_QUERY_EXECUTION"];
            readonly type: "string";
        }];
        readonly "x-enumDeprecated": readonly [false, false, false, false, false];
        readonly "x-enumNames": readonly ["UNSPECIFIED", "CAPABILITY_NEGOTIATION", "GRPC_DECODE", "HTTP_DECODE", "QUERY_EXECUTION"];
    };
    readonly FailureSourceProtoJson: {
        readonly enum: readonly ["FAILURE_SOURCE_UNSPECIFIED", "FAILURE_SOURCE_CAPABILITY_NEGOTIATION", "FAILURE_SOURCE_GRPC_DECODE", "FAILURE_SOURCE_HTTP_DECODE", "FAILURE_SOURCE_QUERY_EXECUTION"];
        readonly type: "string";
    };
    readonly IntegrityQuarantineFinding: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly base_position: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly event_range: {
                readonly $ref: "#/components/schemas/AuthenticatedTimeRange";
            };
            readonly ingest_range: {
                readonly $ref: "#/components/schemas/AuthenticatedTimeRange";
            };
            readonly segment: {
                readonly pattern: "^[0-9a-f]{32}$";
                readonly type: "string";
            };
            readonly shard: {
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly signal: {
                readonly enum: readonly ["logs", "traces"];
                readonly type: "string";
            };
            readonly tenant: {
                readonly format: "uuid";
                readonly type: "string";
            };
        };
        readonly required: readonly ["tenant", "signal", "shard", "segment", "base_position", "event_range", "ingest_range"];
        readonly type: "object";
    };
    readonly KeyAction: {
        readonly enum: readonly ["create", "list", "rotate", "revoke", "scope_inspect"];
        readonly type: "string";
    };
    readonly KeyDescriptor: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly active: {
                readonly type: "boolean";
            };
            readonly expires_at_unix_seconds: {
                readonly anyOf: readonly [{
                    readonly minimum: 1;
                    readonly type: "integer";
                }, {
                    readonly type: "null";
                }];
            };
            readonly generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly principal: {
                readonly format: "uuid";
                readonly type: "string";
            };
            readonly scope: {
                readonly $ref: "#/components/schemas/KeyScope";
            };
        };
        readonly required: readonly ["principal", "scope", "active", "expires_at_unix_seconds", "generation"];
        readonly type: "object";
    };
    readonly KeyScope: {
        readonly enum: readonly ["ingest", "query", "tenant_administration", "system_administration"];
        readonly type: "string";
    };
    readonly LogQueryAcknowledgement: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly digest: {
                readonly contentEncoding: "base64";
                readonly type: "string";
                readonly "x-protobuf-field-number": 2;
            };
            readonly sequence: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 1;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryAffectedRange: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly earliestNanoseconds: {
                readonly format: "int64";
                readonly pattern: "^-?[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 2;
            };
            readonly latestNanoseconds: {
                readonly format: "int64";
                readonly pattern: "^-?[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 3;
            };
            readonly temporalAxis: {
                readonly type: "string";
                readonly "x-protobuf-field-number": 1;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryArray: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly values: {
                readonly items: {
                    readonly $ref: "#/components/schemas/LogQueryValue";
                };
                readonly type: "array";
                readonly "x-protobuf-field-number": 1;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryBatch: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly digest: {
                readonly contentEncoding: "base64";
                readonly type: "string";
                readonly "x-protobuf-field-number": 4;
            };
            readonly priorDigest: {
                readonly contentEncoding: "base64";
                readonly type: "string";
                readonly "x-protobuf-field-number": 3;
            };
            readonly rows: {
                readonly items: {
                    readonly $ref: "#/components/schemas/LogQueryRow";
                };
                readonly type: "array";
                readonly "x-protobuf-field-number": 2;
            };
            readonly sequence: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 1;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryBudget: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly cpuWorkUnits: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 6;
            };
            readonly decodedRecords: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 2;
            };
            readonly maximumTimeRangeNanoseconds: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 8;
            };
            readonly memoryBytes: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 5;
            };
            readonly outputBytes: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 4;
            };
            readonly outputRows: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 3;
            };
            readonly scannedBytes: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 1;
            };
            readonly wallSeconds: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 7;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryCancelRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly query: {
                readonly contentEncoding: "base64";
                readonly type: "string";
                readonly "x-protobuf-field-number": 1;
            };
            readonly tail: {
                readonly contentEncoding: "base64";
                readonly type: "string";
                readonly "x-protobuf-field-number": 2;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryCancelResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly cancelled: {
                readonly type: "boolean";
                readonly "x-protobuf-field-number": 1;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryCell: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly missing: {
                readonly $ref: "#/components/schemas/LogQueryMissing";
                readonly "x-protobuf-field-number": 5;
            };
            readonly nativeValue: {
                readonly $ref: "#/components/schemas/LogQueryValue";
                readonly "x-protobuf-field-number": 1;
            };
            readonly occurrences: {
                readonly $ref: "#/components/schemas/LogQueryOccurrences";
                readonly "x-protobuf-field-number": 2;
            };
            readonly timestamp: {
                readonly $ref: "#/components/schemas/LogQueryTimestamp";
                readonly "x-protobuf-field-number": 3;
            };
            readonly unsignedInteger: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 4;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryColumn: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly name: {
                readonly type: "string";
                readonly "x-protobuf-field-number": 1;
            };
            readonly nullable: {
                readonly type: "boolean";
                readonly "x-protobuf-field-number": 3;
            };
            readonly valueType: {
                readonly type: "string";
                readonly "x-protobuf-field-number": 2;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryEvent: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly batch: {
                readonly $ref: "#/components/schemas/LogQueryBatch";
                readonly "x-protobuf-field-number": 2;
            };
            readonly header: {
                readonly $ref: "#/components/schemas/LogQueryHeader";
                readonly "x-protobuf-field-number": 1;
            };
            readonly terminal: {
                readonly $ref: "#/components/schemas/LogQueryTerminal";
                readonly "x-protobuf-field-number": 3;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryHeader: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly columns: {
                readonly items: {
                    readonly $ref: "#/components/schemas/LogQueryColumn";
                };
                readonly type: "array";
                readonly "x-protobuf-field-number": 1;
            };
            readonly effectiveBudget: {
                readonly $ref: "#/components/schemas/LogQueryBudget";
                readonly "x-protobuf-field-number": 4;
            };
            readonly initialCursor: {
                readonly contentEncoding: "base64";
                readonly type: "string";
                readonly "x-protobuf-field-number": 6;
            };
            readonly lease: {
                readonly $ref: "#/components/schemas/LogQueryLease";
                readonly "x-protobuf-field-number": 5;
            };
            readonly ordering: {
                readonly items: {
                    readonly $ref: "#/components/schemas/LogQueryOrdering";
                };
                readonly type: "array";
                readonly "x-protobuf-field-number": 3;
            };
            readonly snapshot: {
                readonly $ref: "#/components/schemas/LogQuerySnapshot";
                readonly "x-protobuf-field-number": 2;
            };
            readonly tailPhase: {
                readonly type: "string";
                readonly "x-protobuf-field-number": 7;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryKeyValue: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly key: {
                readonly type: "string";
                readonly "x-protobuf-field-number": 1;
            };
            readonly value: {
                readonly $ref: "#/components/schemas/LogQueryValue";
                readonly "x-protobuf-field-number": 2;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryLease: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly expiryUnixSeconds: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 2;
            };
            readonly identity: {
                readonly contentEncoding: "base64";
                readonly type: "string";
                readonly "x-protobuf-field-number": 1;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryMarker: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly action: {
                readonly type: "string";
                readonly "x-protobuf-field-number": 1;
            };
            readonly originalKind: {
                readonly type: "string";
                readonly "x-protobuf-field-number": 2;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryMissing: {
        readonly additionalProperties: false;
        readonly properties: {};
        readonly type: "object";
    };
    readonly LogQueryNull: {
        readonly additionalProperties: false;
        readonly properties: {};
        readonly type: "object";
    };
    readonly LogQueryObject: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly entries: {
                readonly items: {
                    readonly $ref: "#/components/schemas/LogQueryKeyValue";
                };
                readonly type: "array";
                readonly "x-protobuf-field-number": 1;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryOccurrences: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly values: {
                readonly items: {
                    readonly $ref: "#/components/schemas/LogQueryValue";
                };
                readonly type: "array";
                readonly "x-protobuf-field-number": 1;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryOrdering: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly column: {
                readonly type: "string";
                readonly "x-protobuf-field-number": 1;
            };
            readonly direction: {
                readonly type: "string";
                readonly "x-protobuf-field-number": 3;
            };
            readonly valueType: {
                readonly type: "string";
                readonly "x-protobuf-field-number": 2;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly budget: {
                readonly $ref: "#/components/schemas/LogQueryBudget";
                readonly "x-protobuf-field-number": 2;
            };
            readonly pipeline: {
                readonly type: "string";
                readonly "x-protobuf-field-number": 1;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly events: {
                readonly items: {
                    readonly $ref: "#/components/schemas/LogQueryEvent";
                };
                readonly type: "array";
                readonly "x-protobuf-field-number": 1;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryRow: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly cells: {
                readonly items: {
                    readonly $ref: "#/components/schemas/LogQueryCell";
                };
                readonly type: "array";
                readonly "x-protobuf-field-number": 1;
            };
            readonly replayed: {
                readonly type: "boolean";
                readonly "x-protobuf-field-number": 2;
            };
        };
        readonly type: "object";
    };
    readonly LogQuerySessionRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly batchLimit: {
                readonly type: "integer";
                readonly "x-protobuf-field-number": 3;
            };
            readonly execute: {
                readonly $ref: "#/components/schemas/LogQueryRequest";
                readonly "x-protobuf-field-number": 1;
            };
            readonly resume: {
                readonly contentEncoding: "base64";
                readonly type: "string";
                readonly "x-protobuf-field-number": 2;
            };
            readonly tail: {
                readonly $ref: "#/components/schemas/LogQueryTailRequest";
                readonly "x-protobuf-field-number": 4;
            };
        };
        readonly type: "object";
    };
    readonly LogQuerySnapshot: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly frontier: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 3;
            };
            readonly generation: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 2;
            };
            readonly identity: {
                readonly contentEncoding: "base64";
                readonly type: "string";
                readonly "x-protobuf-field-number": 1;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryStats: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly cpuWorkUnits: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 6;
            };
            readonly cumulativeBudget: {
                readonly $ref: "#/components/schemas/LogQueryBudget";
                readonly "x-protobuf-field-number": 10;
            };
            readonly decodedRecords: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 3;
            };
            readonly lastSequence: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 8;
            };
            readonly limitingBudget: {
                readonly type: "string";
                readonly "x-protobuf-field-number": 13;
            };
            readonly memoryPeakBytes: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 5;
            };
            readonly outputBytes: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 4;
            };
            readonly records: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 1;
            };
            readonly reducedPruning: {
                readonly type: "boolean";
                readonly "x-protobuf-field-number": 14;
            };
            readonly repeatedBatchCount: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 12;
            };
            readonly resultDigest: {
                readonly contentEncoding: "base64";
                readonly type: "string";
                readonly "x-protobuf-field-number": 9;
            };
            readonly resumeCount: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 11;
            };
            readonly scannedBytes: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 2;
            };
            readonly wallSeconds: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 7;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryStopReason: {
        readonly enum: readonly [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17];
        readonly type: "integer";
        readonly "x-enumDeprecated": readonly [false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false];
        readonly "x-enumNames": readonly ["UNSPECIFIED", "UNAUTHORIZED", "IDEMPOTENCY_CONFLICT", "INVALID_BUDGET", "BUDGET_EXHAUSTED", "INVALID_CURSOR", "SNAPSHOT_EXPIRED", "AUTHORIZATION_CHANGED", "CANCELLED", "RESOURCE_ADMISSION_REFUSED", "RESOURCE_EXHAUSTED", "UNSUPPORTED_QUERY", "STORE_UNAVAILABLE", "INCOMPLETE_DATA", "MALFORMED_PERSISTENT_DATA", "INTERNAL", "DISCONNECTED", "CONSUMER_LAGGED"];
    };
    readonly LogQueryTailRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly acknowledgement: {
                readonly $ref: "#/components/schemas/LogQueryAcknowledgement";
                readonly "x-protobuf-field-number": 4;
            };
            readonly cursor: {
                readonly contentEncoding: "base64";
                readonly type: "string";
                readonly "x-protobuf-field-number": 2;
            };
            readonly historicalRows: {
                readonly type: "integer";
                readonly "x-protobuf-field-number": 3;
            };
            readonly query: {
                readonly $ref: "#/components/schemas/LogQueryRequest";
                readonly "x-protobuf-field-number": 1;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryTerminal: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly affectedRanges: {
                readonly items: {
                    readonly $ref: "#/components/schemas/LogQueryAffectedRange";
                };
                readonly type: "array";
                readonly "x-protobuf-field-number": 4;
            };
            readonly continuationCursor: {
                readonly contentEncoding: "base64";
                readonly type: "string";
                readonly "x-protobuf-field-number": 5;
            };
            readonly reason: {
                readonly type: "string";
                readonly "x-protobuf-field-number": 2;
            };
            readonly state: {
                readonly type: "string";
                readonly "x-protobuf-field-number": 1;
            };
            readonly stats: {
                readonly $ref: "#/components/schemas/LogQueryStats";
                readonly "x-protobuf-field-number": 3;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryTimestamp: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly provenance: {
                readonly type: "string";
                readonly "x-protobuf-field-number": 2;
            };
            readonly quality: {
                readonly type: "string";
                readonly "x-protobuf-field-number": 3;
            };
            readonly sourceValue: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 4;
            };
            readonly unixNanoseconds: {
                readonly format: "int64";
                readonly pattern: "^-?[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 1;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryTruncated: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly action: {
                readonly type: "string";
                readonly "x-protobuf-field-number": 1;
            };
            readonly value: {
                readonly $ref: "#/components/schemas/LogQueryValue";
                readonly "x-protobuf-field-number": 2;
            };
        };
        readonly type: "object";
    };
    readonly LogQueryValue: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly arrayValue: {
                readonly $ref: "#/components/schemas/LogQueryArray";
                readonly "x-protobuf-field-number": 7;
            };
            readonly booleanValue: {
                readonly type: "boolean";
                readonly "x-protobuf-field-number": 2;
            };
            readonly bytesValue: {
                readonly contentEncoding: "base64";
                readonly type: "string";
                readonly "x-protobuf-field-number": 6;
            };
            readonly floatBits: {
                readonly format: "uint64";
                readonly pattern: "^[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 4;
            };
            readonly integerValue: {
                readonly format: "int64";
                readonly pattern: "^-?[0-9]+$";
                readonly type: "string";
                readonly "x-protobuf-field-number": 3;
            };
            readonly markerValue: {
                readonly $ref: "#/components/schemas/LogQueryMarker";
                readonly "x-protobuf-field-number": 9;
            };
            readonly nullValue: {
                readonly $ref: "#/components/schemas/LogQueryNull";
                readonly "x-protobuf-field-number": 1;
            };
            readonly objectValue: {
                readonly $ref: "#/components/schemas/LogQueryObject";
                readonly "x-protobuf-field-number": 8;
            };
            readonly textValue: {
                readonly type: "string";
                readonly "x-protobuf-field-number": 5;
            };
            readonly truncatedValue: {
                readonly $ref: "#/components/schemas/LogQueryTruncated";
                readonly "x-protobuf-field-number": 10;
            };
        };
        readonly type: "object";
    };
    readonly MaintenanceControlResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly action: {
                readonly enum: readonly ["pause", "resume"];
                readonly type: "string";
            };
            readonly audit_position: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly pause_until_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly resource_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly task: {
                readonly $ref: "#/components/schemas/MaintenanceTaskAcknowledgement";
            };
        };
        readonly required: readonly ["task", "audit_position", "action"];
        readonly type: "object";
    };
    readonly MaintenanceExplainRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly identity: {
                readonly maxLength: 32;
                readonly minLength: 32;
                readonly pattern: "^[0-9a-fA-F]{32}$";
                readonly type: "string";
            };
        };
        readonly required: readonly ["identity"];
        readonly type: "object";
    };
    readonly MaintenanceExplainResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly task: {
                readonly $ref: "#/components/schemas/MaintenanceTaskStatus";
            };
        };
        readonly required: readonly ["task"];
        readonly type: "object";
    };
    readonly MaintenancePauseRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly duration_seconds: {
                readonly format: "uint64-json";
                readonly maximum: 86400;
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly idempotency_key: {
                readonly format: "uuid";
                readonly type: "string";
            };
            readonly identity: {
                readonly maxLength: 32;
                readonly minLength: 32;
                readonly pattern: "^[0-9a-fA-F]{32}$";
                readonly type: "string";
            };
            readonly resource_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
        };
        readonly required: readonly ["identity", "resource_generation", "duration_seconds", "idempotency_key"];
        readonly type: "object";
    };
    readonly MaintenanceResourceReservations: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly batch_items: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly buffer_cache_bytes: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly cpu_work_units: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly disk_headroom_bytes: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly file_descriptors: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly io_permits: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly lease_slots: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly memory_bytes: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly queue_slots: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly retry_slots: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly task_slots: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
        };
        readonly required: readonly ["memory_bytes", "queue_slots", "task_slots", "buffer_cache_bytes", "batch_items", "lease_slots", "retry_slots", "io_permits", "cpu_work_units", "file_descriptors", "disk_headroom_bytes"];
        readonly type: "object";
    };
    readonly MaintenanceResumeRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly idempotency_key: {
                readonly format: "uuid";
                readonly type: "string";
            };
            readonly identity: {
                readonly maxLength: 32;
                readonly minLength: 32;
                readonly pattern: "^[0-9a-fA-F]{32}$";
                readonly type: "string";
            };
        };
        readonly required: readonly ["identity", "idempotency_key"];
        readonly type: "object";
    };
    readonly MaintenanceRunRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly class: {
                readonly enum: readonly ["compaction"];
                readonly type: "string";
            };
            readonly idempotency_key: {
                readonly format: "uuid";
                readonly type: "string";
            };
            readonly shard: {
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly signal: {
                readonly enum: readonly ["logs", "traces"];
                readonly type: "string";
            };
            readonly tenant: {
                readonly format: "uuid";
                readonly type: "string";
            };
        };
        readonly required: readonly ["class", "tenant", "signal", "shard", "idempotency_key"];
        readonly type: "object";
    };
    readonly MaintenanceRunResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly resource_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly task: {
                readonly $ref: "#/components/schemas/MaintenanceTaskAcknowledgement";
            };
        };
        readonly required: readonly ["task", "resource_generation"];
        readonly type: "object";
    };
    readonly MaintenanceStatusRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly cursor: {
                readonly maxLength: 32;
                readonly minLength: 32;
                readonly pattern: "^[0-9a-fA-F]{32}$";
                readonly type: "string";
            };
            readonly limit: {
                readonly maximum: 32;
                readonly minimum: 1;
                readonly type: "integer";
            };
        };
        readonly type: "object";
    };
    readonly MaintenanceStatusResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly deferred: {
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly integrity_findings: {
                readonly items: {
                    readonly $ref: "#/components/schemas/IntegrityQuarantineFinding";
                };
                readonly maxItems: 64;
                readonly type: "array";
            };
            readonly next_cursor: {
                readonly pattern: "^[0-9a-f]{32}$";
                readonly type: "string";
            };
            readonly queued: {
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly returned: {
                readonly maximum: 32;
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly running: {
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly tasks: {
                readonly items: {
                    readonly $ref: "#/components/schemas/MaintenanceTaskStatus";
                };
                readonly maxItems: 32;
                readonly type: "array";
            };
            readonly terminal: {
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly total: {
                readonly maximum: 128;
                readonly minimum: 0;
                readonly type: "integer";
            };
        };
        readonly required: readonly ["tasks", "returned", "total", "queued", "running", "deferred", "terminal", "integrity_findings"];
        readonly type: "object";
    };
    readonly MaintenanceTaskAcknowledgement: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly class: {
                readonly maxLength: 64;
                readonly minLength: 1;
                readonly type: "string";
            };
            readonly identity: {
                readonly pattern: "^[0-9a-f]{32}$";
                readonly type: "string";
            };
            readonly scope: {
                readonly maxLength: 128;
                readonly minLength: 1;
                readonly type: "string";
            };
            readonly submitted_at_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
        };
        readonly required: readonly ["identity", "class", "scope", "submitted_at_unix_seconds"];
        readonly type: "object";
    };
    readonly MaintenanceTaskStatus: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly automatic_resume_at_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly backlog_age_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly blocked_precondition: {
                readonly enum: readonly ["maintenance_pause_active", "maintenance_window_active", "conflict_owner_active", "scheduled_start_time", "clock_uncertain_destructive_schedule"];
                readonly type: "string";
            };
            readonly cancellation_requested: {
                readonly type: "boolean";
            };
            readonly capacity_risk: {
                readonly enum: readonly ["foreground_reservation", "recovery_reserve"];
                readonly type: "string";
            };
            readonly checkpoint_completed_inputs: {
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly checkpoint_sequence: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly class: {
                readonly maxLength: 64;
                readonly minLength: 1;
                readonly type: "string";
            };
            readonly conflict_owner: {
                readonly pattern: "^[0-9a-f]{32}$";
                readonly type: "string";
            };
            readonly estimated_output_object_amplification_milli: {
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly expected_foreground_impact: {
                readonly $ref: "#/components/schemas/MaintenanceResourceReservations";
            };
            readonly identity: {
                readonly pattern: "^[0-9a-f]{32}$";
                readonly type: "string";
            };
            readonly input_object_count: {
                readonly maximum: 16;
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly last_progress_at_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly maintenance_window_until_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly no_durable_progress_slo_breached: {
                readonly type: "boolean";
            };
            readonly no_durable_progress_slo_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly output_object_count: {
                readonly maximum: 16;
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly pause_until_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly phase: {
                readonly enum: readonly ["queued", "running", "deferred", "cancelled", "succeeded", "failed"];
                readonly type: "string";
            };
            readonly recovery_impact: {
                readonly enum: readonly ["unaffected"];
                readonly type: "string";
            };
            readonly reservations: {
                readonly $ref: "#/components/schemas/MaintenanceResourceReservations";
            };
            readonly resource_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly retention_impact: {
                readonly enum: readonly ["unaffected", "eligibility_unknown"];
                readonly type: "string";
            };
            readonly safe_actions: {
                readonly items: {
                    readonly enum: readonly ["pause", "resume"];
                    readonly type: "string";
                };
                readonly maxItems: 1;
                readonly type: "array";
            };
            readonly scope: {
                readonly maxLength: 128;
                readonly minLength: 1;
                readonly type: "string";
            };
            readonly submitted_at_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly terminal_failure_class: {
                readonly enum: readonly ["identity_mismatch", "stale_generation", "unclassified"];
                readonly type: "string";
            };
            readonly terminal_outcome: {
                readonly enum: readonly ["cancelled", "succeeded", "failed"];
                readonly type: "string";
            };
        };
        readonly required: readonly ["identity", "class", "scope", "phase", "submitted_at_unix_seconds", "cancellation_requested"];
        readonly type: "object";
    };
    readonly MaintenanceWindowRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly deferred_classes: {
                readonly items: {
                    readonly enum: readonly ["compaction", "schema_promotion", "schema_demotion", "repository_verification", "backup_snapshot", "durable_export"];
                    readonly type: "string";
                };
                readonly maxItems: 6;
                readonly minItems: 1;
                readonly type: "array";
                readonly uniqueItems: true;
            };
            readonly duration_seconds: {
                readonly format: "uint64-json";
                readonly maximum: 86400;
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly expected_catalog_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly idempotency_key: {
                readonly format: "uuid";
                readonly type: "string";
            };
        };
        readonly required: readonly ["deferred_classes", "expected_catalog_generation", "duration_seconds", "idempotency_key"];
        readonly type: "object";
    };
    readonly MaintenanceWindowResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly audit_position: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly catalog_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly deferred_classes: {
                readonly items: {
                    readonly enum: readonly ["compaction", "schema_promotion", "schema_demotion", "repository_verification", "backup_snapshot", "durable_export"];
                    readonly type: "string";
                };
                readonly maxItems: 6;
                readonly minItems: 1;
                readonly type: "array";
                readonly uniqueItems: true;
            };
            readonly until_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
        };
        readonly required: readonly ["deferred_classes", "until_unix_seconds", "catalog_generation", "audit_position"];
        readonly type: "object";
    };
    readonly OnlineVerificationReport: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly catalog_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly continuation: {
                readonly maxLength: 272;
                readonly minLength: 272;
                readonly pattern: "^[0-9A-Fa-f]{272}$";
                readonly type: "string";
            };
            readonly examined_bytes: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly examined_segments: {
                readonly maximum: 128;
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly findings: {
                readonly items: {
                    readonly $ref: "#/components/schemas/IntegrityQuarantineFinding";
                };
                readonly maxItems: 64;
                readonly type: "array";
            };
            readonly omitted_segments: {
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly outcome: {
                readonly enum: readonly ["verified", "incomplete", "stale", "quarantined", "fenced"];
                readonly type: "string";
            };
            readonly report_checksum: {
                readonly maxLength: 64;
                readonly minLength: 64;
                readonly pattern: "^[0-9a-f]{64}$";
                readonly type: "string";
            };
            readonly report_version: {
                readonly const: 1;
                readonly type: "integer";
            };
            readonly shard: {
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly signal: {
                readonly enum: readonly ["logs", "traces"];
                readonly type: "string";
            };
            readonly tenant: {
                readonly format: "uuid";
                readonly type: "string";
            };
            readonly verification_complete: {
                readonly type: "boolean";
            };
        };
        readonly required: readonly ["report_version", "tenant", "signal", "shard", "catalog_generation", "examined_segments", "examined_bytes", "omitted_segments", "outcome", "verification_complete", "report_checksum", "findings"];
        readonly type: "object";
    };
    readonly OnlineVerificationRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly continuation: {
                readonly maxLength: 272;
                readonly minLength: 272;
                readonly pattern: "^[0-9A-Fa-f]{272}$";
                readonly type: "string";
            };
            readonly expected_catalog_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly shard: {
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly signal: {
                readonly enum: readonly ["logs", "traces"];
                readonly type: "string";
            };
            readonly tenant: {
                readonly format: "uuid";
                readonly type: "string";
            };
        };
        readonly required: readonly ["tenant", "signal", "shard"];
        readonly type: "object";
    };
    readonly PolicyActivateRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly expected_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly idempotency_key: {
                readonly pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";
                readonly type: "string";
            };
            readonly policy_json: {
                readonly maxLength: 65536;
                readonly minLength: 1;
                readonly type: "string";
            };
        };
        readonly required: readonly ["policy_json", "expected_generation", "idempotency_key"];
        readonly type: "object";
    };
    readonly PolicyActivateResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly audit_position: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly policy_digest: {
                readonly pattern: "^[0-9a-f]{64}$";
                readonly type: "string";
            };
            readonly resource_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
        };
        readonly required: readonly ["resource_generation", "policy_digest", "audit_position"];
        readonly type: "object";
    };
    readonly PolicyDiffRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly after_policy_json: {
                readonly maxLength: 65536;
                readonly minLength: 1;
                readonly type: "string";
            };
            readonly before_policy_json: {
                readonly maxLength: 65536;
                readonly minLength: 1;
                readonly type: "string";
            };
        };
        readonly required: readonly ["before_policy_json", "after_policy_json"];
        readonly type: "object";
    };
    readonly PolicyDiffResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly after_policy_digest: {
                readonly pattern: "^[0-9a-f]{64}$";
                readonly type: "string";
            };
            readonly after_policy_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly before_policy_digest: {
                readonly pattern: "^[0-9a-f]{64}$";
                readonly type: "string";
            };
            readonly before_policy_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly semantic_changes: {
                readonly items: {
                    readonly enum: readonly ["generation_changed", "rule_added", "rule_removed", "rule_predicates_changed", "rule_action_changed"];
                    readonly type: "string";
                };
                readonly maxItems: 4096;
                readonly type: "array";
            };
        };
        readonly required: readonly ["before_policy_generation", "before_policy_digest", "after_policy_generation", "after_policy_digest", "semantic_changes"];
        readonly type: "object";
    };
    readonly PolicyExplainRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly candidate_json: {
                readonly maxLength: 65536;
                readonly minLength: 1;
                readonly type: "string";
            };
            readonly policy_json: {
                readonly maxLength: 65536;
                readonly minLength: 1;
                readonly type: "string";
            };
        };
        readonly required: readonly ["policy_json", "candidate_json"];
        readonly type: "object";
    };
    readonly PolicyExplainResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly explanation: {
                readonly maxLength: 4096;
                readonly minLength: 1;
                readonly type: "string";
            };
            readonly outcome: {
                readonly enum: readonly ["accepted", "rejected"];
                readonly type: "string";
            };
            readonly policy_digest: {
                readonly pattern: "^[0-9a-f]{64}$";
                readonly type: "string";
            };
            readonly policy_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
        };
        readonly required: readonly ["policy_generation", "policy_digest", "outcome", "explanation"];
        readonly type: "object";
    };
    readonly PolicyPreviewFailure: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly code: {
                readonly enum: readonly ["invalid_request", "authentication_rejected", "administration_unavailable"];
                readonly type: "string";
            };
        };
        readonly required: readonly ["code"];
        readonly type: "object";
    };
    readonly PolicyPreviewRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly policy_json: {
                readonly description: "Bounded declarative candidate. It is compiled prospectively and never exposed in a response or audit record by this operation.";
                readonly maxLength: 65536;
                readonly minLength: 1;
                readonly type: "string";
            };
        };
        readonly required: readonly ["policy_json"];
        readonly type: "object";
    };
    readonly PolicyTestRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly candidate_json: {
                readonly description: "Bounded fixture evaluated only in memory. Its values are never exposed in a response or audit record by this operation.";
                readonly maxLength: 65536;
                readonly minLength: 1;
                readonly type: "string";
            };
            readonly policy_json: {
                readonly description: "Prospective declarative candidate. It is compiled only in memory and never exposed in a response or audit record by this operation.";
                readonly maxLength: 65536;
                readonly minLength: 1;
                readonly type: "string";
            };
        };
        readonly required: readonly ["policy_json", "candidate_json"];
        readonly type: "object";
    };
    readonly PolicyTestResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly accepted: {
                readonly type: "boolean";
            };
            readonly applied_rule_count: {
                readonly maximum: 4096;
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly policy_digest: {
                readonly pattern: "^[0-9a-f]{64}$";
                readonly type: "string";
            };
            readonly policy_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
        };
        readonly required: readonly ["policy_generation", "policy_digest", "accepted", "applied_rule_count"];
        readonly type: "object";
    };
    readonly PolicyValidateResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly policy_digest: {
                readonly pattern: "^[0-9a-f]{64}$";
                readonly type: "string";
            };
            readonly policy_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly rule_count: {
                readonly maximum: 4096;
                readonly minimum: 0;
                readonly type: "integer";
            };
        };
        readonly required: readonly ["policy_generation", "policy_digest", "rule_count"];
        readonly type: "object";
    };
    readonly ProviderMigrationIdentity: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly family: {
                readonly maximum: 8;
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly locator: {
                readonly maxLength: 512;
                readonly minLength: 1;
                readonly type: "string";
            };
            readonly version: {
                readonly maxLength: 128;
                readonly minLength: 1;
                readonly type: "string";
            };
        };
        readonly required: readonly ["family", "locator", "version"];
        readonly type: "object";
    };
    readonly ProviderMigrationOperation: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly cancellation: {
                readonly type: "string";
            };
            readonly id: {
                readonly type: "string";
            };
            readonly irreversible_boundary: {
                readonly type: "string";
            };
            readonly lookup_expires_at_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly phase: {
                readonly type: "string";
            };
            readonly progress_percent: {
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly retry: {
                readonly type: "string";
            };
            readonly status: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["id", "status", "phase", "progress_percent", "retry", "cancellation", "irreversible_boundary"];
        readonly type: "object";
    };
    readonly ProviderMigrationRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly action: {
                readonly type: "string";
            };
            readonly configuration_reference: {
                readonly type: "string";
            };
            readonly expected_catalog_generation: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly idempotency_key: {
                readonly type: "string";
            };
            readonly operation_id: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["action"];
        readonly type: "object";
    };
    readonly ProviderMigrationResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly active_epoch: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly active_provider: {
                readonly $ref: "#/components/schemas/ProviderMigrationIdentity";
            };
            readonly catalog_generation: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly operation: {
                readonly $ref: "#/components/schemas/ProviderMigrationOperation";
            };
            readonly predecessor_epoch: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly root_phase: {
                readonly type: "string";
            };
            readonly source_provider: {
                readonly $ref: "#/components/schemas/ProviderMigrationIdentity";
            };
            readonly successor_epoch: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly target_provider: {
                readonly $ref: "#/components/schemas/ProviderMigrationIdentity";
            };
        };
        readonly required: readonly ["catalog_generation", "root_phase", "active_epoch", "active_provider", "source_provider"];
        readonly type: "object";
    };
    readonly PublicError: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly code: {
                readonly $ref: "#/components/schemas/PublicErrorCode";
                readonly deprecated: false;
                readonly "x-protobuf-field-number": 1;
            };
            readonly completion_state: {
                readonly $ref: "#/components/schemas/CompletionState";
                readonly deprecated: false;
                readonly "x-protobuf-field-number": 3;
            };
            readonly retry_class: {
                readonly $ref: "#/components/schemas/RetryClass";
                readonly deprecated: false;
                readonly "x-protobuf-field-number": 2;
            };
            readonly safe_detail: {
                readonly $ref: "#/components/schemas/SafeDetail";
                readonly deprecated: false;
                readonly "x-protobuf-field-number": 5;
            };
            readonly source: {
                readonly $ref: "#/components/schemas/FailureSource";
                readonly deprecated: false;
                readonly "x-protobuf-field-number": 4;
            };
        };
        readonly type: "object";
    };
    readonly PublicErrorCode: {
        readonly oneOf: readonly [{
            readonly enum: readonly [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22];
            readonly type: "integer";
        }, {
            readonly enum: readonly ["PUBLIC_ERROR_CODE_UNSPECIFIED", "PUBLIC_ERROR_CODE_UNSUPPORTED_API_VERSION", "PUBLIC_ERROR_CODE_CAPABILITY_UNAVAILABLE", "PUBLIC_ERROR_CODE_CAPABILITY_UNSUPPORTED", "PUBLIC_ERROR_CODE_MALFORMED_REQUEST", "PUBLIC_ERROR_CODE_REQUEST_TOO_LARGE", "PUBLIC_ERROR_CODE_UNKNOWN_FIELD", "PUBLIC_ERROR_CODE_AUTHENTICATION_REJECTED", "PUBLIC_ERROR_CODE_CAPACITY_UNAVAILABLE", "PUBLIC_ERROR_CODE_QUERY_UNAVAILABLE", "PUBLIC_ERROR_CODE_SNAPSHOT_EXPIRED", "PUBLIC_ERROR_CODE_INVALID_CURSOR", "PUBLIC_ERROR_CODE_INVALID_BUDGET", "PUBLIC_ERROR_CODE_BUDGET_EXHAUSTED", "PUBLIC_ERROR_CODE_AUTHORIZATION_CHANGED", "PUBLIC_ERROR_CODE_CANCELLED", "PUBLIC_ERROR_CODE_UNSUPPORTED_QUERY", "PUBLIC_ERROR_CODE_IDEMPOTENCY_CONFLICT", "PUBLIC_ERROR_CODE_STORE_UNAVAILABLE", "PUBLIC_ERROR_CODE_INCOMPLETE_DATA", "PUBLIC_ERROR_CODE_MALFORMED_PERSISTENT_DATA", "PUBLIC_ERROR_CODE_INTERNAL", "PUBLIC_ERROR_CODE_UNSUPPORTED_FEATURE"];
            readonly type: "string";
        }];
        readonly "x-enumDeprecated": readonly [false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false];
        readonly "x-enumNames": readonly ["UNSPECIFIED", "UNSUPPORTED_API_VERSION", "CAPABILITY_UNAVAILABLE", "CAPABILITY_UNSUPPORTED", "MALFORMED_REQUEST", "REQUEST_TOO_LARGE", "UNKNOWN_FIELD", "AUTHENTICATION_REJECTED", "CAPACITY_UNAVAILABLE", "QUERY_UNAVAILABLE", "SNAPSHOT_EXPIRED", "INVALID_CURSOR", "INVALID_BUDGET", "BUDGET_EXHAUSTED", "AUTHORIZATION_CHANGED", "CANCELLED", "UNSUPPORTED_QUERY", "IDEMPOTENCY_CONFLICT", "STORE_UNAVAILABLE", "INCOMPLETE_DATA", "MALFORMED_PERSISTENT_DATA", "INTERNAL", "UNSUPPORTED_FEATURE"];
    };
    readonly PublicErrorCodeProtoJson: {
        readonly enum: readonly ["PUBLIC_ERROR_CODE_UNSPECIFIED", "PUBLIC_ERROR_CODE_UNSUPPORTED_API_VERSION", "PUBLIC_ERROR_CODE_CAPABILITY_UNAVAILABLE", "PUBLIC_ERROR_CODE_CAPABILITY_UNSUPPORTED", "PUBLIC_ERROR_CODE_MALFORMED_REQUEST", "PUBLIC_ERROR_CODE_REQUEST_TOO_LARGE", "PUBLIC_ERROR_CODE_UNKNOWN_FIELD", "PUBLIC_ERROR_CODE_AUTHENTICATION_REJECTED", "PUBLIC_ERROR_CODE_CAPACITY_UNAVAILABLE", "PUBLIC_ERROR_CODE_QUERY_UNAVAILABLE"];
        readonly type: "string";
    };
    readonly PublicErrorProtoJson: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly code: {
                readonly $ref: "#/components/schemas/PublicErrorCodeProtoJson";
                readonly "x-protobuf-field-number": 1;
            };
            readonly completionState: {
                readonly $ref: "#/components/schemas/CompletionStateProtoJson";
                readonly "x-protobuf-field-number": 3;
            };
            readonly retryClass: {
                readonly $ref: "#/components/schemas/RetryClassProtoJson";
                readonly "x-protobuf-field-number": 2;
            };
            readonly safeDetail: {
                readonly $ref: "#/components/schemas/SafeDetailProtoJson";
                readonly "x-protobuf-field-number": 5;
            };
            readonly source: {
                readonly $ref: "#/components/schemas/FailureSourceProtoJson";
                readonly "x-protobuf-field-number": 4;
            };
        };
        readonly type: "object";
    };
    readonly RepositoryAwsS3Target: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly bucket: {
                readonly type: "string";
            };
            readonly endpoint: {
                readonly type: "string";
            };
            readonly expected_owner: {
                readonly type: "string";
            };
            readonly prefix: {
                readonly type: "string";
            };
            readonly region: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["bucket", "region", "endpoint", "expected_owner", "prefix"];
        readonly type: "object";
    };
    readonly RepositoryAzureBlobTarget: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly account: {
                readonly type: "string";
            };
            readonly container: {
                readonly type: "string";
            };
            readonly prefix: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["account", "container", "prefix"];
        readonly type: "object";
    };
    readonly RepositoryDefaultRetention: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly mode: {
                readonly type: "string";
            };
            readonly period: {
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly period_unit: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["mode", "period_unit", "period"];
        readonly type: "object";
    };
    readonly RepositoryDoctorResult: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly external_retention: {
                readonly type: "string";
            };
            readonly probes_deleted: {
                readonly type: "boolean";
            };
            readonly verified: {
                readonly type: "boolean";
            };
        };
        readonly required: readonly ["verified", "probes_deleted", "external_retention"];
        readonly type: "object";
    };
    readonly RepositoryEventHold: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly enabled: {
                readonly type: "boolean";
            };
            readonly period: {
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly period_unit: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["enabled"];
        readonly type: "object";
    };
    readonly RepositoryGoogleCloudStorageTarget: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly bucket: {
                readonly type: "string";
            };
            readonly location: {
                readonly type: "string";
            };
            readonly prefix: {
                readonly type: "string";
            };
            readonly project_number: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["bucket", "project_number", "location", "prefix"];
        readonly type: "object";
    };
    readonly RepositoryIdentity: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly format_epoch: {
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly instance_id: {
                readonly type: "string";
            };
            readonly integrity_fingerprint: {
                readonly type: "string";
            };
            readonly prefix_commitment: {
                readonly type: "string";
            };
            readonly provider_kind: {
                readonly type: "string";
            };
            readonly repository_id: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["repository_id", "instance_id", "provider_kind", "format_epoch", "integrity_fingerprint", "prefix_commitment"];
        readonly type: "object";
    };
    readonly RepositoryLifecyclePolicy: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly abandoned_upload_expiration: {
                readonly type: "boolean";
            };
            readonly current_expiration: {
                readonly type: "boolean";
            };
            readonly noncurrent_expiration: {
                readonly type: "boolean";
            };
            readonly transition: {
                readonly type: "boolean";
            };
        };
        readonly required: readonly ["current_expiration", "noncurrent_expiration", "transition", "abandoned_upload_expiration"];
        readonly type: "object";
    };
    readonly RepositoryObjectProtection: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly event_hold: {
                readonly $ref: "#/components/schemas/RepositoryPolicyObservation";
            };
            readonly legal_hold: {
                readonly $ref: "#/components/schemas/RepositoryPolicyObservation";
            };
            readonly retention: {
                readonly $ref: "#/components/schemas/RepositoryPolicyObservation";
            };
        };
        readonly required: readonly ["retention", "legal_hold", "event_hold"];
        readonly type: "object";
    };
    readonly RepositoryObjectRetention: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly mode: {
                readonly type: "string";
            };
            readonly retain_until_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
        };
        readonly required: readonly ["mode", "retain_until_unix_seconds"];
        readonly type: "object";
    };
    readonly RepositoryOperation: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly cancellation: {
                readonly type: "string";
            };
            readonly id: {
                readonly type: "string";
            };
            readonly irreversible_boundary: {
                readonly type: "string";
            };
            readonly lookup_expires_at_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly phase: {
                readonly type: "string";
            };
            readonly progress_percent: {
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly retry: {
                readonly type: "string";
            };
            readonly status: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["id", "status", "phase", "progress_percent", "retry", "cancellation", "irreversible_boundary"];
        readonly type: "object";
    };
    readonly RepositoryPolicyObservation: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly default_retention: {
                readonly $ref: "#/components/schemas/RepositoryDefaultRetention";
            };
            readonly event_hold: {
                readonly $ref: "#/components/schemas/RepositoryEventHold";
            };
            readonly failure: {
                readonly type: "string";
            };
            readonly lifecycle: {
                readonly $ref: "#/components/schemas/RepositoryLifecyclePolicy";
            };
            readonly object_retention: {
                readonly $ref: "#/components/schemas/RepositoryObjectRetention";
            };
            readonly retry_after_millis: {
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly state: {
                readonly type: "string";
            };
            readonly value: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["state"];
        readonly type: "object";
    };
    readonly RepositoryPolicyReceipt: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly doctor_probe: {
                readonly $ref: "#/components/schemas/RepositoryObjectProtection";
            };
            readonly lifecycle: {
                readonly $ref: "#/components/schemas/RepositoryPolicyObservation";
            };
            readonly object_lock: {
                readonly $ref: "#/components/schemas/RepositoryPolicyObservation";
            };
            readonly observed_at_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly soft_delete: {
                readonly $ref: "#/components/schemas/RepositoryPolicyObservation";
            };
            readonly versioning: {
                readonly $ref: "#/components/schemas/RepositoryPolicyObservation";
            };
        };
        readonly required: readonly ["observed_at_unix_seconds", "versioning", "object_lock", "lifecycle"];
        readonly type: "object";
    };
    readonly RepositoryRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly action: {
                readonly type: "string";
            };
            readonly aws_s3: {
                readonly $ref: "#/components/schemas/RepositoryAwsS3Target";
            };
            readonly azure_blob: {
                readonly $ref: "#/components/schemas/RepositoryAzureBlobTarget";
            };
            readonly expected_catalog_generation: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly google_cloud_storage: {
                readonly $ref: "#/components/schemas/RepositoryGoogleCloudStorageTarget";
            };
            readonly idempotency_key: {
                readonly type: "string";
            };
            readonly locator: {
                readonly type: "string";
            };
            readonly operation_id: {
                readonly type: "string";
            };
            readonly repository_id: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["action"];
        readonly type: "object";
    };
    readonly RepositoryResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly catalog_generation: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly doctor: {
                readonly $ref: "#/components/schemas/RepositoryDoctorResult";
            };
            readonly identity: {
                readonly $ref: "#/components/schemas/RepositoryIdentity";
            };
            readonly operation: {
                readonly $ref: "#/components/schemas/RepositoryOperation";
            };
            readonly policy: {
                readonly $ref: "#/components/schemas/RepositoryPolicyReceipt";
            };
        };
        readonly required: readonly ["catalog_generation"];
        readonly type: "object";
    };
    readonly RetentionReclamation: {
        readonly enum: readonly [0, 1, 2, 3];
        readonly type: "integer";
        readonly "x-enumDeprecated": readonly [false, false, false, false];
        readonly "x-enumNames": readonly ["NONE", "AT", "BLOCKED_BY_DURABLE_LEASE", "BLOCKED_BY_IN_PROCESS_SNAPSHOT"];
    };
    readonly RetryClass: {
        readonly oneOf: readonly [{
            readonly enum: readonly [0, 1, 2, 3];
            readonly type: "integer";
        }, {
            readonly enum: readonly ["RETRY_CLASS_UNSPECIFIED", "RETRY_CLASS_NEVER", "RETRY_CLASS_AFTER_BACKOFF", "RETRY_CLASS_AFTER_INPUT_CORRECTION"];
            readonly type: "string";
        }];
        readonly "x-enumDeprecated": readonly [false, false, false, false];
        readonly "x-enumNames": readonly ["UNSPECIFIED", "NEVER", "AFTER_BACKOFF", "AFTER_INPUT_CORRECTION"];
    };
    readonly RetryClassProtoJson: {
        readonly enum: readonly ["RETRY_CLASS_UNSPECIFIED", "RETRY_CLASS_NEVER", "RETRY_CLASS_AFTER_BACKOFF", "RETRY_CLASS_AFTER_INPUT_CORRECTION"];
        readonly type: "string";
    };
    readonly SafeDetail: {
        readonly oneOf: readonly [{
            readonly enum: readonly [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22];
            readonly type: "integer";
        }, {
            readonly enum: readonly ["SAFE_DETAIL_UNSPECIFIED", "SAFE_DETAIL_API_MAJOR_UNSUPPORTED", "SAFE_DETAIL_CAPABILITY_NOT_AVAILABLE", "SAFE_DETAIL_CAPABILITY_NOT_SUPPORTED", "SAFE_DETAIL_REQUEST_MALFORMED", "SAFE_DETAIL_REQUEST_LIMIT_EXCEEDED", "SAFE_DETAIL_FIELD_NOT_RECOGNIZED", "SAFE_DETAIL_AUTHENTICATION_REJECTED", "SAFE_DETAIL_CAPACITY_UNAVAILABLE", "SAFE_DETAIL_QUERY_UNAVAILABLE", "SAFE_DETAIL_SNAPSHOT_EXPIRED", "SAFE_DETAIL_INVALID_CURSOR", "SAFE_DETAIL_INVALID_BUDGET", "SAFE_DETAIL_BUDGET_EXHAUSTED", "SAFE_DETAIL_AUTHORIZATION_CHANGED", "SAFE_DETAIL_CANCELLED", "SAFE_DETAIL_UNSUPPORTED_QUERY", "SAFE_DETAIL_IDEMPOTENCY_CONFLICT", "SAFE_DETAIL_STORE_UNAVAILABLE", "SAFE_DETAIL_INCOMPLETE_DATA", "SAFE_DETAIL_MALFORMED_PERSISTENT_DATA", "SAFE_DETAIL_INTERNAL", "SAFE_DETAIL_UNSUPPORTED_FEATURE"];
            readonly type: "string";
        }];
        readonly "x-enumDeprecated": readonly [false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false];
        readonly "x-enumNames": readonly ["UNSPECIFIED", "API_MAJOR_UNSUPPORTED", "CAPABILITY_NOT_AVAILABLE", "CAPABILITY_NOT_SUPPORTED", "REQUEST_MALFORMED", "REQUEST_LIMIT_EXCEEDED", "FIELD_NOT_RECOGNIZED", "AUTHENTICATION_REJECTED", "CAPACITY_UNAVAILABLE", "QUERY_UNAVAILABLE", "SNAPSHOT_EXPIRED", "INVALID_CURSOR", "INVALID_BUDGET", "BUDGET_EXHAUSTED", "AUTHORIZATION_CHANGED", "CANCELLED", "UNSUPPORTED_QUERY", "IDEMPOTENCY_CONFLICT", "STORE_UNAVAILABLE", "INCOMPLETE_DATA", "MALFORMED_PERSISTENT_DATA", "INTERNAL", "UNSUPPORTED_FEATURE"];
    };
    readonly SafeDetailProtoJson: {
        readonly enum: readonly ["SAFE_DETAIL_UNSPECIFIED", "SAFE_DETAIL_API_MAJOR_UNSUPPORTED", "SAFE_DETAIL_CAPABILITY_NOT_AVAILABLE", "SAFE_DETAIL_CAPABILITY_NOT_SUPPORTED", "SAFE_DETAIL_REQUEST_MALFORMED", "SAFE_DETAIL_REQUEST_LIMIT_EXCEEDED", "SAFE_DETAIL_FIELD_NOT_RECOGNIZED", "SAFE_DETAIL_AUTHENTICATION_REJECTED", "SAFE_DETAIL_CAPACITY_UNAVAILABLE", "SAFE_DETAIL_QUERY_UNAVAILABLE"];
        readonly type: "string";
    };
    readonly SegmentAbandonmentRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly accept_data_loss: {
                readonly type: "boolean";
            };
            readonly confirmation: {
                readonly type: "string";
            };
            readonly expected_catalog_generation: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly idempotency_key: {
                readonly type: "string";
            };
            readonly operation_id: {
                readonly type: "string";
            };
            readonly segment: {
                readonly type: "string";
            };
            readonly shard: {
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly signal: {
                readonly type: "string";
            };
            readonly tenant: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["tenant", "signal", "shard", "segment", "accept_data_loss"];
        readonly type: "object";
    };
    readonly SegmentAbandonmentResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly catalog_generation: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly confirmation: {
                readonly type: "string";
            };
            readonly finding: {
                readonly $ref: "#/components/schemas/IntegrityQuarantineFinding";
            };
            readonly irreversible_boundary: {
                readonly type: "string";
            };
            readonly operation_id: {
                readonly type: "string";
            };
            readonly status: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["catalog_generation", "status", "irreversible_boundary", "finding"];
        readonly type: "object";
    };
    readonly TenantAliasBindRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly expected_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly external_alias: {
                readonly description: "One protocol compatibility assertion. It is validated only after the credential has attributed data-plane work.";
                readonly maxLength: 128;
                readonly minLength: 1;
                readonly pattern: "^[A-Za-z0-9._-]+$";
                readonly type: "string";
            };
            readonly idempotency_key: {
                readonly format: "uuid";
                readonly type: "string";
            };
            readonly tenant: {
                readonly description: "Explicit system-administration target; it never supplies data-plane attribution.";
                readonly format: "uuid";
                readonly type: "string";
            };
        };
        readonly required: readonly ["tenant", "external_alias", "expected_generation", "idempotency_key"];
        readonly type: "object";
    };
    readonly TenantAliasBindResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly alias_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly audit_ingest_time_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly audit_position: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly tenant: {
                readonly format: "uuid";
                readonly type: "string";
            };
        };
        readonly required: readonly ["tenant", "alias_generation", "audit_position", "audit_ingest_time_unix_seconds"];
        readonly type: "object";
    };
    readonly TenantCreateRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly batch_items: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly buffer_cache_bytes: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly cpu_work_units: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly disk_headroom_bytes: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly display_name: {
                readonly maxLength: 128;
                readonly minLength: 1;
                readonly type: "string";
            };
            readonly file_descriptors: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly idempotency_key: {
                readonly format: "uuid";
                readonly type: "string";
            };
            readonly io_permits: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly lease_slots: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly memory_bytes: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly queue_slots: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly retention_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly retry_slots: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly slug: {
                readonly maxLength: 63;
                readonly minLength: 1;
                readonly pattern: "^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$";
                readonly type: "string";
            };
            readonly task_slots: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly weight: {
                readonly maximum: 65535;
                readonly minimum: 1;
                readonly type: "integer";
            };
        };
        readonly required: readonly ["slug", "display_name", "retention_seconds", "weight", "memory_bytes", "queue_slots", "task_slots", "buffer_cache_bytes", "batch_items", "lease_slots", "retry_slots", "io_permits", "cpu_work_units", "file_descriptors", "disk_headroom_bytes", "idempotency_key"];
        readonly type: "object";
    };
    readonly TenantCreateResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly audit_position: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly resource_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly tenant: {
                readonly format: "uuid";
                readonly type: "string";
            };
        };
        readonly required: readonly ["tenant", "resource_generation", "audit_position"];
        readonly type: "object";
    };
    readonly TenantDescriptor: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly display_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly display_name: {
                readonly maxLength: 128;
                readonly minLength: 1;
                readonly type: "string";
            };
            readonly lifecycle: {
                readonly $ref: "#/components/schemas/TenantLifecycleTarget";
            };
            readonly retention_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly retention_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly slug: {
                readonly maxLength: 63;
                readonly minLength: 1;
                readonly pattern: "^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$";
                readonly type: "string";
            };
            readonly tenant: {
                readonly format: "uuid";
                readonly type: "string";
            };
        };
        readonly required: readonly ["tenant", "slug", "lifecycle"];
        readonly type: "object";
    };
    readonly TenantDisplayNameUpdateRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly display_name: {
                readonly maxLength: 128;
                readonly minLength: 1;
                readonly type: "string";
            };
            readonly expected_display_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly idempotency_key: {
                readonly format: "uuid";
                readonly type: "string";
            };
            readonly tenant: {
                readonly format: "uuid";
                readonly type: "string";
            };
        };
        readonly required: readonly ["tenant", "expected_display_generation", "display_name", "idempotency_key"];
        readonly type: "object";
    };
    readonly TenantDisplayNameUpdateResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly audit_position: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly display_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly tenant: {
                readonly format: "uuid";
                readonly type: "string";
            };
        };
        readonly required: readonly ["tenant", "display_generation", "audit_position"];
        readonly type: "object";
    };
    readonly TenantInspectRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly tenant: {
                readonly format: "uuid";
                readonly type: "string";
            };
        };
        readonly required: readonly ["tenant"];
        readonly type: "object";
    };
    readonly TenantInspectResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly tenant: {
                readonly $ref: "#/components/schemas/TenantDescriptor";
            };
        };
        readonly required: readonly ["tenant"];
        readonly type: "object";
    };
    readonly TenantLifecycleTarget: {
        readonly enum: readonly ["active", "read_only", "suspended", "purging", "purged"];
        readonly type: "string";
    };
    readonly TenantLifecycleTransitionRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly expected_generation: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly idempotency_key: {
                readonly type: "string";
            };
            readonly target: {
                readonly enum: readonly ["active", "read_only", "suspended", "purging", "purged"];
                readonly type: "string";
            };
            readonly tenant: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["expected_generation", "idempotency_key", "target", "tenant"];
        readonly type: "object";
    };
    readonly TenantLifecycleTransitionResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly audit_ingest_time_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly audit_position: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly from: {
                readonly enum: readonly ["active", "read_only", "suspended", "purging", "purged"];
                readonly type: "string";
            };
            readonly lifecycle_generation: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly tenant: {
                readonly type: "string";
            };
            readonly to: {
                readonly enum: readonly ["active", "read_only", "suspended", "purging", "purged"];
                readonly type: "string";
            };
        };
        readonly required: readonly ["audit_ingest_time_unix_seconds", "audit_position", "from", "lifecycle_generation", "tenant", "to"];
        readonly type: "object";
    };
    readonly TenantListRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly continuation: {
                readonly maxLength: 84;
                readonly minLength: 84;
                readonly pattern: "^[0-9a-f]{84}$";
                readonly type: "string";
            };
        };
        readonly type: "object";
    };
    readonly TenantListResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly continuation: {
                readonly maxLength: 84;
                readonly pattern: "^[0-9a-f]{84}$";
                readonly type: readonly ["string", "null"];
            };
            readonly tenants: {
                readonly items: {
                    readonly $ref: "#/components/schemas/TenantDescriptor";
                };
                readonly maxItems: 48;
                readonly type: "array";
            };
        };
        readonly required: readonly ["tenants", "continuation"];
        readonly type: "object";
    };
    readonly TenantPurgeRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly action: {
                readonly type: "string";
            };
            readonly confirmation_slug: {
                readonly type: "string";
            };
            readonly expected_catalog_generation: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly expected_lifecycle_generation: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly idempotency_key: {
                readonly type: "string";
            };
            readonly operation_id: {
                readonly type: "string";
            };
            readonly tenant_id: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["action"];
        readonly type: "object";
    };
    readonly TenantPurgeResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly catalog_generation: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly managed_scope: {
                readonly type: "string";
            };
            readonly operation: {
                readonly $ref: "#/components/schemas/ProviderMigrationOperation";
            };
        };
        readonly required: readonly ["catalog_generation", "managed_scope"];
        readonly type: "object";
    };
    readonly TenantQuotaFailure: {
        readonly oneOf: readonly [{
            readonly additionalProperties: false;
            readonly properties: {
                readonly code: {
                    readonly enum: readonly ["invalid_request", "authentication_rejected", "idempotency_conflict", "administration_unavailable"];
                    readonly type: "string";
                };
            };
            readonly required: readonly ["code"];
            readonly type: "object";
        }, {
            readonly additionalProperties: false;
            readonly properties: {
                readonly code: {
                    readonly const: "stale_generation";
                };
                readonly resource_generation: {
                    readonly minimum: 1;
                    readonly type: "integer";
                };
                readonly semantic_diff: {
                    readonly description: "Redacted description of the changed quota resource; it never contains quota values or credentials.";
                    readonly maxLength: 1024;
                    readonly minLength: 1;
                    readonly type: "string";
                };
            };
            readonly required: readonly ["code", "resource_generation", "semantic_diff"];
            readonly type: "object";
        }];
    };
    readonly TenantQuotaUpdateRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly batch_items: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly buffer_cache_bytes: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly cpu_work_units: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly disk_headroom_bytes: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly expected_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly file_descriptors: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly idempotency_key: {
                readonly format: "uuid";
                readonly type: "string";
            };
            readonly io_permits: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly lease_slots: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly memory_bytes: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly queue_slots: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly retry_slots: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly task_slots: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly tenant: {
                readonly description: "Explicit control-plane tenant. TenantAdministration credentials may select only their attributed tenant.";
                readonly format: "uuid";
                readonly type: "string";
            };
            readonly weight: {
                readonly maximum: 65535;
                readonly minimum: 1;
                readonly type: "integer";
            };
        };
        readonly required: readonly ["tenant", "expected_generation", "idempotency_key", "weight", "memory_bytes", "queue_slots", "task_slots", "buffer_cache_bytes", "batch_items", "lease_slots", "retry_slots", "io_permits", "cpu_work_units", "file_descriptors", "disk_headroom_bytes"];
        readonly type: "object";
    };
    readonly TenantQuotaUpdateResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly resource_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
        };
        readonly required: readonly ["resource_generation"];
        readonly type: "object";
    };
    readonly TenantRetentionPreviewRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly continuation: {
                readonly maxLength: 212;
                readonly minLength: 212;
                readonly pattern: "^[0-9a-f]{212}$";
                readonly type: "string";
            };
            readonly proposed_retention_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly tenant: {
                readonly description: "Explicit tenant-administration target; it cannot select another tenant.";
                readonly format: "uuid";
                readonly type: "string";
            };
        };
        readonly required: readonly ["tenant", "proposed_retention_seconds"];
        readonly type: "object";
    };
    readonly TenantRetentionPreviewResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly catalog_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly catalog_identity: {
                readonly pattern: "^[0-9a-f]{64}$";
                readonly type: "string";
            };
            readonly confirmation_digest: {
                readonly description: "Opaque confirmation binding computed from current canonical evidence.";
                readonly pattern: "^[0-9a-f]{64}$";
                readonly type: "string";
            };
            readonly confirmation_evaluated_at_unix_nanos: {
                readonly format: "int64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly continuation: {
                readonly maxLength: 212;
                readonly pattern: "^[0-9a-f]{212}$";
                readonly type: readonly ["string", "null"];
            };
            readonly proposed_retention_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly retention_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly scopes: {
                readonly items: {
                    readonly $ref: "#/components/schemas/TenantRetentionScopeImpact";
                };
                readonly maxItems: 64;
                readonly type: "array";
            };
            readonly tenant: {
                readonly format: "uuid";
                readonly type: "string";
            };
        };
        readonly required: readonly ["tenant", "retention_generation", "proposed_retention_seconds", "catalog_identity", "catalog_generation", "confirmation_digest", "confirmation_evaluated_at_unix_nanos", "scopes", "continuation"];
        readonly type: "object";
    };
    readonly TenantRetentionScopeImpact: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly affected_bytes: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly affected_end_unix_nanos: {
                readonly format: "int64-json";
                readonly type: "integer";
            };
            readonly affected_start_unix_nanos: {
                readonly format: "int64-json";
                readonly type: "integer";
            };
            readonly catalog_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly catalog_identity: {
                readonly pattern: "^[0-9a-f]{64}$";
                readonly type: "string";
            };
            readonly deferred_active_segment_bytes: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly deferred_mixed_sealed_segment_bytes: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly earliest_reclamation: {
                readonly enum: readonly ["none", "at", "blocked_by_durable_lease", "blocked_by_in_process_snapshot"];
                readonly type: "string";
            };
            readonly earliest_reclamation_unix_nanos: {
                readonly format: "int64-json";
                readonly type: "integer";
            };
            readonly evaluated_at_unix_nanos: {
                readonly format: "int64-json";
                readonly type: "integer";
            };
            readonly immediately_reclaimable_bytes: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly shard: {
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly signal: {
                readonly enum: readonly ["logs", "traces"];
                readonly type: "string";
            };
        };
        readonly required: readonly ["signal", "shard", "catalog_identity", "catalog_generation", "evaluated_at_unix_nanos", "affected_bytes", "immediately_reclaimable_bytes", "deferred_active_segment_bytes", "deferred_mixed_sealed_segment_bytes", "earliest_reclamation"];
        readonly type: "object";
    };
    readonly TenantRetentionUpdateRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly confirmation_digest: {
                readonly description: "Opaque digest received from a preview; callers never submit impact fields.";
                readonly pattern: "^[0-9a-f]{64}$";
                readonly type: "string";
            };
            readonly confirmation_evaluated_at_unix_nanos: {
                readonly description: "Trusted instant returned with the confirmation digest; the server verifies the digest at this instant.";
                readonly format: "int64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly expected_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly idempotency_key: {
                readonly format: "uuid";
                readonly type: "string";
            };
            readonly proposed_retention_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly tenant: {
                readonly description: "Explicit tenant-administration target; it cannot select another tenant.";
                readonly format: "uuid";
                readonly type: "string";
            };
        };
        readonly required: readonly ["tenant", "proposed_retention_seconds", "expected_generation", "idempotency_key"];
        readonly type: "object";
    };
    readonly TenantRetentionUpdateResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly audit_ingest_time_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly audit_position: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly retention_generation: {
                readonly format: "uint64-json";
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly tenant: {
                readonly format: "uuid";
                readonly type: "string";
            };
        };
        readonly required: readonly ["tenant", "retention_generation", "audit_position", "audit_ingest_time_unix_seconds"];
        readonly type: "object";
    };
    readonly UpgradeDetails: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly configuration: {
                readonly type: "string";
            };
            readonly format_epoch: {
                readonly minimum: 1;
                readonly type: "integer";
            };
            readonly repository_id: {
                readonly type: "string";
            };
            readonly rollback_available: {
                readonly type: "boolean";
            };
            readonly snapshot_manifest: {
                readonly type: "string";
            };
            readonly source_artifact: {
                readonly type: "string";
            };
            readonly source_manifest: {
                readonly type: "string";
            };
            readonly source_version: {
                readonly type: "string";
            };
            readonly target_artifact: {
                readonly type: "string";
            };
            readonly target_manifest: {
                readonly type: "string";
            };
            readonly target_version: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["source_version", "target_version", "source_manifest", "target_manifest", "source_artifact", "target_artifact", "configuration", "repository_id", "format_epoch", "rollback_available"];
        readonly type: "object";
    };
    readonly UpgradeOperation: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly cancellation: {
                readonly enum: readonly ["allowed_before_publication", "unavailable_after_publication", "cancelled"];
                readonly type: "string";
            };
            readonly id: {
                readonly type: "string";
            };
            readonly irreversible_boundary: {
                readonly type: "string";
            };
            readonly lookup_expires_at_unix_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly phase: {
                readonly enum: readonly ["preflight", "draining", "snapshot", "publishing", "awaiting_restart", "verifying", "succeeded"];
                readonly type: "string";
            };
            readonly progress_percent: {
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly retry: {
                readonly type: "string";
            };
            readonly status: {
                readonly type: "string";
            };
        };
        readonly required: readonly ["id", "status", "phase", "progress_percent", "retry", "cancellation", "irreversible_boundary"];
        readonly type: "object";
    };
    readonly UpgradePhase: {
        readonly enum: readonly [0, 1, 2, 3, 4, 5, 6, 7];
        readonly type: "integer";
        readonly "x-enumDeprecated": readonly [false, false, false, false, false, false, false, false];
        readonly "x-enumNames": readonly ["UNSPECIFIED", "PREFLIGHT", "DRAINING", "SNAPSHOT", "PUBLISHING", "AWAITING_RESTART", "VERIFYING", "SUCCEEDED"];
    };
    readonly UpgradeRequest: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly action: {
                readonly type: "string";
            };
            readonly candidate_manifest: {
                readonly type: "string";
            };
            readonly expected_catalog_generation: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly idempotency_key: {
                readonly type: "string";
            };
            readonly operation_id: {
                readonly type: "string";
            };
            readonly repository_id: {
                readonly type: "string";
            };
            readonly retention_seconds: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
        };
        readonly required: readonly ["action"];
        readonly type: "object";
    };
    readonly UpgradeResponse: {
        readonly additionalProperties: false;
        readonly properties: {
            readonly catalog_generation: {
                readonly format: "uint64-json";
                readonly minimum: 0;
                readonly type: "integer";
            };
            readonly details: {
                readonly $ref: "#/components/schemas/UpgradeDetails";
            };
            readonly operation: {
                readonly $ref: "#/components/schemas/UpgradeOperation";
            };
        };
        readonly required: readonly ["catalog_generation"];
        readonly type: "object";
    };
};
export declare const descriptor: {
    readonly enums: {
        readonly Capability: readonly [{
            readonly deprecated: false;
            readonly name: "CAPABILITY_UNSPECIFIED";
            readonly number: 0;
        }, {
            readonly deprecated: false;
            readonly name: "CAPABILITY_CANONICAL_PUBLIC_INTERFACE";
            readonly number: 1;
        }, {
            readonly deprecated: false;
            readonly name: "CAPABILITY_RELEASE_ONE_QUERY";
            readonly number: 2;
        }, {
            readonly deprecated: false;
            readonly name: "CAPABILITY_METRICS";
            readonly number: 3;
        }, {
            readonly deprecated: false;
            readonly name: "CAPABILITY_QUERY_SESSIONS";
            readonly number: 4;
        }, {
            readonly deprecated: false;
            readonly name: "CAPABILITY_QUERY_TAIL";
            readonly number: 5;
        }];
        readonly CapabilityAvailability: readonly [{
            readonly deprecated: false;
            readonly name: "CAPABILITY_AVAILABILITY_UNSPECIFIED";
            readonly number: 0;
        }, {
            readonly deprecated: false;
            readonly name: "CAPABILITY_AVAILABILITY_IMPLEMENTED";
            readonly number: 1;
        }, {
            readonly deprecated: false;
            readonly name: "CAPABILITY_AVAILABILITY_UNAVAILABLE";
            readonly number: 2;
        }, {
            readonly deprecated: false;
            readonly name: "CAPABILITY_AVAILABILITY_UNSUPPORTED";
            readonly number: 3;
        }, {
            readonly deprecated: false;
            readonly name: "CAPABILITY_AVAILABILITY_VERSION_INCOMPATIBLE";
            readonly number: 4;
        }];
        readonly CompletionState: readonly [{
            readonly deprecated: false;
            readonly name: "COMPLETION_STATE_UNSPECIFIED";
            readonly number: 0;
        }, {
            readonly deprecated: false;
            readonly name: "COMPLETION_STATE_REJECTED";
            readonly number: 1;
        }, {
            readonly deprecated: false;
            readonly name: "COMPLETION_STATE_AMBIGUOUS";
            readonly number: 2;
        }];
        readonly DeprecationState: readonly [{
            readonly deprecated: false;
            readonly name: "DEPRECATION_STATE_UNSPECIFIED";
            readonly number: 0;
        }, {
            readonly deprecated: false;
            readonly name: "DEPRECATION_STATE_CURRENT";
            readonly number: 1;
        }, {
            readonly deprecated: false;
            readonly name: "DEPRECATION_STATE_DEPRECATED";
            readonly number: 2;
        }];
        readonly FailureSource: readonly [{
            readonly deprecated: false;
            readonly name: "FAILURE_SOURCE_UNSPECIFIED";
            readonly number: 0;
        }, {
            readonly deprecated: false;
            readonly name: "FAILURE_SOURCE_CAPABILITY_NEGOTIATION";
            readonly number: 1;
        }, {
            readonly deprecated: false;
            readonly name: "FAILURE_SOURCE_GRPC_DECODE";
            readonly number: 2;
        }, {
            readonly deprecated: false;
            readonly name: "FAILURE_SOURCE_HTTP_DECODE";
            readonly number: 3;
        }, {
            readonly deprecated: false;
            readonly name: "FAILURE_SOURCE_QUERY_EXECUTION";
            readonly number: 4;
        }];
        readonly KeyAction: readonly [{
            readonly deprecated: false;
            readonly name: "KEY_ACTION_UNSPECIFIED";
            readonly number: 0;
        }, {
            readonly deprecated: false;
            readonly name: "KEY_ACTION_CREATE";
            readonly number: 1;
        }, {
            readonly deprecated: false;
            readonly name: "KEY_ACTION_LIST";
            readonly number: 2;
        }, {
            readonly deprecated: false;
            readonly name: "KEY_ACTION_ROTATE";
            readonly number: 3;
        }, {
            readonly deprecated: false;
            readonly name: "KEY_ACTION_REVOKE";
            readonly number: 4;
        }, {
            readonly deprecated: false;
            readonly name: "KEY_ACTION_SCOPE_INSPECT";
            readonly number: 5;
        }];
        readonly KeyScope: readonly [{
            readonly deprecated: false;
            readonly name: "KEY_SCOPE_UNSPECIFIED";
            readonly number: 0;
        }, {
            readonly deprecated: false;
            readonly name: "KEY_SCOPE_INGEST";
            readonly number: 1;
        }, {
            readonly deprecated: false;
            readonly name: "KEY_SCOPE_QUERY";
            readonly number: 2;
        }, {
            readonly deprecated: false;
            readonly name: "KEY_SCOPE_TENANT_ADMINISTRATION";
            readonly number: 3;
        }, {
            readonly deprecated: false;
            readonly name: "KEY_SCOPE_SYSTEM_ADMINISTRATION";
            readonly number: 4;
        }];
        readonly LogQueryStopReason: readonly [{
            readonly deprecated: false;
            readonly name: "LOG_QUERY_STOP_REASON_UNSPECIFIED";
            readonly number: 0;
        }, {
            readonly deprecated: false;
            readonly name: "LOG_QUERY_STOP_REASON_UNAUTHORIZED";
            readonly number: 1;
        }, {
            readonly deprecated: false;
            readonly name: "LOG_QUERY_STOP_REASON_IDEMPOTENCY_CONFLICT";
            readonly number: 2;
        }, {
            readonly deprecated: false;
            readonly name: "LOG_QUERY_STOP_REASON_INVALID_BUDGET";
            readonly number: 3;
        }, {
            readonly deprecated: false;
            readonly name: "LOG_QUERY_STOP_REASON_BUDGET_EXHAUSTED";
            readonly number: 4;
        }, {
            readonly deprecated: false;
            readonly name: "LOG_QUERY_STOP_REASON_INVALID_CURSOR";
            readonly number: 5;
        }, {
            readonly deprecated: false;
            readonly name: "LOG_QUERY_STOP_REASON_SNAPSHOT_EXPIRED";
            readonly number: 6;
        }, {
            readonly deprecated: false;
            readonly name: "LOG_QUERY_STOP_REASON_AUTHORIZATION_CHANGED";
            readonly number: 7;
        }, {
            readonly deprecated: false;
            readonly name: "LOG_QUERY_STOP_REASON_CANCELLED";
            readonly number: 8;
        }, {
            readonly deprecated: false;
            readonly name: "LOG_QUERY_STOP_REASON_RESOURCE_ADMISSION_REFUSED";
            readonly number: 9;
        }, {
            readonly deprecated: false;
            readonly name: "LOG_QUERY_STOP_REASON_RESOURCE_EXHAUSTED";
            readonly number: 10;
        }, {
            readonly deprecated: false;
            readonly name: "LOG_QUERY_STOP_REASON_UNSUPPORTED_QUERY";
            readonly number: 11;
        }, {
            readonly deprecated: false;
            readonly name: "LOG_QUERY_STOP_REASON_STORE_UNAVAILABLE";
            readonly number: 12;
        }, {
            readonly deprecated: false;
            readonly name: "LOG_QUERY_STOP_REASON_INCOMPLETE_DATA";
            readonly number: 13;
        }, {
            readonly deprecated: false;
            readonly name: "LOG_QUERY_STOP_REASON_MALFORMED_PERSISTENT_DATA";
            readonly number: 14;
        }, {
            readonly deprecated: false;
            readonly name: "LOG_QUERY_STOP_REASON_INTERNAL";
            readonly number: 15;
        }, {
            readonly deprecated: false;
            readonly name: "LOG_QUERY_STOP_REASON_DISCONNECTED";
            readonly number: 16;
        }, {
            readonly deprecated: false;
            readonly name: "LOG_QUERY_STOP_REASON_CONSUMER_LAGGED";
            readonly number: 17;
        }];
        readonly PublicErrorCode: readonly [{
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_UNSPECIFIED";
            readonly number: 0;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_UNSUPPORTED_API_VERSION";
            readonly number: 1;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_CAPABILITY_UNAVAILABLE";
            readonly number: 2;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_CAPABILITY_UNSUPPORTED";
            readonly number: 3;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_MALFORMED_REQUEST";
            readonly number: 4;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_REQUEST_TOO_LARGE";
            readonly number: 5;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_UNKNOWN_FIELD";
            readonly number: 6;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_AUTHENTICATION_REJECTED";
            readonly number: 7;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_CAPACITY_UNAVAILABLE";
            readonly number: 8;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_QUERY_UNAVAILABLE";
            readonly number: 9;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_SNAPSHOT_EXPIRED";
            readonly number: 10;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_INVALID_CURSOR";
            readonly number: 11;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_INVALID_BUDGET";
            readonly number: 12;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_BUDGET_EXHAUSTED";
            readonly number: 13;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_AUTHORIZATION_CHANGED";
            readonly number: 14;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_CANCELLED";
            readonly number: 15;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_UNSUPPORTED_QUERY";
            readonly number: 16;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_IDEMPOTENCY_CONFLICT";
            readonly number: 17;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_STORE_UNAVAILABLE";
            readonly number: 18;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_INCOMPLETE_DATA";
            readonly number: 19;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_MALFORMED_PERSISTENT_DATA";
            readonly number: 20;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_INTERNAL";
            readonly number: 21;
        }, {
            readonly deprecated: false;
            readonly name: "PUBLIC_ERROR_CODE_UNSUPPORTED_FEATURE";
            readonly number: 22;
        }];
        readonly RetentionReclamation: readonly [{
            readonly deprecated: false;
            readonly name: "RETENTION_RECLAMATION_NONE";
            readonly number: 0;
        }, {
            readonly deprecated: false;
            readonly name: "RETENTION_RECLAMATION_AT";
            readonly number: 1;
        }, {
            readonly deprecated: false;
            readonly name: "RETENTION_RECLAMATION_BLOCKED_BY_DURABLE_LEASE";
            readonly number: 2;
        }, {
            readonly deprecated: false;
            readonly name: "RETENTION_RECLAMATION_BLOCKED_BY_IN_PROCESS_SNAPSHOT";
            readonly number: 3;
        }];
        readonly RetryClass: readonly [{
            readonly deprecated: false;
            readonly name: "RETRY_CLASS_UNSPECIFIED";
            readonly number: 0;
        }, {
            readonly deprecated: false;
            readonly name: "RETRY_CLASS_NEVER";
            readonly number: 1;
        }, {
            readonly deprecated: false;
            readonly name: "RETRY_CLASS_AFTER_BACKOFF";
            readonly number: 2;
        }, {
            readonly deprecated: false;
            readonly name: "RETRY_CLASS_AFTER_INPUT_CORRECTION";
            readonly number: 3;
        }];
        readonly SafeDetail: readonly [{
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_UNSPECIFIED";
            readonly number: 0;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_API_MAJOR_UNSUPPORTED";
            readonly number: 1;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_CAPABILITY_NOT_AVAILABLE";
            readonly number: 2;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_CAPABILITY_NOT_SUPPORTED";
            readonly number: 3;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_REQUEST_MALFORMED";
            readonly number: 4;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_REQUEST_LIMIT_EXCEEDED";
            readonly number: 5;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_FIELD_NOT_RECOGNIZED";
            readonly number: 6;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_AUTHENTICATION_REJECTED";
            readonly number: 7;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_CAPACITY_UNAVAILABLE";
            readonly number: 8;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_QUERY_UNAVAILABLE";
            readonly number: 9;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_SNAPSHOT_EXPIRED";
            readonly number: 10;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_INVALID_CURSOR";
            readonly number: 11;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_INVALID_BUDGET";
            readonly number: 12;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_BUDGET_EXHAUSTED";
            readonly number: 13;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_AUTHORIZATION_CHANGED";
            readonly number: 14;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_CANCELLED";
            readonly number: 15;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_UNSUPPORTED_QUERY";
            readonly number: 16;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_IDEMPOTENCY_CONFLICT";
            readonly number: 17;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_STORE_UNAVAILABLE";
            readonly number: 18;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_INCOMPLETE_DATA";
            readonly number: 19;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_MALFORMED_PERSISTENT_DATA";
            readonly number: 20;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_INTERNAL";
            readonly number: 21;
        }, {
            readonly deprecated: false;
            readonly name: "SAFE_DETAIL_UNSUPPORTED_FEATURE";
            readonly number: 22;
        }];
        readonly TenantLifecycleTarget: readonly [{
            readonly deprecated: false;
            readonly name: "TENANT_LIFECYCLE_TARGET_UNSPECIFIED";
            readonly number: 0;
        }, {
            readonly deprecated: false;
            readonly name: "TENANT_LIFECYCLE_TARGET_ACTIVE";
            readonly number: 1;
        }, {
            readonly deprecated: false;
            readonly name: "TENANT_LIFECYCLE_TARGET_READ_ONLY";
            readonly number: 2;
        }, {
            readonly deprecated: false;
            readonly name: "TENANT_LIFECYCLE_TARGET_SUSPENDED";
            readonly number: 3;
        }, {
            readonly deprecated: false;
            readonly name: "TENANT_LIFECYCLE_TARGET_PURGING";
            readonly number: 4;
        }, {
            readonly deprecated: false;
            readonly name: "TENANT_LIFECYCLE_TARGET_PURGED";
            readonly number: 5;
        }];
        readonly UpgradePhase: readonly [{
            readonly deprecated: false;
            readonly name: "UPGRADE_PHASE_UNSPECIFIED";
            readonly number: 0;
        }, {
            readonly deprecated: false;
            readonly name: "UPGRADE_PHASE_PREFLIGHT";
            readonly number: 1;
        }, {
            readonly deprecated: false;
            readonly name: "UPGRADE_PHASE_DRAINING";
            readonly number: 2;
        }, {
            readonly deprecated: false;
            readonly name: "UPGRADE_PHASE_SNAPSHOT";
            readonly number: 3;
        }, {
            readonly deprecated: false;
            readonly name: "UPGRADE_PHASE_PUBLISHING";
            readonly number: 4;
        }, {
            readonly deprecated: false;
            readonly name: "UPGRADE_PHASE_AWAITING_RESTART";
            readonly number: 5;
        }, {
            readonly deprecated: false;
            readonly name: "UPGRADE_PHASE_VERIFYING";
            readonly number: 6;
        }, {
            readonly deprecated: false;
            readonly name: "UPGRADE_PHASE_SUCCEEDED";
            readonly number: 7;
        }];
    };
    readonly messages: {
        readonly ApiKeyRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "action";
            readonly name: "action";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 14;
            readonly type_name: ".positron.v1.KeyAction";
        }, {
            readonly deprecated: false;
            readonly json_name: "scope";
            readonly name: "scope";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 14;
            readonly type_name: ".positron.v1.KeyScope";
        }, {
            readonly deprecated: false;
            readonly json_name: "principal";
            readonly name: "principal";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expiresAtUnixSeconds";
            readonly name: "expires_at_unix_seconds";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expectedGeneration";
            readonly name: "expected_generation";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "idempotencyKey";
            readonly name: "idempotency_key";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "targetTenant";
            readonly name: "target_tenant";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly ApiKeyResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "keys";
            readonly name: "keys";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: true;
            readonly type: 11;
            readonly type_name: ".positron.v1.KeyDescriptor";
        }, {
            readonly deprecated: false;
            readonly json_name: "principal";
            readonly name: "principal";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "secret";
            readonly name: "secret";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly AuthenticatedTimeRange: readonly [{
            readonly deprecated: false;
            readonly json_name: "provenance";
            readonly name: "provenance";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "earliestUnixNanos";
            readonly name: "earliest_unix_nanos";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 18;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "latestUnixNanos";
            readonly name: "latest_unix_nanos";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 18;
            readonly type_name: null;
        }];
        readonly BackupListEntry: readonly [{
            readonly deprecated: false;
            readonly json_name: "snapshotId";
            readonly name: "snapshot_id";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "manifestChecksum";
            readonly name: "manifest_checksum";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "createdUnixSeconds";
            readonly name: "created_unix_seconds";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "retainUntilUnixSeconds";
            readonly name: "retain_until_unix_seconds";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly BackupListRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "repositoryId";
            readonly name: "repository_id";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "limit";
            readonly name: "limit";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "cursor";
            readonly name: "cursor";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly BackupListResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "repository";
            readonly name: "repository";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryIdentity";
        }, {
            readonly deprecated: false;
            readonly json_name: "registryGenerationChecksum";
            readonly name: "registry_generation_checksum";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "entries";
            readonly name: "entries";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: true;
            readonly type: 11;
            readonly type_name: ".positron.v1.BackupListEntry";
        }, {
            readonly deprecated: false;
            readonly json_name: "nextCursor";
            readonly name: "next_cursor";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly BackupRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "action";
            readonly name: "action";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expectedCatalogGeneration";
            readonly name: "expected_catalog_generation";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "idempotencyKey";
            readonly name: "idempotency_key";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "locator";
            readonly name: "locator";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "repositoryId";
            readonly name: "repository_id";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "operationId";
            readonly name: "operation_id";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "awsS3";
            readonly name: "aws_s3";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryAwsS3Target";
        }, {
            readonly deprecated: false;
            readonly json_name: "googleCloudStorage";
            readonly name: "google_cloud_storage";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryGoogleCloudStorageTarget";
        }, {
            readonly deprecated: false;
            readonly json_name: "azureBlob";
            readonly name: "azure_blob";
            readonly number: 9;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryAzureBlobTarget";
        }, {
            readonly deprecated: false;
            readonly json_name: "retentionSeconds";
            readonly name: "retention_seconds";
            readonly number: 10;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "snapshotId";
            readonly name: "snapshot_id";
            readonly number: 11;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expectedManifestChecksum";
            readonly name: "expected_manifest_checksum";
            readonly number: 12;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expectedOperationRevision";
            readonly name: "expected_operation_revision";
            readonly number: 13;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly BackupResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "operation";
            readonly name: "operation";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryOperation";
        }, {
            readonly deprecated: false;
            readonly json_name: "repository";
            readonly name: "repository";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryIdentity";
        }, {
            readonly deprecated: false;
            readonly json_name: "receipt";
            readonly name: "receipt";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.BackupSnapshotReceipt";
        }, {
            readonly deprecated: false;
            readonly json_name: "kind";
            readonly name: "kind";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "cleanupPending";
            readonly name: "cleanup_pending";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 8;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "retentionReceipt";
            readonly name: "retention_receipt";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.BackupRetentionReceipt";
        }, {
            readonly deprecated: false;
            readonly json_name: "operationRevision";
            readonly name: "operation_revision";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "terminalErrorCode";
            readonly name: "terminal_error_code";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "verificationReport";
            readonly name: "verification_report";
            readonly number: 9;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "verificationReportChecksum";
            readonly name: "verification_report_checksum";
            readonly number: 10;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "restoredPublication";
            readonly name: "restored_publication";
            readonly number: 11;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.BackupRestoredPublication";
        }];
        readonly BackupRestoredPublication: readonly [{
            readonly deprecated: false;
            readonly json_name: "manifestChecksum";
            readonly name: "manifest_checksum";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "currentRegistryGenerationChecksum";
            readonly name: "current_registry_generation_checksum";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "sourceCatalogIdentity";
            readonly name: "source_catalog_identity";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "sourceCatalogGeneration";
            readonly name: "source_catalog_generation";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "retainUntilUnixSeconds";
            readonly name: "retain_until_unix_seconds";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "restoreOriginTransaction";
            readonly name: "restore_origin_transaction";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "restoreIntentDigest";
            readonly name: "restore_intent_digest";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "captureOperationId";
            readonly name: "capture_operation_id";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "captureRequestDigest";
            readonly name: "capture_request_digest";
            readonly number: 9;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "restoreIdempotencyKey";
            readonly name: "restore_idempotency_key";
            readonly number: 10;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly BackupRetentionReceipt: readonly [{
            readonly deprecated: false;
            readonly json_name: "snapshotId";
            readonly name: "snapshot_id";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "manifestChecksum";
            readonly name: "manifest_checksum";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "registryGenerationChecksum";
            readonly name: "registry_generation_checksum";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "deletedObjects";
            readonly name: "deleted_objects";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "alreadyAbsentObjects";
            readonly name: "already_absent_objects";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "retainedSharedObjects";
            readonly name: "retained_shared_objects";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }];
        readonly BackupSnapshotReceipt: readonly [{
            readonly deprecated: false;
            readonly json_name: "registryGenerationChecksum";
            readonly name: "registry_generation_checksum";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "manifestChecksum";
            readonly name: "manifest_checksum";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "catalogGeneration";
            readonly name: "catalog_generation";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "catalogIdentity";
            readonly name: "catalog_identity";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "uploadedBytes";
            readonly name: "uploaded_bytes";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "reusedBytes";
            readonly name: "reused_bytes";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "retainUntilUnixSeconds";
            readonly name: "retain_until_unix_seconds";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly CapabilityRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "apiMajor";
            readonly name: "api_major";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "capability";
            readonly name: "capability";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 14;
            readonly type_name: ".positron.v1.Capability";
        }];
        readonly CapabilityResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "apiMajor";
            readonly name: "api_major";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "schemaDigest";
            readonly name: "schema_digest";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "availability";
            readonly name: "availability";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 14;
            readonly type_name: ".positron.v1.CapabilityAvailability";
        }, {
            readonly deprecated: false;
            readonly json_name: "refusal";
            readonly name: "refusal";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.PublicError";
        }, {
            readonly deprecated: false;
            readonly json_name: "deprecation";
            readonly name: "deprecation";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 14;
            readonly type_name: ".positron.v1.DeprecationState";
        }, {
            readonly deprecated: false;
            readonly json_name: "capability";
            readonly name: "capability";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 14;
            readonly type_name: ".positron.v1.Capability";
        }];
        readonly IntegrityQuarantineFinding: readonly [{
            readonly deprecated: false;
            readonly json_name: "tenant";
            readonly name: "tenant";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "signal";
            readonly name: "signal";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "shard";
            readonly name: "shard";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "segment";
            readonly name: "segment";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "basePosition";
            readonly name: "base_position";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "eventRange";
            readonly name: "event_range";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.AuthenticatedTimeRange";
        }, {
            readonly deprecated: false;
            readonly json_name: "ingestRange";
            readonly name: "ingest_range";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.AuthenticatedTimeRange";
        }];
        readonly KeyDescriptor: readonly [{
            readonly deprecated: false;
            readonly json_name: "principal";
            readonly name: "principal";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "scope";
            readonly name: "scope";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 14;
            readonly type_name: ".positron.v1.KeyScope";
        }, {
            readonly deprecated: false;
            readonly json_name: "active";
            readonly name: "active";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 8;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expiresAtUnixSeconds";
            readonly name: "expires_at_unix_seconds";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "generation";
            readonly name: "generation";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly LogQueryAcknowledgement: readonly [{
            readonly deprecated: false;
            readonly json_name: "sequence";
            readonly name: "sequence";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "digest";
            readonly name: "digest";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 12;
            readonly type_name: null;
        }];
        readonly LogQueryAffectedRange: readonly [{
            readonly deprecated: false;
            readonly json_name: "temporalAxis";
            readonly name: "temporal_axis";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "earliestNanoseconds";
            readonly name: "earliest_nanoseconds";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 18;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "latestNanoseconds";
            readonly name: "latest_nanoseconds";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 18;
            readonly type_name: null;
        }];
        readonly LogQueryArray: readonly [{
            readonly deprecated: false;
            readonly json_name: "values";
            readonly name: "values";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: true;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryValue";
        }];
        readonly LogQueryBatch: readonly [{
            readonly deprecated: false;
            readonly json_name: "sequence";
            readonly name: "sequence";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "rows";
            readonly name: "rows";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: true;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryRow";
        }, {
            readonly deprecated: false;
            readonly json_name: "priorDigest";
            readonly name: "prior_digest";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 12;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "digest";
            readonly name: "digest";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 12;
            readonly type_name: null;
        }];
        readonly LogQueryBudget: readonly [{
            readonly deprecated: false;
            readonly json_name: "scannedBytes";
            readonly name: "scanned_bytes";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "decodedRecords";
            readonly name: "decoded_records";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "outputRows";
            readonly name: "output_rows";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "outputBytes";
            readonly name: "output_bytes";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "memoryBytes";
            readonly name: "memory_bytes";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "cpuWorkUnits";
            readonly name: "cpu_work_units";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "wallSeconds";
            readonly name: "wall_seconds";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "maximumTimeRangeNanoseconds";
            readonly name: "maximum_time_range_nanoseconds";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly LogQueryCancelRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "query";
            readonly name: "query";
            readonly number: 1;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 12;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "tail";
            readonly name: "tail";
            readonly number: 2;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 12;
            readonly type_name: null;
        }];
        readonly LogQueryCancelResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "cancelled";
            readonly name: "cancelled";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 8;
            readonly type_name: null;
        }];
        readonly LogQueryCell: readonly [{
            readonly deprecated: false;
            readonly json_name: "nativeValue";
            readonly name: "native_value";
            readonly number: 1;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryValue";
        }, {
            readonly deprecated: false;
            readonly json_name: "occurrences";
            readonly name: "occurrences";
            readonly number: 2;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryOccurrences";
        }, {
            readonly deprecated: false;
            readonly json_name: "timestamp";
            readonly name: "timestamp";
            readonly number: 3;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryTimestamp";
        }, {
            readonly deprecated: false;
            readonly json_name: "unsignedInteger";
            readonly name: "unsigned_integer";
            readonly number: 4;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "missing";
            readonly name: "missing";
            readonly number: 5;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryMissing";
        }];
        readonly LogQueryColumn: readonly [{
            readonly deprecated: false;
            readonly json_name: "name";
            readonly name: "name";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "valueType";
            readonly name: "value_type";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "nullable";
            readonly name: "nullable";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 8;
            readonly type_name: null;
        }];
        readonly LogQueryEvent: readonly [{
            readonly deprecated: false;
            readonly json_name: "header";
            readonly name: "header";
            readonly number: 1;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryHeader";
        }, {
            readonly deprecated: false;
            readonly json_name: "batch";
            readonly name: "batch";
            readonly number: 2;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryBatch";
        }, {
            readonly deprecated: false;
            readonly json_name: "terminal";
            readonly name: "terminal";
            readonly number: 3;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryTerminal";
        }];
        readonly LogQueryHeader: readonly [{
            readonly deprecated: false;
            readonly json_name: "columns";
            readonly name: "columns";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: true;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryColumn";
        }, {
            readonly deprecated: false;
            readonly json_name: "snapshot";
            readonly name: "snapshot";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQuerySnapshot";
        }, {
            readonly deprecated: false;
            readonly json_name: "ordering";
            readonly name: "ordering";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: true;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryOrdering";
        }, {
            readonly deprecated: false;
            readonly json_name: "effectiveBudget";
            readonly name: "effective_budget";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryBudget";
        }, {
            readonly deprecated: false;
            readonly json_name: "lease";
            readonly name: "lease";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryLease";
        }, {
            readonly deprecated: false;
            readonly json_name: "initialCursor";
            readonly name: "initial_cursor";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 12;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "tailPhase";
            readonly name: "tail_phase";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly LogQueryKeyValue: readonly [{
            readonly deprecated: false;
            readonly json_name: "key";
            readonly name: "key";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "value";
            readonly name: "value";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryValue";
        }];
        readonly LogQueryLease: readonly [{
            readonly deprecated: false;
            readonly json_name: "identity";
            readonly name: "identity";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 12;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expiryUnixSeconds";
            readonly name: "expiry_unix_seconds";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly LogQueryMarker: readonly [{
            readonly deprecated: false;
            readonly json_name: "action";
            readonly name: "action";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "originalKind";
            readonly name: "original_kind";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly LogQueryMissing: readonly [];
        readonly LogQueryNull: readonly [];
        readonly LogQueryObject: readonly [{
            readonly deprecated: false;
            readonly json_name: "entries";
            readonly name: "entries";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: true;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryKeyValue";
        }];
        readonly LogQueryOccurrences: readonly [{
            readonly deprecated: false;
            readonly json_name: "values";
            readonly name: "values";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: true;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryValue";
        }];
        readonly LogQueryOrdering: readonly [{
            readonly deprecated: false;
            readonly json_name: "column";
            readonly name: "column";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "valueType";
            readonly name: "value_type";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "direction";
            readonly name: "direction";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly LogQueryRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "pipeline";
            readonly name: "pipeline";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "budget";
            readonly name: "budget";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryBudget";
        }];
        readonly LogQueryResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "events";
            readonly name: "events";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: true;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryEvent";
        }];
        readonly LogQueryRow: readonly [{
            readonly deprecated: false;
            readonly json_name: "cells";
            readonly name: "cells";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: true;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryCell";
        }, {
            readonly deprecated: false;
            readonly json_name: "replayed";
            readonly name: "replayed";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 8;
            readonly type_name: null;
        }];
        readonly LogQuerySessionRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "execute";
            readonly name: "execute";
            readonly number: 1;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryRequest";
        }, {
            readonly deprecated: false;
            readonly json_name: "resume";
            readonly name: "resume";
            readonly number: 2;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 12;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "tail";
            readonly name: "tail";
            readonly number: 4;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryTailRequest";
        }, {
            readonly deprecated: false;
            readonly json_name: "batchLimit";
            readonly name: "batch_limit";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }];
        readonly LogQuerySnapshot: readonly [{
            readonly deprecated: false;
            readonly json_name: "identity";
            readonly name: "identity";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 12;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "generation";
            readonly name: "generation";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "frontier";
            readonly name: "frontier";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly LogQueryStats: readonly [{
            readonly deprecated: false;
            readonly json_name: "records";
            readonly name: "records";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "scannedBytes";
            readonly name: "scanned_bytes";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "decodedRecords";
            readonly name: "decoded_records";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "outputBytes";
            readonly name: "output_bytes";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "memoryPeakBytes";
            readonly name: "memory_peak_bytes";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "cpuWorkUnits";
            readonly name: "cpu_work_units";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "wallSeconds";
            readonly name: "wall_seconds";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "lastSequence";
            readonly name: "last_sequence";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "resultDigest";
            readonly name: "result_digest";
            readonly number: 9;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 12;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "cumulativeBudget";
            readonly name: "cumulative_budget";
            readonly number: 10;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryBudget";
        }, {
            readonly deprecated: false;
            readonly json_name: "resumeCount";
            readonly name: "resume_count";
            readonly number: 11;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "repeatedBatchCount";
            readonly name: "repeated_batch_count";
            readonly number: 12;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "limitingBudget";
            readonly name: "limiting_budget";
            readonly number: 13;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "reducedPruning";
            readonly name: "reduced_pruning";
            readonly number: 14;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 8;
            readonly type_name: null;
        }];
        readonly LogQueryTailRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "query";
            readonly name: "query";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryRequest";
        }, {
            readonly deprecated: false;
            readonly json_name: "cursor";
            readonly name: "cursor";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 12;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "historicalRows";
            readonly name: "historical_rows";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "acknowledgement";
            readonly name: "acknowledgement";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryAcknowledgement";
        }];
        readonly LogQueryTerminal: readonly [{
            readonly deprecated: false;
            readonly json_name: "state";
            readonly name: "state";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "reason";
            readonly name: "reason";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "stats";
            readonly name: "stats";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryStats";
        }, {
            readonly deprecated: false;
            readonly json_name: "affectedRanges";
            readonly name: "affected_ranges";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: true;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryAffectedRange";
        }, {
            readonly deprecated: false;
            readonly json_name: "continuationCursor";
            readonly name: "continuation_cursor";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 12;
            readonly type_name: null;
        }];
        readonly LogQueryTimestamp: readonly [{
            readonly deprecated: false;
            readonly json_name: "unixNanoseconds";
            readonly name: "unix_nanoseconds";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 18;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "provenance";
            readonly name: "provenance";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "quality";
            readonly name: "quality";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "sourceValue";
            readonly name: "source_value";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly LogQueryTruncated: readonly [{
            readonly deprecated: false;
            readonly json_name: "action";
            readonly name: "action";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "value";
            readonly name: "value";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryValue";
        }];
        readonly LogQueryValue: readonly [{
            readonly deprecated: false;
            readonly json_name: "nullValue";
            readonly name: "null_value";
            readonly number: 1;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryNull";
        }, {
            readonly deprecated: false;
            readonly json_name: "booleanValue";
            readonly name: "boolean_value";
            readonly number: 2;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 8;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "integerValue";
            readonly name: "integer_value";
            readonly number: 3;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 18;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "floatBits";
            readonly name: "float_bits";
            readonly number: 4;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 6;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "textValue";
            readonly name: "text_value";
            readonly number: 5;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "bytesValue";
            readonly name: "bytes_value";
            readonly number: 6;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 12;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "arrayValue";
            readonly name: "array_value";
            readonly number: 7;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryArray";
        }, {
            readonly deprecated: false;
            readonly json_name: "objectValue";
            readonly name: "object_value";
            readonly number: 8;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryObject";
        }, {
            readonly deprecated: false;
            readonly json_name: "markerValue";
            readonly name: "marker_value";
            readonly number: 9;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryMarker";
        }, {
            readonly deprecated: false;
            readonly json_name: "truncatedValue";
            readonly name: "truncated_value";
            readonly number: 10;
            readonly oneof: 0;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.LogQueryTruncated";
        }];
        readonly MaintenanceControlResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "task";
            readonly name: "task";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.MaintenanceTaskAcknowledgement";
        }, {
            readonly deprecated: false;
            readonly json_name: "auditPosition";
            readonly name: "audit_position";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "action";
            readonly name: "action";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "resourceGeneration";
            readonly name: "resource_generation";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "pauseUntilUnixSeconds";
            readonly name: "pause_until_unix_seconds";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly MaintenanceExplainRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "identity";
            readonly name: "identity";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly MaintenanceExplainResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "task";
            readonly name: "task";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.MaintenanceTaskStatus";
        }];
        readonly MaintenancePauseRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "identity";
            readonly name: "identity";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "resourceGeneration";
            readonly name: "resource_generation";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "durationSeconds";
            readonly name: "duration_seconds";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "idempotencyKey";
            readonly name: "idempotency_key";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly MaintenanceResourceReservations: readonly [{
            readonly deprecated: false;
            readonly json_name: "memoryBytes";
            readonly name: "memory_bytes";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "queueSlots";
            readonly name: "queue_slots";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "taskSlots";
            readonly name: "task_slots";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "bufferCacheBytes";
            readonly name: "buffer_cache_bytes";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "batchItems";
            readonly name: "batch_items";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "leaseSlots";
            readonly name: "lease_slots";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "retrySlots";
            readonly name: "retry_slots";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "ioPermits";
            readonly name: "io_permits";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "cpuWorkUnits";
            readonly name: "cpu_work_units";
            readonly number: 9;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "fileDescriptors";
            readonly name: "file_descriptors";
            readonly number: 10;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "diskHeadroomBytes";
            readonly name: "disk_headroom_bytes";
            readonly number: 11;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly MaintenanceResumeRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "identity";
            readonly name: "identity";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "idempotencyKey";
            readonly name: "idempotency_key";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly MaintenanceRunRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "taskClass";
            readonly name: "task_class";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "tenant";
            readonly name: "tenant";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "signal";
            readonly name: "signal";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "shard";
            readonly name: "shard";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "idempotencyKey";
            readonly name: "idempotency_key";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly MaintenanceRunResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "task";
            readonly name: "task";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.MaintenanceTaskAcknowledgement";
        }, {
            readonly deprecated: false;
            readonly json_name: "resourceGeneration";
            readonly name: "resource_generation";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly MaintenanceStatusRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "cursor";
            readonly name: "cursor";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "limit";
            readonly name: "limit";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }];
        readonly MaintenanceStatusResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "tasks";
            readonly name: "tasks";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: true;
            readonly type: 11;
            readonly type_name: ".positron.v1.MaintenanceTaskStatus";
        }, {
            readonly deprecated: false;
            readonly json_name: "queued";
            readonly name: "queued";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "running";
            readonly name: "running";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "deferred";
            readonly name: "deferred";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "terminal";
            readonly name: "terminal";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "returned";
            readonly name: "returned";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "total";
            readonly name: "total";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "nextCursor";
            readonly name: "next_cursor";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "integrityFindings";
            readonly name: "integrity_findings";
            readonly number: 9;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: true;
            readonly type: 11;
            readonly type_name: ".positron.v1.IntegrityQuarantineFinding";
        }];
        readonly MaintenanceTaskAcknowledgement: readonly [{
            readonly deprecated: false;
            readonly json_name: "identity";
            readonly name: "identity";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "taskClass";
            readonly name: "task_class";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "scope";
            readonly name: "scope";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "submittedAtUnixSeconds";
            readonly name: "submitted_at_unix_seconds";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly MaintenanceTaskStatus: readonly [{
            readonly deprecated: false;
            readonly json_name: "identity";
            readonly name: "identity";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "taskClass";
            readonly name: "task_class";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "scope";
            readonly name: "scope";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "phase";
            readonly name: "phase";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "submittedAtUnixSeconds";
            readonly name: "submitted_at_unix_seconds";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "checkpointSequence";
            readonly name: "checkpoint_sequence";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "pauseUntilUnixSeconds";
            readonly name: "pause_until_unix_seconds";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "cancellationRequested";
            readonly name: "cancellation_requested";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 8;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "resourceGeneration";
            readonly name: "resource_generation";
            readonly number: 9;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "reservations";
            readonly name: "reservations";
            readonly number: 10;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.MaintenanceResourceReservations";
        }, {
            readonly deprecated: false;
            readonly json_name: "blockedPrecondition";
            readonly name: "blocked_precondition";
            readonly number: 11;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "safeActions";
            readonly name: "safe_actions";
            readonly number: 12;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: true;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "backlogAgeSeconds";
            readonly name: "backlog_age_seconds";
            readonly number: 13;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "conflictOwner";
            readonly name: "conflict_owner";
            readonly number: 14;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "checkpointCompletedInputs";
            readonly name: "checkpoint_completed_inputs";
            readonly number: 15;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "inputObjectCount";
            readonly name: "input_object_count";
            readonly number: 16;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "outputObjectCount";
            readonly name: "output_object_count";
            readonly number: 17;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "estimatedOutputObjectAmplificationMilli";
            readonly name: "estimated_output_object_amplification_milli";
            readonly number: 18;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "terminalOutcome";
            readonly name: "terminal_outcome";
            readonly number: 19;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expectedForegroundImpact";
            readonly name: "expected_foreground_impact";
            readonly number: 20;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.MaintenanceResourceReservations";
        }, {
            readonly deprecated: false;
            readonly json_name: "terminalFailureClass";
            readonly name: "terminal_failure_class";
            readonly number: 21;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "maintenanceWindowUntilUnixSeconds";
            readonly name: "maintenance_window_until_unix_seconds";
            readonly number: 22;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "lastProgressAtUnixSeconds";
            readonly name: "last_progress_at_unix_seconds";
            readonly number: 23;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "noDurableProgressSloBreached";
            readonly name: "no_durable_progress_slo_breached";
            readonly number: 24;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 8;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "noDurableProgressSloSeconds";
            readonly name: "no_durable_progress_slo_seconds";
            readonly number: 25;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "capacityRisk";
            readonly name: "capacity_risk";
            readonly number: 26;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "retentionImpact";
            readonly name: "retention_impact";
            readonly number: 27;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "recoveryImpact";
            readonly name: "recovery_impact";
            readonly number: 28;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "automaticResumeAtUnixSeconds";
            readonly name: "automatic_resume_at_unix_seconds";
            readonly number: 29;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly MaintenanceWindowRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "deferredClasses";
            readonly name: "deferred_classes";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: true;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expectedCatalogGeneration";
            readonly name: "expected_catalog_generation";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "durationSeconds";
            readonly name: "duration_seconds";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "idempotencyKey";
            readonly name: "idempotency_key";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly MaintenanceWindowResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "deferredClasses";
            readonly name: "deferred_classes";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: true;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "untilUnixSeconds";
            readonly name: "until_unix_seconds";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "catalogGeneration";
            readonly name: "catalog_generation";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "auditPosition";
            readonly name: "audit_position";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly OnlineVerificationReport: readonly [{
            readonly deprecated: false;
            readonly json_name: "reportVersion";
            readonly name: "report_version";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "tenant";
            readonly name: "tenant";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "signal";
            readonly name: "signal";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "shard";
            readonly name: "shard";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "catalogGeneration";
            readonly name: "catalog_generation";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "examinedSegments";
            readonly name: "examined_segments";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "examinedBytes";
            readonly name: "examined_bytes";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "omittedSegments";
            readonly name: "omitted_segments";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "outcome";
            readonly name: "outcome";
            readonly number: 9;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "verificationComplete";
            readonly name: "verification_complete";
            readonly number: 10;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 8;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "continuation";
            readonly name: "continuation";
            readonly number: 11;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "findings";
            readonly name: "findings";
            readonly number: 12;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: true;
            readonly type: 11;
            readonly type_name: ".positron.v1.IntegrityQuarantineFinding";
        }, {
            readonly deprecated: false;
            readonly json_name: "reportChecksum";
            readonly name: "report_checksum";
            readonly number: 13;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly OnlineVerificationRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "tenant";
            readonly name: "tenant";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "signal";
            readonly name: "signal";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "shard";
            readonly name: "shard";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expectedCatalogGeneration";
            readonly name: "expected_catalog_generation";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "continuation";
            readonly name: "continuation";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly PolicyActivateRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "policyJson";
            readonly name: "policy_json";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expectedGeneration";
            readonly name: "expected_generation";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "idempotencyKey";
            readonly name: "idempotency_key";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly PolicyActivateResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "resourceGeneration";
            readonly name: "resource_generation";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "policyDigest";
            readonly name: "policy_digest";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "auditPosition";
            readonly name: "audit_position";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly PolicyDiffRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "beforePolicyJson";
            readonly name: "before_policy_json";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "afterPolicyJson";
            readonly name: "after_policy_json";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly PolicyDiffResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "beforePolicyGeneration";
            readonly name: "before_policy_generation";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "beforePolicyDigest";
            readonly name: "before_policy_digest";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "afterPolicyGeneration";
            readonly name: "after_policy_generation";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "afterPolicyDigest";
            readonly name: "after_policy_digest";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "semanticChanges";
            readonly name: "semantic_changes";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: true;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly PolicyExplainRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "policyJson";
            readonly name: "policy_json";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "candidateJson";
            readonly name: "candidate_json";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly PolicyExplainResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "policyGeneration";
            readonly name: "policy_generation";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "policyDigest";
            readonly name: "policy_digest";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "outcome";
            readonly name: "outcome";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "explanation";
            readonly name: "explanation";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly PolicyPreviewRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "policyJson";
            readonly name: "policy_json";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly PolicyTestRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "policyJson";
            readonly name: "policy_json";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "candidateJson";
            readonly name: "candidate_json";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly PolicyTestResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "policyGeneration";
            readonly name: "policy_generation";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "policyDigest";
            readonly name: "policy_digest";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "accepted";
            readonly name: "accepted";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 8;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "appliedRuleCount";
            readonly name: "applied_rule_count";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }];
        readonly PolicyValidateResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "policyGeneration";
            readonly name: "policy_generation";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "policyDigest";
            readonly name: "policy_digest";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "ruleCount";
            readonly name: "rule_count";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }];
        readonly ProviderMigrationIdentity: readonly [{
            readonly deprecated: false;
            readonly json_name: "family";
            readonly name: "family";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "locator";
            readonly name: "locator";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "version";
            readonly name: "version";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly ProviderMigrationOperation: readonly [{
            readonly deprecated: false;
            readonly json_name: "id";
            readonly name: "id";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "status";
            readonly name: "status";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "phase";
            readonly name: "phase";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "progressPercent";
            readonly name: "progress_percent";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "retry";
            readonly name: "retry";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "cancellation";
            readonly name: "cancellation";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "irreversibleBoundary";
            readonly name: "irreversible_boundary";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "lookupExpiresAtUnixSeconds";
            readonly name: "lookup_expires_at_unix_seconds";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly ProviderMigrationRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "action";
            readonly name: "action";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expectedCatalogGeneration";
            readonly name: "expected_catalog_generation";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "idempotencyKey";
            readonly name: "idempotency_key";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "configurationReference";
            readonly name: "configuration_reference";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "operationId";
            readonly name: "operation_id";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly ProviderMigrationResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "catalogGeneration";
            readonly name: "catalog_generation";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "rootPhase";
            readonly name: "root_phase";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "activeEpoch";
            readonly name: "active_epoch";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "successorEpoch";
            readonly name: "successor_epoch";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "predecessorEpoch";
            readonly name: "predecessor_epoch";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "operation";
            readonly name: "operation";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.ProviderMigrationOperation";
        }, {
            readonly deprecated: false;
            readonly json_name: "activeProvider";
            readonly name: "active_provider";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.ProviderMigrationIdentity";
        }, {
            readonly deprecated: false;
            readonly json_name: "sourceProvider";
            readonly name: "source_provider";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.ProviderMigrationIdentity";
        }, {
            readonly deprecated: false;
            readonly json_name: "targetProvider";
            readonly name: "target_provider";
            readonly number: 9;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.ProviderMigrationIdentity";
        }];
        readonly PublicError: readonly [{
            readonly deprecated: false;
            readonly json_name: "code";
            readonly name: "code";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 14;
            readonly type_name: ".positron.v1.PublicErrorCode";
        }, {
            readonly deprecated: false;
            readonly json_name: "retryClass";
            readonly name: "retry_class";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 14;
            readonly type_name: ".positron.v1.RetryClass";
        }, {
            readonly deprecated: false;
            readonly json_name: "completionState";
            readonly name: "completion_state";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 14;
            readonly type_name: ".positron.v1.CompletionState";
        }, {
            readonly deprecated: false;
            readonly json_name: "source";
            readonly name: "source";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 14;
            readonly type_name: ".positron.v1.FailureSource";
        }, {
            readonly deprecated: false;
            readonly json_name: "safeDetail";
            readonly name: "safe_detail";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 14;
            readonly type_name: ".positron.v1.SafeDetail";
        }];
        readonly RepositoryAwsS3Target: readonly [{
            readonly deprecated: false;
            readonly json_name: "bucket";
            readonly name: "bucket";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "region";
            readonly name: "region";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "endpoint";
            readonly name: "endpoint";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expectedOwner";
            readonly name: "expected_owner";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "prefix";
            readonly name: "prefix";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly RepositoryAzureBlobTarget: readonly [{
            readonly deprecated: false;
            readonly json_name: "account";
            readonly name: "account";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "container";
            readonly name: "container";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "prefix";
            readonly name: "prefix";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly RepositoryDefaultRetention: readonly [{
            readonly deprecated: false;
            readonly json_name: "mode";
            readonly name: "mode";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "periodUnit";
            readonly name: "period_unit";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "period";
            readonly name: "period";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }];
        readonly RepositoryDoctorResult: readonly [{
            readonly deprecated: false;
            readonly json_name: "verified";
            readonly name: "verified";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 8;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "probesDeleted";
            readonly name: "probes_deleted";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 8;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "externalRetention";
            readonly name: "external_retention";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly RepositoryEventHold: readonly [{
            readonly deprecated: false;
            readonly json_name: "enabled";
            readonly name: "enabled";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 8;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "periodUnit";
            readonly name: "period_unit";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "period";
            readonly name: "period";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }];
        readonly RepositoryGoogleCloudStorageTarget: readonly [{
            readonly deprecated: false;
            readonly json_name: "bucket";
            readonly name: "bucket";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "projectNumber";
            readonly name: "project_number";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "location";
            readonly name: "location";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "prefix";
            readonly name: "prefix";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly RepositoryIdentity: readonly [{
            readonly deprecated: false;
            readonly json_name: "repositoryId";
            readonly name: "repository_id";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "instanceId";
            readonly name: "instance_id";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "providerKind";
            readonly name: "provider_kind";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "formatEpoch";
            readonly name: "format_epoch";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "integrityFingerprint";
            readonly name: "integrity_fingerprint";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "prefixCommitment";
            readonly name: "prefix_commitment";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly RepositoryLifecyclePolicy: readonly [{
            readonly deprecated: false;
            readonly json_name: "currentExpiration";
            readonly name: "current_expiration";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 8;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "noncurrentExpiration";
            readonly name: "noncurrent_expiration";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 8;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "transition";
            readonly name: "transition";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 8;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "abandonedUploadExpiration";
            readonly name: "abandoned_upload_expiration";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 8;
            readonly type_name: null;
        }];
        readonly RepositoryObjectProtection: readonly [{
            readonly deprecated: false;
            readonly json_name: "retention";
            readonly name: "retention";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryPolicyObservation";
        }, {
            readonly deprecated: false;
            readonly json_name: "legalHold";
            readonly name: "legal_hold";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryPolicyObservation";
        }, {
            readonly deprecated: false;
            readonly json_name: "eventHold";
            readonly name: "event_hold";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryPolicyObservation";
        }];
        readonly RepositoryObjectRetention: readonly [{
            readonly deprecated: false;
            readonly json_name: "mode";
            readonly name: "mode";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "retainUntilUnixSeconds";
            readonly name: "retain_until_unix_seconds";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly RepositoryOperation: readonly [{
            readonly deprecated: false;
            readonly json_name: "id";
            readonly name: "id";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "status";
            readonly name: "status";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "phase";
            readonly name: "phase";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "progressPercent";
            readonly name: "progress_percent";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "retry";
            readonly name: "retry";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "cancellation";
            readonly name: "cancellation";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "irreversibleBoundary";
            readonly name: "irreversible_boundary";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "lookupExpiresAtUnixSeconds";
            readonly name: "lookup_expires_at_unix_seconds";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly RepositoryPolicyObservation: readonly [{
            readonly deprecated: false;
            readonly json_name: "state";
            readonly name: "state";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "value";
            readonly name: "value";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "failure";
            readonly name: "failure";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "retryAfterMillis";
            readonly name: "retry_after_millis";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "defaultRetention";
            readonly name: "default_retention";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryDefaultRetention";
        }, {
            readonly deprecated: false;
            readonly json_name: "lifecycle";
            readonly name: "lifecycle";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryLifecyclePolicy";
        }, {
            readonly deprecated: false;
            readonly json_name: "objectRetention";
            readonly name: "object_retention";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryObjectRetention";
        }, {
            readonly deprecated: false;
            readonly json_name: "eventHold";
            readonly name: "event_hold";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryEventHold";
        }];
        readonly RepositoryPolicyReceipt: readonly [{
            readonly deprecated: false;
            readonly json_name: "observedAtUnixSeconds";
            readonly name: "observed_at_unix_seconds";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "versioning";
            readonly name: "versioning";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryPolicyObservation";
        }, {
            readonly deprecated: false;
            readonly json_name: "objectLock";
            readonly name: "object_lock";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryPolicyObservation";
        }, {
            readonly deprecated: false;
            readonly json_name: "lifecycle";
            readonly name: "lifecycle";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryPolicyObservation";
        }, {
            readonly deprecated: false;
            readonly json_name: "doctorProbe";
            readonly name: "doctor_probe";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryObjectProtection";
        }, {
            readonly deprecated: false;
            readonly json_name: "softDelete";
            readonly name: "soft_delete";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryPolicyObservation";
        }];
        readonly RepositoryRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "action";
            readonly name: "action";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expectedCatalogGeneration";
            readonly name: "expected_catalog_generation";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "idempotencyKey";
            readonly name: "idempotency_key";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "locator";
            readonly name: "locator";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "repositoryId";
            readonly name: "repository_id";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "operationId";
            readonly name: "operation_id";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "awsS3";
            readonly name: "aws_s3";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryAwsS3Target";
        }, {
            readonly deprecated: false;
            readonly json_name: "googleCloudStorage";
            readonly name: "google_cloud_storage";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryGoogleCloudStorageTarget";
        }, {
            readonly deprecated: false;
            readonly json_name: "azureBlob";
            readonly name: "azure_blob";
            readonly number: 9;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryAzureBlobTarget";
        }];
        readonly RepositoryResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "catalogGeneration";
            readonly name: "catalog_generation";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "operation";
            readonly name: "operation";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryOperation";
        }, {
            readonly deprecated: false;
            readonly json_name: "identity";
            readonly name: "identity";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryIdentity";
        }, {
            readonly deprecated: false;
            readonly json_name: "doctor";
            readonly name: "doctor";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryDoctorResult";
        }, {
            readonly deprecated: false;
            readonly json_name: "policy";
            readonly name: "policy";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.RepositoryPolicyReceipt";
        }];
        readonly SegmentAbandonmentRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "tenant";
            readonly name: "tenant";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "signal";
            readonly name: "signal";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "shard";
            readonly name: "shard";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "segment";
            readonly name: "segment";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expectedCatalogGeneration";
            readonly name: "expected_catalog_generation";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "confirmation";
            readonly name: "confirmation";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "idempotencyKey";
            readonly name: "idempotency_key";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "acceptDataLoss";
            readonly name: "accept_data_loss";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 8;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "operationId";
            readonly name: "operation_id";
            readonly number: 9;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly SegmentAbandonmentResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "catalogGeneration";
            readonly name: "catalog_generation";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "status";
            readonly name: "status";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "irreversibleBoundary";
            readonly name: "irreversible_boundary";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "confirmation";
            readonly name: "confirmation";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "operationId";
            readonly name: "operation_id";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "finding";
            readonly name: "finding";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.IntegrityQuarantineFinding";
        }];
        readonly TenantAliasBindRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "tenant";
            readonly name: "tenant";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "externalAlias";
            readonly name: "external_alias";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expectedGeneration";
            readonly name: "expected_generation";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "idempotencyKey";
            readonly name: "idempotency_key";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly TenantAliasBindResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "tenant";
            readonly name: "tenant";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "aliasGeneration";
            readonly name: "alias_generation";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "auditPosition";
            readonly name: "audit_position";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "auditIngestTimeUnixSeconds";
            readonly name: "audit_ingest_time_unix_seconds";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly TenantCreateRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "slug";
            readonly name: "slug";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "displayName";
            readonly name: "display_name";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "retentionSeconds";
            readonly name: "retention_seconds";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "weight";
            readonly name: "weight";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "memoryBytes";
            readonly name: "memory_bytes";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "queueSlots";
            readonly name: "queue_slots";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "taskSlots";
            readonly name: "task_slots";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "bufferCacheBytes";
            readonly name: "buffer_cache_bytes";
            readonly number: 9;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "batchItems";
            readonly name: "batch_items";
            readonly number: 10;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "leaseSlots";
            readonly name: "lease_slots";
            readonly number: 11;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "retrySlots";
            readonly name: "retry_slots";
            readonly number: 12;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "ioPermits";
            readonly name: "io_permits";
            readonly number: 13;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "cpuWorkUnits";
            readonly name: "cpu_work_units";
            readonly number: 14;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "fileDescriptors";
            readonly name: "file_descriptors";
            readonly number: 15;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "diskHeadroomBytes";
            readonly name: "disk_headroom_bytes";
            readonly number: 16;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "idempotencyKey";
            readonly name: "idempotency_key";
            readonly number: 17;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly TenantCreateResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "tenant";
            readonly name: "tenant";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "resourceGeneration";
            readonly name: "resource_generation";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "auditPosition";
            readonly name: "audit_position";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly TenantDescriptor: readonly [{
            readonly deprecated: false;
            readonly json_name: "tenant";
            readonly name: "tenant";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "slug";
            readonly name: "slug";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "displayName";
            readonly name: "display_name";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "retentionSeconds";
            readonly name: "retention_seconds";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "displayGeneration";
            readonly name: "display_generation";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "retentionGeneration";
            readonly name: "retention_generation";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "lifecycle";
            readonly name: "lifecycle";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 14;
            readonly type_name: ".positron.v1.TenantLifecycleTarget";
        }];
        readonly TenantDisplayNameUpdateRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "tenant";
            readonly name: "tenant";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expectedDisplayGeneration";
            readonly name: "expected_display_generation";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "displayName";
            readonly name: "display_name";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "idempotencyKey";
            readonly name: "idempotency_key";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly TenantDisplayNameUpdateResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "tenant";
            readonly name: "tenant";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "displayGeneration";
            readonly name: "display_generation";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "auditPosition";
            readonly name: "audit_position";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly TenantInspectRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "tenant";
            readonly name: "tenant";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly TenantInspectResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "tenant";
            readonly name: "tenant";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.TenantDescriptor";
        }];
        readonly TenantLifecycleTransitionRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "tenant";
            readonly name: "tenant";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "target";
            readonly name: "target";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 14;
            readonly type_name: ".positron.v1.TenantLifecycleTarget";
        }, {
            readonly deprecated: false;
            readonly json_name: "expectedGeneration";
            readonly name: "expected_generation";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "idempotencyKey";
            readonly name: "idempotency_key";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly TenantLifecycleTransitionResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "tenant";
            readonly name: "tenant";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "from";
            readonly name: "from";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 14;
            readonly type_name: ".positron.v1.TenantLifecycleTarget";
        }, {
            readonly deprecated: false;
            readonly json_name: "to";
            readonly name: "to";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 14;
            readonly type_name: ".positron.v1.TenantLifecycleTarget";
        }, {
            readonly deprecated: false;
            readonly json_name: "lifecycleGeneration";
            readonly name: "lifecycle_generation";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "auditPosition";
            readonly name: "audit_position";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "auditIngestTimeUnixSeconds";
            readonly name: "audit_ingest_time_unix_seconds";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly TenantListRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "continuation";
            readonly name: "continuation";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly TenantListResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "tenants";
            readonly name: "tenants";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: true;
            readonly type: 11;
            readonly type_name: ".positron.v1.TenantDescriptor";
        }, {
            readonly deprecated: false;
            readonly json_name: "continuation";
            readonly name: "continuation";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly TenantPurgeRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "action";
            readonly name: "action";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "tenantId";
            readonly name: "tenant_id";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "confirmationSlug";
            readonly name: "confirmation_slug";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expectedCatalogGeneration";
            readonly name: "expected_catalog_generation";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expectedLifecycleGeneration";
            readonly name: "expected_lifecycle_generation";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "idempotencyKey";
            readonly name: "idempotency_key";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "operationId";
            readonly name: "operation_id";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly TenantPurgeResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "catalogGeneration";
            readonly name: "catalog_generation";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "operation";
            readonly name: "operation";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.ProviderMigrationOperation";
        }, {
            readonly deprecated: false;
            readonly json_name: "managedScope";
            readonly name: "managed_scope";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly TenantQuotaUpdateRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "tenant";
            readonly name: "tenant";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expectedGeneration";
            readonly name: "expected_generation";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "idempotencyKey";
            readonly name: "idempotency_key";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "weight";
            readonly name: "weight";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "memoryBytes";
            readonly name: "memory_bytes";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "queueSlots";
            readonly name: "queue_slots";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "taskSlots";
            readonly name: "task_slots";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "bufferCacheBytes";
            readonly name: "buffer_cache_bytes";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "batchItems";
            readonly name: "batch_items";
            readonly number: 9;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "leaseSlots";
            readonly name: "lease_slots";
            readonly number: 10;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "retrySlots";
            readonly name: "retry_slots";
            readonly number: 11;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "ioPermits";
            readonly name: "io_permits";
            readonly number: 12;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "cpuWorkUnits";
            readonly name: "cpu_work_units";
            readonly number: 13;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "fileDescriptors";
            readonly name: "file_descriptors";
            readonly number: 14;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "diskHeadroomBytes";
            readonly name: "disk_headroom_bytes";
            readonly number: 15;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly TenantQuotaUpdateResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "resourceGeneration";
            readonly name: "resource_generation";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly TenantRetentionPreviewRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "tenant";
            readonly name: "tenant";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "proposedRetentionSeconds";
            readonly name: "proposed_retention_seconds";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "continuation";
            readonly name: "continuation";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly TenantRetentionPreviewResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "tenant";
            readonly name: "tenant";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "retentionGeneration";
            readonly name: "retention_generation";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "proposedRetentionSeconds";
            readonly name: "proposed_retention_seconds";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "catalogIdentity";
            readonly name: "catalog_identity";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "catalogGeneration";
            readonly name: "catalog_generation";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "confirmationDigest";
            readonly name: "confirmation_digest";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "scopes";
            readonly name: "scopes";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: true;
            readonly type: 11;
            readonly type_name: ".positron.v1.TenantRetentionScopeImpact";
        }, {
            readonly deprecated: false;
            readonly json_name: "continuation";
            readonly name: "continuation";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "confirmationEvaluatedAtUnixNanos";
            readonly name: "confirmation_evaluated_at_unix_nanos";
            readonly number: 9;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 18;
            readonly type_name: null;
        }];
        readonly TenantRetentionScopeImpact: readonly [{
            readonly deprecated: false;
            readonly json_name: "signal";
            readonly name: "signal";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "shard";
            readonly name: "shard";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "catalogIdentity";
            readonly name: "catalog_identity";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "catalogGeneration";
            readonly name: "catalog_generation";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "evaluatedAtUnixNanos";
            readonly name: "evaluated_at_unix_nanos";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 18;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "affectedStartUnixNanos";
            readonly name: "affected_start_unix_nanos";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 18;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "affectedEndUnixNanos";
            readonly name: "affected_end_unix_nanos";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 18;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "affectedBytes";
            readonly name: "affected_bytes";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "immediatelyReclaimableBytes";
            readonly name: "immediately_reclaimable_bytes";
            readonly number: 9;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "deferredActiveSegmentBytes";
            readonly name: "deferred_active_segment_bytes";
            readonly number: 10;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "deferredMixedSealedSegmentBytes";
            readonly name: "deferred_mixed_sealed_segment_bytes";
            readonly number: 11;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "earliestReclamation";
            readonly name: "earliest_reclamation";
            readonly number: 12;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 14;
            readonly type_name: ".positron.v1.RetentionReclamation";
        }, {
            readonly deprecated: false;
            readonly json_name: "earliestReclamationUnixNanos";
            readonly name: "earliest_reclamation_unix_nanos";
            readonly number: 13;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 18;
            readonly type_name: null;
        }];
        readonly TenantRetentionUpdateRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "tenant";
            readonly name: "tenant";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "proposedRetentionSeconds";
            readonly name: "proposed_retention_seconds";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expectedGeneration";
            readonly name: "expected_generation";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "confirmationDigest";
            readonly name: "confirmation_digest";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "idempotencyKey";
            readonly name: "idempotency_key";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "confirmationEvaluatedAtUnixNanos";
            readonly name: "confirmation_evaluated_at_unix_nanos";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 18;
            readonly type_name: null;
        }];
        readonly TenantRetentionUpdateResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "tenant";
            readonly name: "tenant";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "retentionGeneration";
            readonly name: "retention_generation";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "auditPosition";
            readonly name: "audit_position";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "auditIngestTimeUnixSeconds";
            readonly name: "audit_ingest_time_unix_seconds";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly UpgradeDetails: readonly [{
            readonly deprecated: false;
            readonly json_name: "sourceVersion";
            readonly name: "source_version";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "targetVersion";
            readonly name: "target_version";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "sourceManifest";
            readonly name: "source_manifest";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "targetManifest";
            readonly name: "target_manifest";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "sourceArtifact";
            readonly name: "source_artifact";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "targetArtifact";
            readonly name: "target_artifact";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "configuration";
            readonly name: "configuration";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "formatEpoch";
            readonly name: "format_epoch";
            readonly number: 9;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "repositoryId";
            readonly name: "repository_id";
            readonly number: 10;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "rollbackAvailable";
            readonly name: "rollback_available";
            readonly number: 11;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 8;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "snapshotManifest";
            readonly name: "snapshot_manifest";
            readonly number: 12;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly UpgradeOperation: readonly [{
            readonly deprecated: false;
            readonly json_name: "id";
            readonly name: "id";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "status";
            readonly name: "status";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "phase";
            readonly name: "phase";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 14;
            readonly type_name: ".positron.v1.UpgradePhase";
        }, {
            readonly deprecated: false;
            readonly json_name: "progressPercent";
            readonly name: "progress_percent";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 13;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "retry";
            readonly name: "retry";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "cancellation";
            readonly name: "cancellation";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "irreversibleBoundary";
            readonly name: "irreversible_boundary";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "lookupExpiresAtUnixSeconds";
            readonly name: "lookup_expires_at_unix_seconds";
            readonly number: 8;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }];
        readonly UpgradeRequest: readonly [{
            readonly deprecated: false;
            readonly json_name: "action";
            readonly name: "action";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "candidateManifest";
            readonly name: "candidate_manifest";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "repositoryId";
            readonly name: "repository_id";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "retentionSeconds";
            readonly name: "retention_seconds";
            readonly number: 4;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "expectedCatalogGeneration";
            readonly name: "expected_catalog_generation";
            readonly number: 5;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "idempotencyKey";
            readonly name: "idempotency_key";
            readonly number: 6;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "operationId";
            readonly name: "operation_id";
            readonly number: 7;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 9;
            readonly type_name: null;
        }];
        readonly UpgradeResponse: readonly [{
            readonly deprecated: false;
            readonly json_name: "catalogGeneration";
            readonly name: "catalog_generation";
            readonly number: 1;
            readonly oneof: null;
            readonly optional: false;
            readonly repeated: false;
            readonly type: 4;
            readonly type_name: null;
        }, {
            readonly deprecated: false;
            readonly json_name: "operation";
            readonly name: "operation";
            readonly number: 2;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.UpgradeOperation";
        }, {
            readonly deprecated: false;
            readonly json_name: "details";
            readonly name: "details";
            readonly number: 3;
            readonly oneof: null;
            readonly optional: true;
            readonly repeated: false;
            readonly type: 11;
            readonly type_name: ".positron.v1.UpgradeDetails";
        }];
    };
};
export declare const routes: readonly [{
    readonly method: "POST";
    readonly path: "/v1/capabilities:negotiate";
    readonly public_error_fields: readonly [{
        readonly deprecated: false;
        readonly json: "code";
        readonly number: 1;
        readonly proto: "code";
        readonly type: "PublicErrorCode";
    }, {
        readonly deprecated: false;
        readonly json: "retry_class";
        readonly number: 2;
        readonly proto: "retry_class";
        readonly type: "RetryClass";
    }, {
        readonly deprecated: false;
        readonly json: "completion_state";
        readonly number: 3;
        readonly proto: "completion_state";
        readonly type: "CompletionState";
    }, {
        readonly deprecated: false;
        readonly json: "source";
        readonly number: 4;
        readonly proto: "source";
        readonly type: "FailureSource";
    }, {
        readonly deprecated: false;
        readonly json: "safe_detail";
        readonly number: 5;
        readonly proto: "safe_detail";
        readonly type: "SafeDetail";
    }];
    readonly request: "CapabilityRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "api_major";
        readonly number: 1;
        readonly proto: "api_major";
        readonly type: "uint32";
    }, {
        readonly deprecated: false;
        readonly json: "capability";
        readonly number: 2;
        readonly proto: "capability";
        readonly type: "Capability";
    }];
    readonly response: "CapabilityResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "api_major";
        readonly number: 1;
        readonly proto: "api_major";
        readonly type: "uint32";
    }, {
        readonly deprecated: false;
        readonly json: "schema_digest";
        readonly number: 2;
        readonly proto: "schema_digest";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "availability";
        readonly number: 3;
        readonly proto: "availability";
        readonly type: "CapabilityAvailability";
    }, {
        readonly deprecated: false;
        readonly json: "refusal";
        readonly number: 4;
        readonly proto: "refusal";
        readonly type: "PublicError";
    }, {
        readonly deprecated: false;
        readonly json: "deprecation";
        readonly number: 5;
        readonly proto: "deprecation";
        readonly type: "DeprecationState";
    }, {
        readonly deprecated: false;
        readonly json: "capability";
        readonly number: 6;
        readonly proto: "capability";
        readonly type: "Capability";
    }];
    readonly rpc: "positron.v1.CapabilityService/Negotiate";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 1024;
    readonly max_response_bytes: 65536;
    readonly method: "POST";
    readonly path: "/v1/api-keys:manage";
    readonly request: "ApiKeyRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "action";
        readonly number: 1;
        readonly proto: "action";
        readonly type: "KeyAction";
    }, {
        readonly deprecated: false;
        readonly json: "scope";
        readonly number: 2;
        readonly proto: "scope";
        readonly type: "KeyScope";
    }, {
        readonly deprecated: false;
        readonly json: "principal";
        readonly number: 3;
        readonly proto: "principal";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "expires_at_unix_seconds";
        readonly number: 4;
        readonly proto: "expires_at_unix_seconds";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "expected_generation";
        readonly number: 5;
        readonly proto: "expected_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "idempotency_key";
        readonly number: 6;
        readonly proto: "idempotency_key";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "target_tenant";
        readonly number: 7;
        readonly proto: "target_tenant";
        readonly type: "string";
    }];
    readonly response: "ApiKeyResponse";
    readonly responses: {
        readonly "200": "ApiKeyResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "404": "key_unavailable";
        readonly "409": readonly ["stale_generation", "idempotency_conflict"];
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.ApiKeyService/Manage";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer TenantAdministration";
    readonly max_request_bytes: 1024;
    readonly max_response_bytes: 1024;
    readonly method: "POST";
    readonly path: "/v1/tenant-quotas:update";
    readonly request: "TenantQuotaUpdateRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "expected_generation";
        readonly number: 2;
        readonly proto: "expected_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "idempotency_key";
        readonly number: 3;
        readonly proto: "idempotency_key";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "weight";
        readonly number: 4;
        readonly proto: "weight";
        readonly type: "uint32";
    }, {
        readonly deprecated: false;
        readonly json: "memory_bytes";
        readonly number: 5;
        readonly proto: "memory_bytes";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "queue_slots";
        readonly number: 6;
        readonly proto: "queue_slots";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "task_slots";
        readonly number: 7;
        readonly proto: "task_slots";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "buffer_cache_bytes";
        readonly number: 8;
        readonly proto: "buffer_cache_bytes";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "batch_items";
        readonly number: 9;
        readonly proto: "batch_items";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "lease_slots";
        readonly number: 10;
        readonly proto: "lease_slots";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "retry_slots";
        readonly number: 11;
        readonly proto: "retry_slots";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "io_permits";
        readonly number: 12;
        readonly proto: "io_permits";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "cpu_work_units";
        readonly number: 13;
        readonly proto: "cpu_work_units";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "file_descriptors";
        readonly number: 14;
        readonly proto: "file_descriptors";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "disk_headroom_bytes";
        readonly number: 15;
        readonly proto: "disk_headroom_bytes";
        readonly type: "uint64";
    }];
    readonly response: "TenantQuotaUpdateResponse";
    readonly responses: {
        readonly "200": "TenantQuotaUpdateResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "409": readonly ["stale_generation", "idempotency_conflict"];
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.TenantQuotaService/Update";
    readonly stale_generation_response_fields: readonly [{
        readonly description: "current resource generation";
        readonly json: "resource_generation";
        readonly minimum: 1;
        readonly type: "uint64";
    }, {
        readonly description: "redacted quota change summary";
        readonly json: "semantic_diff";
        readonly maximum_length: 1024;
        readonly minimum_length: 1;
        readonly type: "string";
    }];
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 1024;
    readonly max_response_bytes: 1024;
    readonly method: "POST";
    readonly path: "/v1/tenant-lifecycle:transition";
    readonly request: "TenantLifecycleTransitionRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "tenant";
        readonly number: 1;
        readonly proto: "tenant";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "target";
        readonly number: 2;
        readonly proto: "target";
        readonly type: "TenantLifecycleTarget";
    }, {
        readonly deprecated: false;
        readonly json: "expected_generation";
        readonly number: 3;
        readonly proto: "expected_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "idempotency_key";
        readonly number: 4;
        readonly proto: "idempotency_key";
        readonly type: "string";
    }];
    readonly response: "TenantLifecycleTransitionResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "tenant";
        readonly number: 1;
        readonly proto: "tenant";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "from";
        readonly number: 2;
        readonly proto: "from";
        readonly type: "TenantLifecycleTarget";
    }, {
        readonly deprecated: false;
        readonly json: "to";
        readonly number: 3;
        readonly proto: "to";
        readonly type: "TenantLifecycleTarget";
    }, {
        readonly deprecated: false;
        readonly json: "lifecycle_generation";
        readonly number: 4;
        readonly proto: "lifecycle_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "audit_position";
        readonly number: 5;
        readonly proto: "audit_position";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "audit_ingest_time_unix_seconds";
        readonly number: 6;
        readonly proto: "audit_ingest_time_unix_seconds";
        readonly type: "uint64";
    }];
    readonly responses: {
        readonly "200": "TenantLifecycleTransitionResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "404": "tenant_unavailable";
        readonly "409": readonly ["stale_generation", "idempotency_conflict", "invalid_transition", "purge_completion_unavailable"];
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.TenantLifecycleService/Transition";
    readonly stale_generation_response_fields: readonly [{
        readonly description: "current lifecycle generation";
        readonly json: "lifecycle_generation";
        readonly minimum: 1;
        readonly type: "uint64";
    }, {
        readonly description: "redacted lifecycle change summary";
        readonly json: "semantic_diff";
        readonly maximum_length: 1024;
        readonly minimum_length: 1;
        readonly type: "string";
    }];
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 1024;
    readonly max_response_bytes: 1024;
    readonly method: "POST";
    readonly path: "/v1/tenant-aliases:bind";
    readonly request: "TenantAliasBindRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "tenant";
        readonly number: 1;
        readonly proto: "tenant";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "external_alias";
        readonly number: 2;
        readonly proto: "external_alias";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "expected_generation";
        readonly number: 3;
        readonly proto: "expected_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "idempotency_key";
        readonly number: 4;
        readonly proto: "idempotency_key";
        readonly type: "string";
    }];
    readonly response: "TenantAliasBindResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "tenant";
        readonly number: 1;
        readonly proto: "tenant";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "alias_generation";
        readonly number: 2;
        readonly proto: "alias_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "audit_position";
        readonly number: 3;
        readonly proto: "audit_position";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "audit_ingest_time_unix_seconds";
        readonly number: 4;
        readonly proto: "audit_ingest_time_unix_seconds";
        readonly type: "uint64";
    }];
    readonly responses: {
        readonly "200": "TenantAliasBindResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "404": "tenant_unavailable";
        readonly "409": readonly ["stale_generation", "idempotency_conflict", "alias_already_bound", "alias_conflict"];
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.TenantAliasService/Bind";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 2048;
    readonly max_response_bytes: 65536;
    readonly method: "POST";
    readonly path: "/v1/tenants:create";
    readonly request: "TenantCreateRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "tenant";
        readonly number: 1;
        readonly proto: "tenant";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "slug";
        readonly number: 2;
        readonly proto: "slug";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "display_name";
        readonly number: 3;
        readonly proto: "display_name";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "retention_seconds";
        readonly number: 4;
        readonly proto: "retention_seconds";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "weight";
        readonly number: 5;
        readonly proto: "weight";
        readonly type: "uint32";
    }, {
        readonly deprecated: false;
        readonly json: "memory_bytes";
        readonly number: 6;
        readonly proto: "memory_bytes";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "queue_slots";
        readonly number: 7;
        readonly proto: "queue_slots";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "task_slots";
        readonly number: 8;
        readonly proto: "task_slots";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "buffer_cache_bytes";
        readonly number: 9;
        readonly proto: "buffer_cache_bytes";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "batch_items";
        readonly number: 10;
        readonly proto: "batch_items";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "lease_slots";
        readonly number: 11;
        readonly proto: "lease_slots";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "retry_slots";
        readonly number: 12;
        readonly proto: "retry_slots";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "io_permits";
        readonly number: 13;
        readonly proto: "io_permits";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "cpu_work_units";
        readonly number: 14;
        readonly proto: "cpu_work_units";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "file_descriptors";
        readonly number: 15;
        readonly proto: "file_descriptors";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "disk_headroom_bytes";
        readonly number: 16;
        readonly proto: "disk_headroom_bytes";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "idempotency_key";
        readonly number: 17;
        readonly proto: "idempotency_key";
        readonly type: "string";
    }];
    readonly response: "TenantCreateResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "tenant";
        readonly number: 1;
        readonly proto: "tenant";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "resource_generation";
        readonly number: 2;
        readonly proto: "resource_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "audit_position";
        readonly number: 3;
        readonly proto: "audit_position";
        readonly type: "uint64";
    }];
    readonly responses: {
        readonly "200": "TenantCreateResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "409": readonly ["tenant_conflict", "idempotency_conflict"];
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.TenantService/Create";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 2048;
    readonly max_response_bytes: 65536;
    readonly method: "POST";
    readonly path: "/v1/tenants:inspect";
    readonly request: "TenantInspectRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "tenant";
        readonly number: 1;
        readonly proto: "tenant";
        readonly type: "string";
    }];
    readonly response: "TenantInspectResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "tenant";
        readonly number: 1;
        readonly proto: "tenant";
        readonly type: "TenantDescriptor";
    }];
    readonly responses: {
        readonly "200": "TenantInspectResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "404": "tenant_unavailable";
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.TenantService/Inspect";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 2048;
    readonly max_response_bytes: 65536;
    readonly method: "POST";
    readonly path: "/v1/tenants:list";
    readonly request: "TenantListRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "continuation";
        readonly number: 1;
        readonly proto: "continuation";
        readonly type: "string";
    }];
    readonly response: "TenantListResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "tenants";
        readonly number: 1;
        readonly proto: "tenants";
        readonly repeated: true;
        readonly type: "TenantDescriptor";
    }, {
        readonly deprecated: false;
        readonly json: "continuation";
        readonly number: 2;
        readonly proto: "continuation";
        readonly type: "string";
    }];
    readonly responses: {
        readonly "200": "TenantListResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "409": "stale_continuation";
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.TenantService/List";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 2048;
    readonly max_response_bytes: 65536;
    readonly method: "POST";
    readonly path: "/v1/tenants:update-display-name";
    readonly request: "TenantDisplayNameUpdateRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "tenant";
        readonly number: 1;
        readonly proto: "tenant";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "expected_display_generation";
        readonly number: 2;
        readonly proto: "expected_display_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "display_name";
        readonly number: 3;
        readonly proto: "display_name";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "idempotency_key";
        readonly number: 4;
        readonly proto: "idempotency_key";
        readonly type: "string";
    }];
    readonly response: "TenantDisplayNameUpdateResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "tenant";
        readonly number: 1;
        readonly proto: "tenant";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "display_generation";
        readonly number: 2;
        readonly proto: "display_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "audit_position";
        readonly number: 3;
        readonly proto: "audit_position";
        readonly type: "uint64";
    }];
    readonly responses: {
        readonly "200": "TenantDisplayNameUpdateResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "409": readonly ["stale_display_generation", "idempotency_conflict"];
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.TenantService/UpdateDisplayName";
    readonly stale_generation_response_fields: readonly [{
        readonly description: "current display generation";
        readonly json: "display_generation";
        readonly minimum: 1;
        readonly type: "uint64";
    }, {
        readonly description: "redacted display-name change summary";
        readonly json: "semantic_diff";
        readonly maximum_length: 1024;
        readonly minimum_length: 1;
        readonly type: "string";
    }];
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer TenantAdministration";
    readonly availability: "available";
    readonly max_request_bytes: 2048;
    readonly max_response_bytes: 65536;
    readonly method: "POST";
    readonly path: "/v1/tenant-retention:preview";
    readonly request: "TenantRetentionPreviewRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "tenant";
        readonly number: 1;
        readonly proto: "tenant";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "proposed_retention_seconds";
        readonly number: 2;
        readonly proto: "proposed_retention_seconds";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "continuation";
        readonly number: 3;
        readonly proto: "continuation";
        readonly type: "string";
    }];
    readonly response: "TenantRetentionPreviewResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "tenant";
        readonly number: 1;
        readonly proto: "tenant";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "retention_generation";
        readonly number: 2;
        readonly proto: "retention_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "proposed_retention_seconds";
        readonly number: 3;
        readonly proto: "proposed_retention_seconds";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "catalog_identity";
        readonly number: 4;
        readonly proto: "catalog_identity";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "catalog_generation";
        readonly number: 5;
        readonly proto: "catalog_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "confirmation_digest";
        readonly number: 6;
        readonly proto: "confirmation_digest";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "scopes";
        readonly number: 7;
        readonly proto: "scopes";
        readonly repeated: true;
        readonly type: "TenantRetentionScopeImpact";
    }, {
        readonly deprecated: false;
        readonly json: "continuation";
        readonly number: 8;
        readonly proto: "continuation";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "confirmation_evaluated_at_unix_nanos";
        readonly number: 9;
        readonly proto: "confirmation_evaluated_at_unix_nanos";
        readonly type: "sint64";
    }];
    readonly responses: {
        readonly "200": "TenantRetentionPreviewResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "404": "tenant_unavailable";
        readonly "409": "stale_continuation";
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.TenantRetentionService/Preview";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer TenantAdministration";
    readonly availability: "available";
    readonly max_request_bytes: 2048;
    readonly max_response_bytes: 65536;
    readonly method: "POST";
    readonly path: "/v1/tenant-retention:update";
    readonly request: "TenantRetentionUpdateRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "tenant";
        readonly number: 1;
        readonly proto: "tenant";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "proposed_retention_seconds";
        readonly number: 2;
        readonly proto: "proposed_retention_seconds";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "expected_generation";
        readonly number: 3;
        readonly proto: "expected_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "confirmation_digest";
        readonly number: 4;
        readonly optional: true;
        readonly proto: "confirmation_digest";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "idempotency_key";
        readonly number: 5;
        readonly proto: "idempotency_key";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "confirmation_evaluated_at_unix_nanos";
        readonly number: 6;
        readonly optional: true;
        readonly proto: "confirmation_evaluated_at_unix_nanos";
        readonly type: "sint64";
    }];
    readonly response: "TenantRetentionUpdateResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "tenant";
        readonly number: 1;
        readonly proto: "tenant";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "retention_generation";
        readonly number: 2;
        readonly proto: "retention_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "audit_position";
        readonly number: 3;
        readonly proto: "audit_position";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "audit_ingest_time_unix_seconds";
        readonly number: 4;
        readonly proto: "audit_ingest_time_unix_seconds";
        readonly type: "uint64";
    }];
    readonly responses: {
        readonly "200": "TenantRetentionUpdateResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "404": "tenant_unavailable";
        readonly "409": readonly ["invalid_confirmation", "stale_generation", "idempotency_conflict"];
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.TenantRetentionService/Update";
    readonly stale_generation_response_fields: readonly [{
        readonly description: "current retention generation";
        readonly json: "retention_generation";
        readonly minimum: 1;
        readonly type: "uint64";
    }, {
        readonly description: "redacted retention change summary";
        readonly json: "semantic_diff";
        readonly maximum_length: 1024;
        readonly minimum_length: 1;
        readonly type: "string";
    }];
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 128;
    readonly max_response_bytes: 65536;
    readonly method: "POST";
    readonly path: "/v1/maintenance:status";
    readonly request: "MaintenanceStatusRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "cursor";
        readonly number: 1;
        readonly optional: true;
        readonly proto: "cursor";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "limit";
        readonly number: 2;
        readonly optional: true;
        readonly proto: "limit";
        readonly type: "uint32";
    }];
    readonly response: "MaintenanceStatusResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "tasks";
        readonly number: 1;
        readonly proto: "tasks";
        readonly repeated: true;
        readonly type: "MaintenanceTaskStatus";
    }, {
        readonly deprecated: false;
        readonly json: "queued";
        readonly number: 2;
        readonly proto: "queued";
        readonly type: "uint32";
    }, {
        readonly deprecated: false;
        readonly json: "running";
        readonly number: 3;
        readonly proto: "running";
        readonly type: "uint32";
    }, {
        readonly deprecated: false;
        readonly json: "deferred";
        readonly number: 4;
        readonly proto: "deferred";
        readonly type: "uint32";
    }, {
        readonly deprecated: false;
        readonly json: "terminal";
        readonly number: 5;
        readonly proto: "terminal";
        readonly type: "uint32";
    }, {
        readonly deprecated: false;
        readonly json: "returned";
        readonly number: 6;
        readonly proto: "returned";
        readonly type: "uint32";
    }, {
        readonly deprecated: false;
        readonly json: "total";
        readonly number: 7;
        readonly proto: "total";
        readonly type: "uint32";
    }, {
        readonly deprecated: false;
        readonly json: "next_cursor";
        readonly number: 8;
        readonly optional: true;
        readonly proto: "next_cursor";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "integrity_findings";
        readonly maximum_items: 64;
        readonly number: 9;
        readonly proto: "integrity_findings";
        readonly repeated: true;
        readonly type: "IntegrityQuarantineFinding";
    }];
    readonly responses: {
        readonly "200": "MaintenanceStatusResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.MaintenanceService/Status";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 128;
    readonly max_response_bytes: 2048;
    readonly method: "POST";
    readonly path: "/v1/maintenance:explain";
    readonly request: "MaintenanceExplainRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "identity";
        readonly number: 1;
        readonly proto: "identity";
        readonly type: "string";
    }];
    readonly response: "MaintenanceExplainResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "task";
        readonly number: 1;
        readonly proto: "task";
        readonly type: "MaintenanceTaskStatus";
    }];
    readonly responses: {
        readonly "200": "MaintenanceExplainResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "404": "task_unavailable";
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.MaintenanceService/Explain";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 256;
    readonly max_response_bytes: 2048;
    readonly method: "POST";
    readonly path: "/v1/maintenance:run";
    readonly request: "MaintenanceRunRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "class";
        readonly number: 1;
        readonly proto: "task_class";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "tenant";
        readonly number: 2;
        readonly proto: "tenant";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "signal";
        readonly number: 3;
        readonly proto: "signal";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "shard";
        readonly number: 4;
        readonly proto: "shard";
        readonly type: "uint32";
    }, {
        readonly deprecated: false;
        readonly json: "idempotency_key";
        readonly number: 5;
        readonly proto: "idempotency_key";
        readonly type: "string";
    }];
    readonly response: "MaintenanceRunResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "task";
        readonly number: 1;
        readonly proto: "task";
        readonly type: "MaintenanceTaskAcknowledgement";
    }, {
        readonly deprecated: false;
        readonly json: "resource_generation";
        readonly number: 2;
        readonly proto: "resource_generation";
        readonly type: "uint64";
    }];
    readonly responses: {
        readonly "200": "MaintenanceRunResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "404": "source_unavailable";
        readonly "409": "idempotency_conflict";
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.MaintenanceService/Run";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 192;
    readonly max_response_bytes: 2048;
    readonly method: "POST";
    readonly path: "/v1/maintenance:pause";
    readonly request: "MaintenancePauseRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "identity";
        readonly number: 1;
        readonly proto: "identity";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "resource_generation";
        readonly number: 2;
        readonly proto: "resource_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "duration_seconds";
        readonly number: 3;
        readonly proto: "duration_seconds";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "idempotency_key";
        readonly number: 4;
        readonly proto: "idempotency_key";
        readonly type: "string";
    }];
    readonly response: "MaintenanceControlResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "task";
        readonly number: 1;
        readonly proto: "task";
        readonly type: "MaintenanceTaskAcknowledgement";
    }, {
        readonly deprecated: false;
        readonly json: "audit_position";
        readonly number: 2;
        readonly proto: "audit_position";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "action";
        readonly number: 3;
        readonly proto: "action";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "resource_generation";
        readonly number: 4;
        readonly optional: true;
        readonly proto: "resource_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "pause_until_unix_seconds";
        readonly number: 5;
        readonly optional: true;
        readonly proto: "pause_until_unix_seconds";
        readonly type: "uint64";
    }];
    readonly responses: {
        readonly "200": "MaintenanceControlResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "404": "task_unavailable";
        readonly "409": readonly ["precondition_failed", "idempotency_conflict"];
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.MaintenanceService/Pause";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 192;
    readonly max_response_bytes: 2048;
    readonly method: "POST";
    readonly path: "/v1/maintenance:resume";
    readonly request: "MaintenanceResumeRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "identity";
        readonly number: 1;
        readonly proto: "identity";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "idempotency_key";
        readonly number: 2;
        readonly proto: "idempotency_key";
        readonly type: "string";
    }];
    readonly response: "MaintenanceControlResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "task";
        readonly number: 1;
        readonly proto: "task";
        readonly type: "MaintenanceTaskAcknowledgement";
    }, {
        readonly deprecated: false;
        readonly json: "audit_position";
        readonly number: 2;
        readonly proto: "audit_position";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "action";
        readonly number: 3;
        readonly proto: "action";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "resource_generation";
        readonly number: 4;
        readonly optional: true;
        readonly proto: "resource_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "pause_until_unix_seconds";
        readonly number: 5;
        readonly optional: true;
        readonly proto: "pause_until_unix_seconds";
        readonly type: "uint64";
    }];
    readonly responses: {
        readonly "200": "MaintenanceControlResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "404": "task_unavailable";
        readonly "409": readonly ["precondition_failed", "idempotency_conflict"];
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.MaintenanceService/Resume";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 266;
    readonly max_response_bytes: 2048;
    readonly method: "POST";
    readonly path: "/v1/maintenance:window";
    readonly request: "MaintenanceWindowRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "deferred_classes";
        readonly number: 1;
        readonly proto: "deferred_classes";
        readonly repeated: true;
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "expected_catalog_generation";
        readonly number: 2;
        readonly proto: "expected_catalog_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "duration_seconds";
        readonly number: 3;
        readonly proto: "duration_seconds";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "idempotency_key";
        readonly number: 4;
        readonly proto: "idempotency_key";
        readonly type: "string";
    }];
    readonly response: "MaintenanceWindowResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "deferred_classes";
        readonly number: 1;
        readonly proto: "deferred_classes";
        readonly repeated: true;
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "until_unix_seconds";
        readonly number: 2;
        readonly proto: "until_unix_seconds";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "catalog_generation";
        readonly number: 3;
        readonly proto: "catalog_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "audit_position";
        readonly number: 4;
        readonly proto: "audit_position";
        readonly type: "uint64";
    }];
    readonly responses: {
        readonly "200": "MaintenanceWindowResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "409": readonly ["precondition_failed", "idempotency_conflict"];
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.MaintenanceService/Window";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 512;
    readonly max_response_bytes: 65536;
    readonly method: "POST";
    readonly path: "/v1/maintenance:verify";
    readonly request: "OnlineVerificationRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "tenant";
        readonly number: 1;
        readonly proto: "tenant";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "signal";
        readonly number: 2;
        readonly proto: "signal";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "shard";
        readonly number: 3;
        readonly proto: "shard";
        readonly type: "uint32";
    }, {
        readonly deprecated: false;
        readonly json: "expected_catalog_generation";
        readonly number: 4;
        readonly optional: true;
        readonly proto: "expected_catalog_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "continuation";
        readonly number: 5;
        readonly optional: true;
        readonly proto: "continuation";
        readonly type: "string";
    }];
    readonly response: "OnlineVerificationReport";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "report_version";
        readonly number: 1;
        readonly proto: "report_version";
        readonly type: "uint32";
    }, {
        readonly deprecated: false;
        readonly json: "tenant";
        readonly number: 2;
        readonly proto: "tenant";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "signal";
        readonly number: 3;
        readonly proto: "signal";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "shard";
        readonly number: 4;
        readonly proto: "shard";
        readonly type: "uint32";
    }, {
        readonly deprecated: false;
        readonly json: "catalog_generation";
        readonly number: 5;
        readonly proto: "catalog_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "examined_segments";
        readonly number: 6;
        readonly proto: "examined_segments";
        readonly type: "uint32";
    }, {
        readonly deprecated: false;
        readonly json: "examined_bytes";
        readonly number: 7;
        readonly proto: "examined_bytes";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "omitted_segments";
        readonly number: 8;
        readonly proto: "omitted_segments";
        readonly type: "uint32";
    }, {
        readonly deprecated: false;
        readonly json: "outcome";
        readonly number: 9;
        readonly proto: "outcome";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "verification_complete";
        readonly number: 10;
        readonly proto: "verification_complete";
        readonly type: "bool";
    }, {
        readonly deprecated: false;
        readonly json: "continuation";
        readonly number: 11;
        readonly optional: true;
        readonly proto: "continuation";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "findings";
        readonly maximum_items: 64;
        readonly number: 12;
        readonly proto: "findings";
        readonly repeated: true;
        readonly type: "IntegrityQuarantineFinding";
    }, {
        readonly deprecated: false;
        readonly json: "report_checksum";
        readonly number: 13;
        readonly proto: "report_checksum";
        readonly type: "string";
    }];
    readonly responses: {
        readonly "200": "OnlineVerificationReport";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "404": "source_unavailable";
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.MaintenanceService/Verify";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer TenantAdministration";
    readonly max_request_bytes: 65536;
    readonly max_response_bytes: 1024;
    readonly method: "POST";
    readonly path: "/v1/policies:validate";
    readonly request: "PolicyPreviewRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "policy_json";
        readonly number: 1;
        readonly proto: "policy_json";
        readonly type: "string";
    }];
    readonly response: "PolicyValidateResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "policy_generation";
        readonly number: 1;
        readonly proto: "policy_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "policy_digest";
        readonly number: 2;
        readonly proto: "policy_digest";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "rule_count";
        readonly number: 3;
        readonly proto: "rule_count";
        readonly type: "uint32";
    }];
    readonly responses: {
        readonly "200": "PolicyValidateResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.PolicyService/Validate";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer TenantAdministration";
    readonly max_request_bytes: 65536;
    readonly max_response_bytes: 1024;
    readonly method: "POST";
    readonly path: "/v1/policies:test";
    readonly request: "PolicyTestRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "policy_json";
        readonly number: 1;
        readonly proto: "policy_json";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "candidate_json";
        readonly number: 2;
        readonly proto: "candidate_json";
        readonly type: "string";
    }];
    readonly response: "PolicyTestResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "policy_generation";
        readonly number: 1;
        readonly proto: "policy_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "policy_digest";
        readonly number: 2;
        readonly proto: "policy_digest";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "accepted";
        readonly number: 3;
        readonly proto: "accepted";
        readonly type: "bool";
    }, {
        readonly deprecated: false;
        readonly json: "applied_rule_count";
        readonly number: 4;
        readonly proto: "applied_rule_count";
        readonly type: "uint32";
    }];
    readonly responses: {
        readonly "200": "PolicyTestResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.PolicyService/Test";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer TenantAdministration";
    readonly max_request_bytes: 65536;
    readonly max_response_bytes: 8192;
    readonly method: "POST";
    readonly path: "/v1/policies:diff";
    readonly request: "PolicyDiffRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "before_policy_json";
        readonly number: 1;
        readonly proto: "before_policy_json";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "after_policy_json";
        readonly number: 2;
        readonly proto: "after_policy_json";
        readonly type: "string";
    }];
    readonly response: "PolicyDiffResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "before_policy_generation";
        readonly number: 1;
        readonly proto: "before_policy_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "before_policy_digest";
        readonly number: 2;
        readonly proto: "before_policy_digest";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "after_policy_generation";
        readonly number: 3;
        readonly proto: "after_policy_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "after_policy_digest";
        readonly number: 4;
        readonly proto: "after_policy_digest";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "semantic_changes";
        readonly number: 5;
        readonly proto: "semantic_changes";
        readonly repeated: true;
        readonly type: "string";
    }];
    readonly responses: {
        readonly "200": "PolicyDiffResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.PolicyService/Diff";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer TenantAdministration";
    readonly max_request_bytes: 65536;
    readonly max_response_bytes: 8192;
    readonly method: "POST";
    readonly path: "/v1/policies:explain";
    readonly request: "PolicyExplainRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "policy_json";
        readonly number: 1;
        readonly proto: "policy_json";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "candidate_json";
        readonly number: 2;
        readonly proto: "candidate_json";
        readonly type: "string";
    }];
    readonly response: "PolicyExplainResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "policy_generation";
        readonly number: 1;
        readonly proto: "policy_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "policy_digest";
        readonly number: 2;
        readonly proto: "policy_digest";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "outcome";
        readonly number: 3;
        readonly proto: "outcome";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "explanation";
        readonly number: 4;
        readonly proto: "explanation";
        readonly type: "string";
    }];
    readonly responses: {
        readonly "200": "PolicyExplainResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.PolicyService/Explain";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer TenantAdministration";
    readonly max_request_bytes: 65536;
    readonly max_response_bytes: 1024;
    readonly method: "POST";
    readonly path: "/v1/policies:activate";
    readonly request: "PolicyActivateRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "policy_json";
        readonly number: 1;
        readonly proto: "policy_json";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "expected_generation";
        readonly number: 2;
        readonly proto: "expected_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "idempotency_key";
        readonly number: 3;
        readonly proto: "idempotency_key";
        readonly type: "string";
    }];
    readonly response: "PolicyActivateResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "resource_generation";
        readonly number: 1;
        readonly proto: "resource_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "policy_digest";
        readonly number: 2;
        readonly proto: "policy_digest";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "audit_position";
        readonly number: 3;
        readonly proto: "audit_position";
        readonly type: "uint64";
    }];
    readonly responses: {
        readonly "200": "PolicyActivateResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "409": readonly ["stale_generation", "idempotency_conflict"];
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.PolicyService/Activate";
    readonly stale_generation_response_fields: readonly [{
        readonly description: "current policy generation";
        readonly json: "resource_generation";
        readonly minimum: 1;
        readonly type: "uint64";
    }, {
        readonly description: "redacted policy generation change";
        readonly json: "semantic_diff";
        readonly maximum_length: 1024;
        readonly minimum_length: 1;
        readonly type: "string";
    }];
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 768;
    readonly max_response_bytes: 65536;
    readonly method: "POST";
    readonly path: "/v1/maintenance:abandon-segment";
    readonly request: "SegmentAbandonmentRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "tenant";
        readonly number: 1;
        readonly proto: "tenant";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "signal";
        readonly number: 2;
        readonly proto: "signal";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "shard";
        readonly number: 3;
        readonly proto: "shard";
        readonly type: "uint32";
    }, {
        readonly deprecated: false;
        readonly json: "segment";
        readonly number: 4;
        readonly proto: "segment";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "expected_catalog_generation";
        readonly number: 5;
        readonly optional: true;
        readonly proto: "expected_catalog_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "confirmation";
        readonly number: 6;
        readonly optional: true;
        readonly proto: "confirmation";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "idempotency_key";
        readonly number: 7;
        readonly optional: true;
        readonly proto: "idempotency_key";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "accept_data_loss";
        readonly number: 8;
        readonly proto: "accept_data_loss";
        readonly type: "bool";
    }, {
        readonly deprecated: false;
        readonly json: "operation_id";
        readonly number: 9;
        readonly optional: true;
        readonly proto: "operation_id";
        readonly type: "string";
    }];
    readonly response: "SegmentAbandonmentResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "catalog_generation";
        readonly number: 1;
        readonly proto: "catalog_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "status";
        readonly number: 2;
        readonly proto: "status";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "irreversible_boundary";
        readonly number: 3;
        readonly proto: "irreversible_boundary";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "confirmation";
        readonly number: 4;
        readonly optional: true;
        readonly proto: "confirmation";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "operation_id";
        readonly number: 5;
        readonly optional: true;
        readonly proto: "operation_id";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "finding";
        readonly number: 6;
        readonly proto: "finding";
        readonly type: "IntegrityQuarantineFinding";
    }];
    readonly responses: {
        readonly "200": "SegmentAbandonmentResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "404": "source_unavailable";
        readonly "409": "precondition_failed or idempotency_conflict";
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.MaintenanceService/AbandonSegment";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 4096;
    readonly max_response_bytes: 4096;
    readonly method: "POST";
    readonly path: "/v1/key-provider-migrations:manage";
    readonly request: "ProviderMigrationRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "action";
        readonly number: 1;
        readonly proto: "action";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "expected_catalog_generation";
        readonly number: 2;
        readonly optional: true;
        readonly proto: "expected_catalog_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "idempotency_key";
        readonly number: 3;
        readonly optional: true;
        readonly proto: "idempotency_key";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "configuration_reference";
        readonly number: 4;
        readonly optional: true;
        readonly proto: "configuration_reference";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "operation_id";
        readonly number: 5;
        readonly optional: true;
        readonly proto: "operation_id";
        readonly type: "string";
    }];
    readonly response: "ProviderMigrationResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "catalog_generation";
        readonly number: 1;
        readonly proto: "catalog_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "root_phase";
        readonly number: 2;
        readonly proto: "root_phase";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "active_epoch";
        readonly number: 3;
        readonly proto: "active_epoch";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "successor_epoch";
        readonly number: 4;
        readonly optional: true;
        readonly proto: "successor_epoch";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "predecessor_epoch";
        readonly number: 5;
        readonly optional: true;
        readonly proto: "predecessor_epoch";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "operation";
        readonly number: 6;
        readonly optional: true;
        readonly proto: "operation";
        readonly type: "ProviderMigrationOperation";
    }, {
        readonly deprecated: false;
        readonly json: "active_provider";
        readonly number: 7;
        readonly proto: "active_provider";
        readonly type: "ProviderMigrationIdentity";
    }, {
        readonly deprecated: false;
        readonly json: "source_provider";
        readonly number: 8;
        readonly proto: "source_provider";
        readonly type: "ProviderMigrationIdentity";
    }, {
        readonly deprecated: false;
        readonly json: "target_provider";
        readonly number: 9;
        readonly optional: true;
        readonly proto: "target_provider";
        readonly type: "ProviderMigrationIdentity";
    }];
    readonly responses: {
        readonly "200": "ProviderMigrationResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "404": "source_unavailable";
        readonly "409": "stale_generation or precondition_failed or idempotency_conflict";
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.ProviderMigrationService/Manage";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 4096;
    readonly max_response_bytes: 4096;
    readonly method: "POST";
    readonly path: "/v1/repositories:manage";
    readonly request: "RepositoryRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "action";
        readonly number: 1;
        readonly proto: "action";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "expected_catalog_generation";
        readonly number: 2;
        readonly optional: true;
        readonly proto: "expected_catalog_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "idempotency_key";
        readonly number: 3;
        readonly optional: true;
        readonly proto: "idempotency_key";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "locator";
        readonly number: 4;
        readonly optional: true;
        readonly proto: "locator";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "repository_id";
        readonly number: 5;
        readonly optional: true;
        readonly proto: "repository_id";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "operation_id";
        readonly number: 6;
        readonly optional: true;
        readonly proto: "operation_id";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "aws_s3";
        readonly number: 7;
        readonly optional: true;
        readonly proto: "aws_s3";
        readonly type: "RepositoryAwsS3Target";
    }, {
        readonly deprecated: false;
        readonly json: "google_cloud_storage";
        readonly number: 8;
        readonly optional: true;
        readonly proto: "google_cloud_storage";
        readonly type: "RepositoryGoogleCloudStorageTarget";
    }, {
        readonly deprecated: false;
        readonly json: "azure_blob";
        readonly number: 9;
        readonly optional: true;
        readonly proto: "azure_blob";
        readonly type: "RepositoryAzureBlobTarget";
    }];
    readonly response: "RepositoryResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "catalog_generation";
        readonly number: 1;
        readonly proto: "catalog_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "operation";
        readonly number: 2;
        readonly optional: true;
        readonly proto: "operation";
        readonly type: "RepositoryOperation";
    }, {
        readonly deprecated: false;
        readonly json: "identity";
        readonly number: 3;
        readonly optional: true;
        readonly proto: "identity";
        readonly type: "RepositoryIdentity";
    }, {
        readonly deprecated: false;
        readonly json: "doctor";
        readonly number: 4;
        readonly optional: true;
        readonly proto: "doctor";
        readonly type: "RepositoryDoctorResult";
    }, {
        readonly deprecated: false;
        readonly json: "policy";
        readonly number: 5;
        readonly optional: true;
        readonly proto: "policy";
        readonly type: "RepositoryPolicyReceipt";
    }];
    readonly responses: {
        readonly "200": "RepositoryResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "404": "source_unavailable";
        readonly "409": "stale_generation or precondition_failed or idempotency_conflict";
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.RepositoryService/Manage";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 4096;
    readonly max_response_bytes: 4096;
    readonly method: "POST";
    readonly path: "/v1/backups:manage";
    readonly request: "BackupRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "action";
        readonly number: 1;
        readonly proto: "action";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "expected_catalog_generation";
        readonly number: 2;
        readonly optional: true;
        readonly proto: "expected_catalog_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "idempotency_key";
        readonly number: 3;
        readonly optional: true;
        readonly proto: "idempotency_key";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "locator";
        readonly number: 4;
        readonly optional: true;
        readonly proto: "locator";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "repository_id";
        readonly number: 5;
        readonly optional: true;
        readonly proto: "repository_id";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "operation_id";
        readonly number: 6;
        readonly optional: true;
        readonly proto: "operation_id";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "aws_s3";
        readonly number: 7;
        readonly optional: true;
        readonly proto: "aws_s3";
        readonly type: "RepositoryAwsS3Target";
    }, {
        readonly deprecated: false;
        readonly json: "google_cloud_storage";
        readonly number: 8;
        readonly optional: true;
        readonly proto: "google_cloud_storage";
        readonly type: "RepositoryGoogleCloudStorageTarget";
    }, {
        readonly deprecated: false;
        readonly json: "azure_blob";
        readonly number: 9;
        readonly optional: true;
        readonly proto: "azure_blob";
        readonly type: "RepositoryAzureBlobTarget";
    }, {
        readonly deprecated: false;
        readonly json: "retention_seconds";
        readonly number: 10;
        readonly optional: true;
        readonly proto: "retention_seconds";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "snapshot_id";
        readonly number: 11;
        readonly optional: true;
        readonly proto: "snapshot_id";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "expected_manifest_checksum";
        readonly number: 12;
        readonly optional: true;
        readonly proto: "expected_manifest_checksum";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "expected_operation_revision";
        readonly number: 13;
        readonly optional: true;
        readonly proto: "expected_operation_revision";
        readonly type: "uint64";
    }];
    readonly response: "BackupResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "operation";
        readonly number: 1;
        readonly proto: "operation";
        readonly type: "RepositoryOperation";
    }, {
        readonly deprecated: false;
        readonly json: "repository";
        readonly number: 2;
        readonly optional: true;
        readonly proto: "repository";
        readonly type: "RepositoryIdentity";
    }, {
        readonly deprecated: false;
        readonly json: "receipt";
        readonly number: 3;
        readonly optional: true;
        readonly proto: "receipt";
        readonly type: "BackupSnapshotReceipt";
    }, {
        readonly deprecated: false;
        readonly json: "kind";
        readonly number: 4;
        readonly proto: "kind";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "cleanup_pending";
        readonly number: 5;
        readonly proto: "cleanup_pending";
        readonly type: "bool";
    }, {
        readonly deprecated: false;
        readonly json: "retention_receipt";
        readonly number: 6;
        readonly optional: true;
        readonly proto: "retention_receipt";
        readonly type: "BackupRetentionReceipt";
    }, {
        readonly deprecated: false;
        readonly json: "operation_revision";
        readonly number: 7;
        readonly proto: "operation_revision";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "terminal_error_code";
        readonly number: 8;
        readonly optional: true;
        readonly proto: "terminal_error_code";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "verification_report";
        readonly number: 9;
        readonly optional: true;
        readonly proto: "verification_report";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "verification_report_checksum";
        readonly number: 10;
        readonly optional: true;
        readonly proto: "verification_report_checksum";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "restored_publication";
        readonly number: 11;
        readonly optional: true;
        readonly proto: "restored_publication";
        readonly type: "BackupRestoredPublication";
    }];
    readonly responses: {
        readonly "200": "BackupResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "404": "source_unavailable";
        readonly "409": "stale_generation or precondition_failed or idempotency_conflict";
        readonly "503": "administration_unavailable or capacity_unavailable";
    };
    readonly rpc: "positron.v1.BackupService/Manage";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 4096;
    readonly max_response_bytes: 65536;
    readonly method: "POST";
    readonly path: "/v1/backups:list";
    readonly request: "BackupListRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "repository_id";
        readonly number: 1;
        readonly proto: "repository_id";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "limit";
        readonly number: 2;
        readonly proto: "limit";
        readonly type: "uint32";
    }, {
        readonly deprecated: false;
        readonly json: "cursor";
        readonly number: 3;
        readonly optional: true;
        readonly proto: "cursor";
        readonly type: "string";
    }];
    readonly response: "BackupListResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "repository";
        readonly number: 1;
        readonly proto: "repository";
        readonly type: "RepositoryIdentity";
    }, {
        readonly deprecated: false;
        readonly json: "registry_generation_checksum";
        readonly number: 2;
        readonly optional: true;
        readonly proto: "registry_generation_checksum";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "entries";
        readonly number: 3;
        readonly proto: "entries";
        readonly repeated: true;
        readonly type: "BackupListEntry";
    }, {
        readonly deprecated: false;
        readonly json: "next_cursor";
        readonly number: 4;
        readonly optional: true;
        readonly proto: "next_cursor";
        readonly type: "string";
    }];
    readonly responses: {
        readonly "200": "BackupListResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "404": "source_unavailable";
        readonly "409": "precondition_failed";
        readonly "503": "administration_unavailable or capacity_unavailable";
    };
    readonly rpc: "positron.v1.BackupService/List";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 4096;
    readonly max_response_bytes: 4096;
    readonly method: "POST";
    readonly path: "/v1/tenant-purges:manage";
    readonly request: "TenantPurgeRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "action";
        readonly number: 1;
        readonly proto: "action";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "tenant_id";
        readonly number: 2;
        readonly optional: true;
        readonly proto: "tenant_id";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "confirmation_slug";
        readonly number: 3;
        readonly optional: true;
        readonly proto: "confirmation_slug";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "expected_catalog_generation";
        readonly number: 4;
        readonly optional: true;
        readonly proto: "expected_catalog_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "expected_lifecycle_generation";
        readonly number: 5;
        readonly optional: true;
        readonly proto: "expected_lifecycle_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "idempotency_key";
        readonly number: 6;
        readonly optional: true;
        readonly proto: "idempotency_key";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "operation_id";
        readonly number: 7;
        readonly optional: true;
        readonly proto: "operation_id";
        readonly type: "string";
    }];
    readonly response: "TenantPurgeResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "catalog_generation";
        readonly number: 1;
        readonly proto: "catalog_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "operation";
        readonly number: 2;
        readonly optional: true;
        readonly proto: "operation";
        readonly type: "ProviderMigrationOperation";
    }, {
        readonly deprecated: false;
        readonly json: "managed_scope";
        readonly number: 3;
        readonly proto: "managed_scope";
        readonly type: "string";
    }];
    readonly responses: {
        readonly "200": "TenantPurgeResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "404": "source_unavailable";
        readonly "409": "stale_generation or precondition_failed or idempotency_conflict";
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.TenantPurgeService/Manage";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer SystemAdministration";
    readonly max_request_bytes: 4096;
    readonly max_response_bytes: 4096;
    readonly method: "POST";
    readonly path: "/v1/upgrades:manage";
    readonly request: "UpgradeRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "action";
        readonly number: 1;
        readonly proto: "action";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "candidate_manifest";
        readonly number: 2;
        readonly optional: true;
        readonly proto: "candidate_manifest";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "repository_id";
        readonly number: 3;
        readonly optional: true;
        readonly proto: "repository_id";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "retention_seconds";
        readonly number: 4;
        readonly optional: true;
        readonly proto: "retention_seconds";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "expected_catalog_generation";
        readonly number: 5;
        readonly optional: true;
        readonly proto: "expected_catalog_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "idempotency_key";
        readonly number: 6;
        readonly optional: true;
        readonly proto: "idempotency_key";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "operation_id";
        readonly number: 7;
        readonly optional: true;
        readonly proto: "operation_id";
        readonly type: "string";
    }];
    readonly response: "UpgradeResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "catalog_generation";
        readonly number: 1;
        readonly proto: "catalog_generation";
        readonly type: "uint64";
    }, {
        readonly deprecated: false;
        readonly json: "operation";
        readonly number: 2;
        readonly optional: true;
        readonly proto: "operation";
        readonly type: "UpgradeOperation";
    }, {
        readonly deprecated: false;
        readonly json: "details";
        readonly number: 3;
        readonly optional: true;
        readonly proto: "details";
        readonly type: "UpgradeDetails";
    }];
    readonly responses: {
        readonly "200": "UpgradeResponse";
        readonly "400": "invalid_request";
        readonly "401": "authentication_rejected";
        readonly "404": "source_unavailable";
        readonly "409": "stale_generation or precondition_failed or idempotency_conflict";
        readonly "503": "administration_unavailable";
    };
    readonly rpc: "positron.v1.UpgradeService/Manage";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer Query";
    readonly max_request_bytes: 8192;
    readonly max_response_bytes: 262144;
    readonly method: "POST";
    readonly path: "/v1/logs:query";
    readonly request: "LogQueryRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "pipeline";
        readonly number: 1;
        readonly proto: "pipeline";
        readonly type: "string";
    }, {
        readonly deprecated: false;
        readonly json: "budget";
        readonly number: 2;
        readonly proto: "budget";
        readonly type: "LogQueryBudget";
    }];
    readonly response: "LogQueryResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "events";
        readonly number: 1;
        readonly proto: "events";
        readonly repeated: true;
        readonly type: "LogQueryEvent";
    }];
    readonly rpc: "positron.v1.LogQueryService/Execute";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer Query";
    readonly max_request_bytes: 16384;
    readonly max_response_bytes: 262144;
    readonly method: "POST";
    readonly path: "/v1/logs:session";
    readonly request: "LogQuerySessionRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "execute";
        readonly number: 1;
        readonly optional: true;
        readonly proto: "execute";
        readonly type: "LogQueryRequest";
    }, {
        readonly deprecated: false;
        readonly json: "resume";
        readonly number: 2;
        readonly optional: true;
        readonly proto: "resume";
        readonly type: "bytes";
    }, {
        readonly deprecated: false;
        readonly json: "tail";
        readonly number: 4;
        readonly optional: true;
        readonly proto: "tail";
        readonly type: "LogQueryTailRequest";
    }, {
        readonly deprecated: false;
        readonly json: "batchLimit";
        readonly number: 3;
        readonly proto: "batch_limit";
        readonly type: "uint32";
    }];
    readonly response: "LogQueryResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "events";
        readonly number: 1;
        readonly proto: "events";
        readonly repeated: true;
        readonly type: "LogQueryEvent";
    }];
    readonly rpc: "positron.v1.LogQueryService/Session";
    readonly unknown_fields: "reject";
}, {
    readonly authentication: "Bearer Query";
    readonly max_request_bytes: 16384;
    readonly max_response_bytes: 1024;
    readonly method: "POST";
    readonly path: "/v1/logs:cancel";
    readonly request: "LogQueryCancelRequest";
    readonly request_fields: readonly [{
        readonly deprecated: false;
        readonly json: "query";
        readonly number: 1;
        readonly optional: true;
        readonly proto: "query";
        readonly type: "bytes";
    }, {
        readonly deprecated: false;
        readonly json: "tail";
        readonly number: 2;
        readonly optional: true;
        readonly proto: "tail";
        readonly type: "bytes";
    }];
    readonly response: "LogQueryCancelResponse";
    readonly response_fields: readonly [{
        readonly deprecated: false;
        readonly json: "cancelled";
        readonly number: 1;
        readonly proto: "cancelled";
        readonly type: "bool";
    }];
    readonly rpc: "positron.v1.LogQueryService/Cancel";
    readonly unknown_fields: "reject";
}];
export declare const queryErrors: readonly [{
    readonly error: {
        readonly code: "PUBLIC_ERROR_CODE_MALFORMED_REQUEST";
        readonly completionState: "COMPLETION_STATE_REJECTED";
        readonly retryClass: "RETRY_CLASS_AFTER_INPUT_CORRECTION";
        readonly safeDetail: "SAFE_DETAIL_REQUEST_MALFORMED";
        readonly source: "FAILURE_SOURCE_HTTP_DECODE";
    };
    readonly failure: "InvalidRequest";
    readonly status: 400;
}, {
    readonly error: {
        readonly code: "PUBLIC_ERROR_CODE_REQUEST_TOO_LARGE";
        readonly completionState: "COMPLETION_STATE_REJECTED";
        readonly retryClass: "RETRY_CLASS_AFTER_INPUT_CORRECTION";
        readonly safeDetail: "SAFE_DETAIL_REQUEST_LIMIT_EXCEEDED";
        readonly source: "FAILURE_SOURCE_HTTP_DECODE";
    };
    readonly failure: "InvalidRequest";
    readonly status: 413;
}, {
    readonly error: {
        readonly code: "PUBLIC_ERROR_CODE_AUTHENTICATION_REJECTED";
        readonly completionState: "COMPLETION_STATE_REJECTED";
        readonly retryClass: "RETRY_CLASS_AFTER_INPUT_CORRECTION";
        readonly safeDetail: "SAFE_DETAIL_AUTHENTICATION_REJECTED";
        readonly source: "FAILURE_SOURCE_QUERY_EXECUTION";
    };
    readonly failure: "AuthenticationRejected";
    readonly status: 401;
}, {
    readonly error: {
        readonly code: "PUBLIC_ERROR_CODE_CAPACITY_UNAVAILABLE";
        readonly completionState: "COMPLETION_STATE_REJECTED";
        readonly retryClass: "RETRY_CLASS_AFTER_BACKOFF";
        readonly safeDetail: "SAFE_DETAIL_CAPACITY_UNAVAILABLE";
        readonly source: "FAILURE_SOURCE_QUERY_EXECUTION";
    };
    readonly failure: "CapacityUnavailable";
    readonly status: 429;
}, {
    readonly error: {
        readonly code: "PUBLIC_ERROR_CODE_QUERY_UNAVAILABLE";
        readonly completionState: "COMPLETION_STATE_REJECTED";
        readonly retryClass: "RETRY_CLASS_AFTER_BACKOFF";
        readonly safeDetail: "SAFE_DETAIL_QUERY_UNAVAILABLE";
        readonly source: "FAILURE_SOURCE_QUERY_EXECUTION";
    };
    readonly failure: "QueryUnavailable";
    readonly status: 503;
}, {
    readonly error: {
        readonly code: "PUBLIC_ERROR_CODE_SNAPSHOT_EXPIRED";
        readonly completionState: "COMPLETION_STATE_REJECTED";
        readonly retryClass: "RETRY_CLASS_NEVER";
        readonly safeDetail: "SAFE_DETAIL_SNAPSHOT_EXPIRED";
        readonly source: "FAILURE_SOURCE_QUERY_EXECUTION";
    };
    readonly failure: "SnapshotExpired";
    readonly status: 410;
}, {
    readonly error: {
        readonly code: "PUBLIC_ERROR_CODE_INVALID_CURSOR";
        readonly completionState: "COMPLETION_STATE_REJECTED";
        readonly retryClass: "RETRY_CLASS_AFTER_INPUT_CORRECTION";
        readonly safeDetail: "SAFE_DETAIL_INVALID_CURSOR";
        readonly source: "FAILURE_SOURCE_QUERY_EXECUTION";
    };
    readonly failure: "InvalidCursor";
    readonly status: 400;
}, {
    readonly error: {
        readonly code: "PUBLIC_ERROR_CODE_INVALID_BUDGET";
        readonly completionState: "COMPLETION_STATE_REJECTED";
        readonly retryClass: "RETRY_CLASS_AFTER_INPUT_CORRECTION";
        readonly safeDetail: "SAFE_DETAIL_INVALID_BUDGET";
        readonly source: "FAILURE_SOURCE_QUERY_EXECUTION";
    };
    readonly failure: "InvalidBudget";
    readonly status: 400;
}, {
    readonly error: {
        readonly code: "PUBLIC_ERROR_CODE_BUDGET_EXHAUSTED";
        readonly completionState: "COMPLETION_STATE_REJECTED";
        readonly retryClass: "RETRY_CLASS_AFTER_INPUT_CORRECTION";
        readonly safeDetail: "SAFE_DETAIL_BUDGET_EXHAUSTED";
        readonly source: "FAILURE_SOURCE_QUERY_EXECUTION";
    };
    readonly failure: "BudgetExhausted";
    readonly status: 422;
}, {
    readonly error: {
        readonly code: "PUBLIC_ERROR_CODE_AUTHORIZATION_CHANGED";
        readonly completionState: "COMPLETION_STATE_REJECTED";
        readonly retryClass: "RETRY_CLASS_AFTER_INPUT_CORRECTION";
        readonly safeDetail: "SAFE_DETAIL_AUTHORIZATION_CHANGED";
        readonly source: "FAILURE_SOURCE_QUERY_EXECUTION";
    };
    readonly failure: "AuthorizationChanged";
    readonly status: 403;
}, {
    readonly error: {
        readonly code: "PUBLIC_ERROR_CODE_CANCELLED";
        readonly completionState: "COMPLETION_STATE_REJECTED";
        readonly retryClass: "RETRY_CLASS_NEVER";
        readonly safeDetail: "SAFE_DETAIL_CANCELLED";
        readonly source: "FAILURE_SOURCE_QUERY_EXECUTION";
    };
    readonly failure: "Cancelled";
    readonly status: 409;
}, {
    readonly error: {
        readonly code: "PUBLIC_ERROR_CODE_UNSUPPORTED_QUERY";
        readonly completionState: "COMPLETION_STATE_REJECTED";
        readonly retryClass: "RETRY_CLASS_AFTER_INPUT_CORRECTION";
        readonly safeDetail: "SAFE_DETAIL_UNSUPPORTED_QUERY";
        readonly source: "FAILURE_SOURCE_QUERY_EXECUTION";
    };
    readonly failure: "UnsupportedQuery";
    readonly status: 400;
}, {
    readonly error: {
        readonly code: "PUBLIC_ERROR_CODE_IDEMPOTENCY_CONFLICT";
        readonly completionState: "COMPLETION_STATE_REJECTED";
        readonly retryClass: "RETRY_CLASS_AFTER_INPUT_CORRECTION";
        readonly safeDetail: "SAFE_DETAIL_IDEMPOTENCY_CONFLICT";
        readonly source: "FAILURE_SOURCE_QUERY_EXECUTION";
    };
    readonly failure: "IdempotencyConflict";
    readonly status: 409;
}, {
    readonly error: {
        readonly code: "PUBLIC_ERROR_CODE_STORE_UNAVAILABLE";
        readonly completionState: "COMPLETION_STATE_REJECTED";
        readonly retryClass: "RETRY_CLASS_AFTER_BACKOFF";
        readonly safeDetail: "SAFE_DETAIL_STORE_UNAVAILABLE";
        readonly source: "FAILURE_SOURCE_QUERY_EXECUTION";
    };
    readonly failure: "StoreUnavailable";
    readonly status: 503;
}, {
    readonly error: {
        readonly code: "PUBLIC_ERROR_CODE_INCOMPLETE_DATA";
        readonly completionState: "COMPLETION_STATE_REJECTED";
        readonly retryClass: "RETRY_CLASS_AFTER_BACKOFF";
        readonly safeDetail: "SAFE_DETAIL_INCOMPLETE_DATA";
        readonly source: "FAILURE_SOURCE_QUERY_EXECUTION";
    };
    readonly failure: "IncompleteData";
    readonly status: 503;
}, {
    readonly error: {
        readonly code: "PUBLIC_ERROR_CODE_MALFORMED_PERSISTENT_DATA";
        readonly completionState: "COMPLETION_STATE_REJECTED";
        readonly retryClass: "RETRY_CLASS_NEVER";
        readonly safeDetail: "SAFE_DETAIL_MALFORMED_PERSISTENT_DATA";
        readonly source: "FAILURE_SOURCE_QUERY_EXECUTION";
    };
    readonly failure: "MalformedPersistentData";
    readonly status: 500;
}, {
    readonly error: {
        readonly code: "PUBLIC_ERROR_CODE_INTERNAL";
        readonly completionState: "COMPLETION_STATE_REJECTED";
        readonly retryClass: "RETRY_CLASS_NEVER";
        readonly safeDetail: "SAFE_DETAIL_INTERNAL";
        readonly source: "FAILURE_SOURCE_QUERY_EXECUTION";
    };
    readonly failure: "Internal";
    readonly status: 500;
}];
