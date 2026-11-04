// Retry and completion policy is emitted by the canonical Rust error owner.
import { descriptor, queryErrors } from './contract.js';
import { object, WireError, parseWireJson } from './codec.js';
const enums = descriptor.enums;
function canonical(name, value) {
    const found = enums[name]?.find(item => item.name === value || item.number === value);
    if (!found?.name)
        throw new WireError();
    return found.name;
}
export class QueryError extends Error {
    failure;
    retryClass;
    completionState;
    constructor(failure, retryClass, completionState) {
        super('Positron query failed');
        this.failure = failure;
        this.retryClass = retryClass;
        this.completionState = completionState;
        this.name = 'QueryError';
    }
}
export function queryError(status, text, cancellation = false) {
    const transport = new QueryError('Transport', 'RETRY_CLASS_NEVER', 'COMPLETION_STATE_AMBIGUOUS');
    if (Buffer.byteLength(text) > 1024)
        return transport;
    try {
        const error = object(parseWireJson(text));
        const read = (snake, camel, type) => {
            if (Object.hasOwn(error, snake) && Object.hasOwn(error, camel))
                throw new WireError();
            return canonical(type, error[snake] ?? error[camel]);
        };
        const code = canonical('PublicErrorCode', error.code);
        const retry = read('retry_class', 'retryClass', 'RetryClass');
        const completion = read('completion_state', 'completionState', 'CompletionState');
        const source = canonical('FailureSource', error.source);
        const detail = read('safe_detail', 'safeDetail', 'SafeDetail');
        for (const policy of queryErrors) {
            const expected = policy.error;
            if (policy.status !== status || canonical('PublicErrorCode', expected.code) !== code || canonical('FailureSource', expected.source) !== source || canonical('SafeDetail', expected.safeDetail) !== detail)
                continue;
            if (cancellation && completion === 'COMPLETION_STATE_AMBIGUOUS' && retry === 'RETRY_CLASS_NEVER')
                return new QueryError(`AmbiguousCancellation(${policy.failure})`, retry, completion);
            if (canonical('RetryClass', expected.retryClass) === retry && canonical('CompletionState', expected.completionState) === completion)
                return new QueryError(policy.failure, retry, completion);
        }
    }
    catch {
        return transport;
    }
    return transport;
}
