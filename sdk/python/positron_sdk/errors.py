"""Retry and completion policy is emitted by the canonical Rust error owner."""
from .codec import CONTRACT, WireError, obj, parse_json, require

class QueryError(Exception):
    def __init__(self, failure, retry_class, completion_state):
        super().__init__('Positron query failed')
        self.failure, self.retry_class, self.completion_state = failure, retry_class, completion_state

def canonical(name, value):
    for item in CONTRACT['descriptor']['enums'][name]:
        if value in (item['name'], item['number']):
            return item['name']
    raise WireError()

def query_error(status, text, cancellation=False):
    transport = QueryError('Transport', 'RETRY_CLASS_NEVER', 'COMPLETION_STATE_AMBIGUOUS')
    if len(text.encode()) > 1024:
        return transport
    try:
        error = obj(parse_json(text))
        def read(snake, camel, kind):
            require(not (snake in error and camel in error))
            return canonical(kind, error.get(snake, error.get(camel)))
        code = canonical('PublicErrorCode', error.get('code'))
        retry = read('retry_class', 'retryClass', 'RetryClass')
        completion = read('completion_state', 'completionState', 'CompletionState')
        source = canonical('FailureSource', error.get('source'))
        detail = read('safe_detail', 'safeDetail', 'SafeDetail')
        for policy in CONTRACT['query_errors']:
            expected = policy['error']
            if policy['status'] != status or canonical('PublicErrorCode', expected['code']) != code or canonical('FailureSource', expected['source']) != source or canonical('SafeDetail', expected['safeDetail']) != detail:
                continue
            if cancellation and completion == 'COMPLETION_STATE_AMBIGUOUS' and retry == 'RETRY_CLASS_NEVER':
                return QueryError('AmbiguousCancellation(' + policy['failure'] + ')', retry, completion)
            if canonical('RetryClass', expected['retryClass']) == retry and canonical('CompletionState', expected['completionState']) == completion:
                return QueryError(policy['failure'], retry, completion)
    except WireError:
        pass
    return transport
