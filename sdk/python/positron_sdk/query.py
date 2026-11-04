"""Bounded delivery helpers over generated canonical query messages."""
import base64
import hashlib
import json
import re
from .codec import CONTRACT, WireError, base64_value, decode, obj, require

ZERO = base64.b64encode(bytes(32)).decode()
VALUE_TYPES = ('native_value', 'unix_nanoseconds', 'optional_unix_nanoseconds', 'query_time', 'event_time', 'ingest_time', 'commit_position', 'record_ordinal', 'unsigned_integer', 'attribute_occurrence_set')

def items(value):
    if value is None:
        return []
    require(isinstance(value, list))
    return value

def uint(value=None):
    if value is None:
        return 0
    require(isinstance(value, str) and re.fullmatch(r'[0-9]+', value) is not None)
    result = int(value)
    require(result < 1 << 64)
    return result

def digest(value):
    require(len(base64.b64decode(base64_value(value, 32))) == 32)
    return value

def cursor(value):
    require(bool(base64_value(value, 8192)))
    return value

def budget(value, session):
    value = obj(value)
    limits = dict(scannedBytes=1 << 30, decodedRecords=1024, outputRows=128, outputBytes=16384, memoryBytes=1048576, cpuWorkUnits=1024, wallSeconds=3600 if session else 5, maximumTimeRangeNanoseconds=2678400000000000)
    for key, maximum in limits.items():
        require(0 < uint(value.get(key)) <= maximum)

def native(value, depth=0):
    require(depth <= 32)
    value = obj(value)
    require(len(value) == 1)
    if 'arrayValue' in value:
        for item in items(obj(value['arrayValue']).get('values')):
            native(item, depth + 1)
    if 'objectValue' in value:
        for item in items(obj(value['objectValue']).get('entries')):
            native(obj(item).get('value'), depth + 1)
    if 'markerValue' in value:
        marker = obj(value['markerValue'])
        require(marker.get('action') in ('removed', 'redacted') and marker.get('originalKind') in ('null', 'boolean', 'signed_integer', 'floating_point_bits', 'string', 'bytes', 'array', 'key_value_list', 'marker'))
    if 'truncatedValue' in value:
        truncated = obj(value['truncatedValue'])
        require(truncated.get('action') in ('truncated_bytes', 'truncated_elements'))
        native(truncated.get('value'), depth + 1)

def cell(value, column):
    value = obj(value)
    require(len(value) == 1)
    kind = column.get('valueType')
    if 'missing' in value:
        require(column.get('nullable') is True)
    elif 'nativeValue' in value:
        require(kind == 'native_value')
        native(value['nativeValue'])
    elif 'occurrences' in value:
        require(kind == 'attribute_occurrence_set')
        values = items(obj(value['occurrences']).get('values'))
        require(0 < len(values) <= 1024)
        for item in values:
            native(item)
    elif 'unsignedInteger' in value:
        require(kind in ('commit_position', 'unsigned_integer') or kind == 'record_ordinal' and uint(value['unsignedInteger']) <= 4294967295)
    elif 'timestamp' in value:
        time = obj(value['timestamp'])
        provenance = time.get('provenance')
        require((provenance in ('event', 'observed', 'ingest', 'kernel') and not time.get('quality') and 'unixNanoseconds' in time and 'sourceValue' not in time) or (not provenance and time.get('quality') in ('usable', 'missing', 'zero', 'outlier', 'contradictory')))
        require(kind == 'query_time' and provenance in ('event', 'observed', 'ingest') or kind == 'event_time' and not provenance or kind == 'ingest_time' and provenance == 'kernel' or kind in ('unix_nanoseconds', 'optional_unix_nanoseconds') and 'unixNanoseconds' in time)
    else:
        raise WireError()

def stop_reason(value):
    return any(item['number'] != 0 and item['name'] == 'LOG_QUERY_STOP_REASON_' + str(value).upper() for item in CONTRACT['descriptor']['enums']['LogQueryStopReason'])

def decode_query(text, mode='execute'):
    require(mode in ('execute', 'session', 'tail'))
    response = obj(decode('LogQueryResponse', text))
    events = items(response.get('events'))
    tail, session = mode == 'tail', mode != 'execute'
    require(2 <= len(events) <= (3 if tail else 130))
    header = obj(obj(events[0]).get('header'))
    columns = [obj(column) for column in items(header.get('columns'))]
    ordering = [obj(order) for order in items(header.get('ordering'))]
    require(0 < len(columns) <= 128 and 0 < len(ordering) <= 128)
    digest(obj(header.get('snapshot')).get('identity'))
    require(len(base64.b64decode(base64_value(obj(header.get('lease')).get('identity'), 16))) == 16 and uint(obj(header.get('lease')).get('expiryUnixSeconds')) > 0)
    budget(header.get('effectiveBudget'), session)
    if 'initialCursor' in header:
        cursor(header['initialCursor'])
    require(header.get('tailPhase') in ('live_commit_vector', 'historical_temporal_then_live_commit_vector') if tail else 'tailPhase' not in header)
    for column in columns:
        require(isinstance(column.get('name'), str) and 0 < len(column['name'].encode()) <= 4096 and column.get('valueType') in VALUE_TYPES)
    for order in ordering:
        require(isinstance(order.get('column'), str) and 0 < len(order['column'].encode()) <= 4096 and order.get('valueType') in VALUE_TYPES and order.get('direction') in ('ascending', 'descending'))
    batches = [obj(obj(event).get('batch')) for event in events[1:-1]]
    sequence = uint(batches[0].get('sequence')) if session and batches else 0
    previous = digest(batches[0].get('priorDigest')) if session and batches else ZERO
    rows = 0
    for batch in batches:
        records = items(batch.get('rows'))
        require(uint(batch.get('sequence')) == sequence and digest(batch.get('priorDigest')) == previous and bool(records))
        previous = digest(batch.get('digest'))
        sequence += 1
        require(sequence < 1 << 64)
        for row in records:
            cells = items(obj(row).get('cells'))
            require(len(cells) == len(columns))
            for value, column in zip(cells, columns):
                cell(value, column)
        rows += len(records)
        require(rows <= 128)
    terminal = obj(obj(events[-1]).get('terminal'))
    if terminal.get('state') == 'continued':
        require(not tail and 'stats' not in terminal and not terminal.get('reason'))
        cursor(terminal.get('continuationCursor'))
    else:
        require(terminal.get('state') in ('complete', 'incomplete'))
        stats = obj(terminal.get('stats'))
        prior_only = session and not batches and 'initialCursor' in header
        last_sequence = uint(stats['lastSequence']) if 'lastSequence' in stats else -1
        if prior_only:
            digest(stats.get('resultDigest'))
            require((uint(stats.get('records')) == 0) == ('lastSequence' not in stats))
        if tail and batches:
            require(digest(stats.get('resultDigest')) == digest(batches[0].get('priorDigest')) and last_sequence == uint(batches[0].get('sequence')) - 1)
        elif not prior_only:
            require(digest(stats.get('resultDigest')) == previous and last_sequence == sequence - 1)
        require(tail or (uint(stats.get('records')) >= rows if session else uint(stats.get('records')) == rows))
        budget(stats.get('cumulativeBudget'), session)
        if 'limitingBudget' in stats:
            require(stats['limitingBudget'] in ('scanned_bytes', 'decoded_records', 'output_rows', 'output_bytes', 'memory_bytes', 'cpu_work_units', 'wall_seconds', 'maximum_time_range_nanoseconds'))
        ranges = items(terminal.get('affectedRanges'))
        require(len(ranges) <= 1024)
        for affected in ranges:
            affected = obj(affected)
            require(affected.get('temporalAxis') in ('query_time', 'event_time', 'ingest_time'))
            require('earliestNanoseconds' not in affected and 'latestNanoseconds' not in affected or isinstance(affected.get('earliestNanoseconds'), str) and isinstance(affected.get('latestNanoseconds'), str) and int(affected['earliestNanoseconds']) <= int(affected['latestNanoseconds']))
        if 'continuationCursor' in terminal:
            require(tail)
            cursor(terminal['continuationCursor'])
        if terminal['state'] == 'complete':
            require(not tail and not terminal.get('reason') and not ranges)
        else:
            require(stop_reason(terminal.get('reason')) and (tail or terminal.get('reason') not in ('disconnected', 'consumer_lagged')))
    return response

def terminal_status(terminal):
    terminal = obj(terminal)
    state = terminal.get('state')
    if state == 'complete':
        require(not terminal.get('reason') and not terminal.get('continuationCursor') and not terminal.get('affectedRanges'))
        digest(obj(terminal.get('stats')).get('resultDigest'))
        return {'kind': 'complete'}
    if state == 'continued':
        require(not terminal.get('reason') and 'stats' not in terminal and not terminal.get('affectedRanges'))
        return {'kind': 'continued', 'cursor': cursor(terminal.get('continuationCursor'))}
    require(state == 'incomplete' and stop_reason(terminal.get('reason')))
    digest(obj(terminal.get('stats')).get('resultDigest'))
    result = {'kind': 'incomplete', 'reason': terminal['reason']}
    if 'continuationCursor' in terminal:
        result['cursor'] = cursor(terminal['continuationCursor'])
    return result

def fingerprint(name, value):
    def canonical(name, value):
        value = obj(value)
        result = []
        for field in CONTRACT['descriptor']['messages'][name]:
            key = field['json_name']
            if key not in value or name == 'LogQueryRow' and key == 'replayed':
                continue
            item = value[key]
            if not field['optional'] and field['oneof'] is None and item in ('', '0', 0, False, []):
                continue
            def convert(item):
                return canonical(field['type_name'].rsplit('.', 1)[-1], item) if field['type'] == 11 and field['type_name'] else item
            result.append([key, [convert(item) for item in items(item)] if field['repeated'] else convert(item)])
        return result
    return hashlib.sha256(json.dumps(canonical(name, value), separators=(',', ':'), ensure_ascii=False).encode()).hexdigest()

class BatchTracker:
    """Retain one receipt; expose acknowledgement only after caller consumption."""
    def __init__(self, mode='session'):
        require(mode in ('session', 'tail'))
        self.mode = mode
        self._snapshot = self._schema = self._last = None
        self._next = self._rows = 0
        self._digest = ZERO
        self._finished = self._live = False

    def filter(self, response):
        checked = decode_query(json.dumps(response), self.mode)
        events = checked['events']
        header = events[0]['header']
        snapshot = digest(header['snapshot']['identity'])
        require(self.mode == 'tail' or self._snapshot is None or self._snapshot == snapshot)
        schema = fingerprint('LogQueryHeader', {key: value for key, value in header.items() if key not in ('snapshot', 'lease', 'effectiveBudget', 'initialCursor', 'tailPhase')})
        require(self._schema is None or self._schema == schema)
        live = header.get('tailPhase') == 'live_commit_vector'
        require(not self._live or live)
        next_sequence, previous, rows, last = self._next, self._digest, self._rows, self._last
        batches = []
        for event in events:
            if 'batch' not in event:
                continue
            batch = event['batch']
            sequence, content, hash_value = uint(batch.get('sequence')), fingerprint('LogQueryBatch', batch), digest(batch.get('digest'))
            if last and sequence == last['sequence']:
                require(hash_value == last['digest'] and content == last['fingerprint'])
                continue
            require(not self._finished and sequence == next_sequence and digest(batch.get('priorDigest')) == previous)
            next_sequence += 1
            require(next_sequence < 1 << 64)
            count = len(items(batch.get('rows')))
            rows += count
            require(rows <= uint(header['effectiveBudget'].get('outputRows')))
            previous = hash_value
            last = dict(sequence=sequence, digest=hash_value, prior=digest(batch.get('priorDigest')), rows=count, fingerprint=content)
            batches.append(batch)
        terminal = events[-1]['terminal']
        if terminal['state'] != 'continued':
            stats = terminal['stats']
            sequence = uint(stats['lastSequence']) if 'lastSequence' in stats else -1
            received = uint(stats.get('records')) == rows and sequence == next_sequence - 1 and digest(stats.get('resultDigest')) == previous
            pending = self.mode == 'tail' and last and uint(stats.get('records')) == rows - last['rows'] and sequence == last['sequence'] - 1 and digest(stats.get('resultDigest')) == last['prior']
            require(received or pending)
        self._snapshot, self._schema, self._next, self._digest, self._rows, self._last = snapshot, schema, next_sequence, previous, rows, last
        self._live |= live
        self._finished |= self.mode != 'tail' and terminal['state'] != 'continued'
        return batches

    def acknowledgement(self):
        return dict(sequence=str(self._last['sequence']), digest=self._last['digest']) if self._last else None

def validate_request(rpc, request):
    def query(value, session):
        value = obj(value)
        require(isinstance(value.get('pipeline'), str) and 0 < len(value['pipeline'].encode()) <= 4096)
        budget(value.get('budget'), session)
    if rpc.endswith('/Execute'):
        query(request, False)
    if rpc.endswith('/Cancel'):
        require(sum(key in request for key in ('query', 'tail')) == 1)
        cursor(request.get('query', request.get('tail')))
    if rpc.endswith('/Session'):
        require(type(request.get('batchLimit')) is int and 1 <= request['batchLimit'] <= 128)
        require(sum(key in request for key in ('execute', 'resume', 'tail')) == 1)
        if 'execute' in request:
            query(request['execute'], True)
        if 'resume' in request:
            cursor(request['resume'])
        if 'tail' in request:
            require(request['batchLimit'] == 1)
            tail = obj(request['tail'])
            query(tail.get('query'), True)
            if 'cursor' in tail:
                cursor(tail['cursor'])
                require('historicalRows' not in tail)
            if 'historicalRows' in tail:
                require(0 < uint(tail['historicalRows']) <= 128)
            if 'acknowledgement' in tail:
                require('cursor' in tail)
                digest(obj(tail['acknowledgement']).get('digest'))
