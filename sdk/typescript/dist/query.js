import { descriptor } from './contract.js';
import { decode, object, base64, WireError } from './codec.js';
import { createHash } from 'node:crypto';
const zero = Buffer.alloc(32).toString('base64');
function require(condition) { if (!condition)
    throw new WireError(); }
function list(value) { require(value === undefined || Array.isArray(value)); return value ?? []; }
function uint(value) { if (value === undefined)
    return 0n; require(typeof value === 'string' && /^[0-9]+$/.test(value)); return BigInt(value); }
function digest(value) { const text = base64(value, 32); require(Buffer.byteLength(text, 'base64') === 32); return text; }
function cursor(value) { const text = base64(value, 8192); require(text.length > 0); return text; }
const valueTypes = ['native_value', 'unix_nanoseconds', 'optional_unix_nanoseconds', 'query_time', 'event_time', 'ingest_time', 'commit_position', 'record_ordinal', 'unsigned_integer', 'attribute_occurrence_set'];
function budget(value, session) {
    const input = object(value);
    for (const [name, maximum] of Object.entries({ scannedBytes: 1n << 30n, decodedRecords: 1024n, outputRows: 128n, outputBytes: 16384n, memoryBytes: 1048576n, cpuWorkUnits: 1024n, wallSeconds: session ? 3600n : 5n, maximumTimeRangeNanoseconds: 2678400000000000n }))
        require(uint(input[name]) > 0n && uint(input[name]) <= maximum);
}
function native(value, depth = 0) {
    require(depth <= 32);
    const input = object(value);
    require(Object.keys(input).length === 1);
    if (input.arrayValue !== undefined)
        for (const value of list(object(input.arrayValue).values))
            native(value, depth + 1);
    if (input.objectValue !== undefined)
        for (const entry of list(object(input.objectValue).entries))
            native(object(entry).value, depth + 1);
    if (input.markerValue !== undefined) {
        const marker = object(input.markerValue);
        require(['removed', 'redacted'].includes(String(marker.action)) && ['null', 'boolean', 'signed_integer', 'floating_point_bits', 'string', 'bytes', 'array', 'key_value_list', 'marker'].includes(String(marker.originalKind)));
    }
    if (input.truncatedValue !== undefined) {
        const truncated = object(input.truncatedValue);
        require(['truncated_bytes', 'truncated_elements'].includes(String(truncated.action)));
        native(truncated.value, depth + 1);
    }
}
function cell(value, column) {
    const input = object(value);
    require(Object.keys(input).length === 1);
    const kind = column.valueType;
    if (input.missing !== undefined)
        require(column.nullable === true);
    else if (input.nativeValue !== undefined) {
        require(kind === 'native_value');
        native(input.nativeValue);
    }
    else if (input.occurrences !== undefined) {
        require(kind === 'attribute_occurrence_set');
        const values = list(object(input.occurrences).values);
        require(values.length > 0 && values.length <= 1024);
        for (const value of values)
            native(value);
    }
    else if (input.unsignedInteger !== undefined)
        require(kind === 'commit_position' || kind === 'unsigned_integer' || kind === 'record_ordinal' && uint(input.unsignedInteger) <= 4294967295n);
    else if (input.timestamp !== undefined) {
        const time = object(input.timestamp);
        require((['event', 'observed', 'ingest', 'kernel'].includes(String(time.provenance)) && !time.quality && time.unixNanoseconds !== undefined && time.sourceValue === undefined) || (!time.provenance && ['usable', 'missing', 'zero', 'outlier', 'contradictory'].includes(String(time.quality))));
        require(kind === 'query_time' && ['event', 'observed', 'ingest'].includes(String(time.provenance)) || kind === 'event_time' && !time.provenance || kind === 'ingest_time' && time.provenance === 'kernel' || ['unix_nanoseconds', 'optional_unix_nanoseconds'].includes(String(kind)) && time.unixNanoseconds !== undefined);
    }
    else
        throw new WireError();
}
export function decodeQuery(text, mode = 'execute') {
    const response = object(decode('LogQueryResponse', text));
    const events = list(response.events);
    const tail = mode === 'tail';
    const session = mode !== 'execute';
    require(events.length >= 2 && events.length <= (tail ? 3 : 130));
    const header = object(object(events[0]).header);
    const columns = list(header.columns).map(object);
    const ordering = list(header.ordering).map(object);
    require(columns.length > 0 && columns.length <= 128 && ordering.length > 0 && ordering.length <= 128);
    digest(object(header.snapshot).identity);
    require(Buffer.byteLength(base64(object(header.lease).identity, 16), 'base64') === 16 && uint(object(header.lease).expiryUnixSeconds) > 0n);
    budget(header.effectiveBudget, session);
    if (header.initialCursor !== undefined)
        cursor(header.initialCursor);
    require(tail ? ['live_commit_vector', 'historical_temporal_then_live_commit_vector'].includes(String(header.tailPhase)) : header.tailPhase === undefined);
    for (const column of columns)
        require(typeof column.name === 'string' && column.name.length > 0 && Buffer.byteLength(column.name) <= 4096 && valueTypes.includes(String(column.valueType)));
    for (const order of ordering)
        require(typeof order.column === 'string' && order.column.length > 0 && Buffer.byteLength(order.column) <= 4096 && valueTypes.includes(String(order.valueType)) && ['ascending', 'descending'].includes(String(order.direction)));
    const batches = events.slice(1, -1).map(event => object(object(event).batch));
    let sequence = session && batches[0] ? uint(batches[0].sequence) : 0n;
    let previous = session && batches[0] ? digest(batches[0].priorDigest) : zero;
    let rows = 0n;
    for (const batch of batches) {
        const records = list(batch.rows);
        require(uint(batch.sequence) === sequence && digest(batch.priorDigest) === previous && records.length > 0);
        previous = digest(batch.digest);
        sequence++;
        require(sequence <= 18446744073709551615n);
        for (const row of records) {
            const cells = list(object(row).cells);
            require(cells.length === columns.length);
            cells.forEach((value, index) => { const column = columns[index]; require(column); cell(value, column); });
        }
        rows += BigInt(records.length);
        require(rows <= 128n);
    }
    const terminal = object(object(events.at(-1)).terminal);
    if (terminal.state === 'continued') {
        require(!tail && terminal.stats === undefined && !terminal.reason);
        cursor(terminal.continuationCursor);
    }
    else {
        require(terminal.state === 'complete' || terminal.state === 'incomplete');
        const stats = object(terminal.stats);
        const priorOnly = session && batches.length === 0 && header.initialCursor !== undefined;
        if (priorOnly) {
            digest(stats.resultDigest);
            require((uint(stats.records) === 0n) === (stats.lastSequence === undefined));
        }
        const first = batches[0];
        if (tail && first)
            require(digest(stats.resultDigest) === digest(first.priorDigest) && (stats.lastSequence === undefined ? -1n : uint(stats.lastSequence)) === uint(first.sequence) - 1n);
        else if (!priorOnly)
            require(digest(stats.resultDigest) === previous && (stats.lastSequence === undefined ? -1n : uint(stats.lastSequence)) === sequence - 1n);
        require(tail || (session ? uint(stats.records) >= rows : uint(stats.records) === rows));
        budget(stats.cumulativeBudget, session);
        if (stats.limitingBudget !== undefined)
            require(['scanned_bytes', 'decoded_records', 'output_rows', 'output_bytes', 'memory_bytes', 'cpu_work_units', 'wall_seconds', 'maximum_time_range_nanoseconds'].includes(String(stats.limitingBudget)));
        const ranges = list(terminal.affectedRanges);
        require(ranges.length <= 1024);
        for (const value of ranges) {
            const range = object(value);
            require(['query_time', 'event_time', 'ingest_time'].includes(String(range.temporalAxis)));
            require(range.earliestNanoseconds === undefined && range.latestNanoseconds === undefined || typeof range.earliestNanoseconds === 'string' && typeof range.latestNanoseconds === 'string' && BigInt(range.earliestNanoseconds) <= BigInt(range.latestNanoseconds));
        }
        if (terminal.continuationCursor !== undefined) {
            require(tail);
            cursor(terminal.continuationCursor);
        }
        if (terminal.state === 'complete')
            require(!tail && !terminal.reason && ranges.length === 0);
        else
            require(descriptor.enums.LogQueryStopReason.some(reason => reason.name === `LOG_QUERY_STOP_REASON_${String(terminal.reason).toUpperCase()}` && reason.number !== 0 && (tail || !['disconnected', 'consumer_lagged'].includes(String(terminal.reason)))));
    }
    return response;
}
export function terminalStatus(terminal) {
    if (terminal.state === 'complete' && !terminal.reason && !terminal.continuationCursor && !terminal.affectedRanges?.length) {
        digest(terminal.stats?.resultDigest);
        return { kind: 'complete' };
    }
    if (terminal.state === 'continued' && !terminal.reason && !terminal.stats && !terminal.affectedRanges?.length)
        return { kind: 'continued', cursor: cursor(terminal.continuationCursor) };
    if (terminal.state === 'incomplete' && descriptor.enums.LogQueryStopReason.some(reason => reason.number !== 0 && reason.name === `LOG_QUERY_STOP_REASON_${terminal.reason?.toUpperCase()}`)) {
        digest(terminal.stats?.resultDigest);
        return terminal.continuationCursor === undefined ? { kind: 'incomplete', reason: terminal.reason ?? '' } : { kind: 'incomplete', reason: terminal.reason ?? '', cursor: cursor(terminal.continuationCursor) };
    }
    throw new WireError();
}
function fingerprint(name, value) {
    function canonical(name, value) {
        const input = object(value);
        const metadata = descriptor.messages;
        const fields = metadata[name];
        require(fields);
        const result = [];
        for (const field of fields) {
            if (!field.json_name)
                continue;
            const value = input[field.json_name];
            if (value === undefined || field.json_name === 'replayed' && name === 'LogQueryRow')
                continue;
            if (!field.optional && field.oneof === null && (value === '' || value === '0' || value === 0 || value === false || Array.isArray(value) && value.length === 0))
                continue;
            const convert = (value) => field.type === 11 && field.type_name ? canonical(field.type_name.split('.').at(-1) ?? '', value) : value;
            result.push([field.json_name, field.repeated ? list(value).map(convert) : convert(value)]);
        }
        return result;
    }
    return createHash('sha256').update(JSON.stringify(canonical(name, value))).digest('hex');
}
export class BatchTracker {
    mode;
    #snapshot;
    #schema;
    #next = 0n;
    #digest = zero;
    #rows = 0n;
    #last;
    #finished = false;
    #live = false;
    constructor(mode = 'session') {
        this.mode = mode;
    }
    filter(response) {
        const checked = decodeQuery(JSON.stringify(response), this.mode);
        const events = checked.events ?? [];
        const header = events[0]?.header;
        require(header);
        const snapshot = digest(header.snapshot?.identity);
        require(this.mode === 'tail' || this.#snapshot === undefined || this.#snapshot === snapshot);
        const schema = fingerprint('LogQueryHeader', { ...header, snapshot: undefined, lease: undefined, effectiveBudget: undefined, initialCursor: undefined, tailPhase: undefined });
        require(this.#schema === undefined || this.#schema === schema);
        const live = header.tailPhase === 'live_commit_vector';
        require(!this.#live || live);
        let next = this.#next, previous = this.#digest, rows = this.#rows, last = this.#last;
        const batches = [];
        for (const event of events) {
            const batch = event.batch;
            if (!batch)
                continue;
            const sequence = uint(batch.sequence), content = fingerprint('LogQueryBatch', batch), hash = digest(batch.digest);
            if (last && sequence === last.sequence) {
                require(hash === last.digest && content === last.fingerprint);
                continue;
            }
            require(!this.#finished && sequence === next && digest(batch.priorDigest) === previous);
            next++;
            require(next <= 18446744073709551615n);
            const count = BigInt(batch.rows?.length ?? 0);
            rows += count;
            require(rows <= uint(header.effectiveBudget?.outputRows));
            previous = hash;
            last = { sequence, digest: hash, prior: digest(batch.priorDigest), rows: count, fingerprint: content };
            batches.push(batch);
        }
        const terminal = events.at(-1)?.terminal;
        require(terminal);
        if (terminal.state !== 'continued') {
            const stats = terminal.stats;
            require(stats);
            const received = uint(stats.records) === rows && (stats.lastSequence === undefined ? -1n : uint(stats.lastSequence)) === next - 1n && digest(stats.resultDigest) === previous;
            const pending = this.mode === 'tail' && last && uint(stats.records) === rows - last.rows && (stats.lastSequence === undefined ? -1n : uint(stats.lastSequence)) === last.sequence - 1n && digest(stats.resultDigest) === last.prior;
            require(received || pending);
        }
        this.#snapshot = snapshot;
        this.#schema = schema;
        this.#next = next;
        this.#digest = previous;
        this.#rows = rows;
        this.#last = last;
        this.#live ||= live;
        this.#finished ||= this.mode !== 'tail' && terminal.state !== 'continued';
        return batches;
    }
    acknowledgement() { return this.#last ? { sequence: this.#last.sequence.toString(), digest: this.#last.digest } : undefined; }
}
export function validateQueryRequest(rpc, request) {
    const input = object(request);
    function query(value, session) { const request = object(value); require(typeof request.pipeline === 'string' && Buffer.byteLength(request.pipeline) > 0 && Buffer.byteLength(request.pipeline) <= 4096); budget(request.budget, session); }
    if (rpc.endsWith('/Execute'))
        query(input, false);
    if (rpc.endsWith('/Cancel'))
        cursor(input.query ?? input.tail);
    if (rpc.endsWith('/Session')) {
        require(typeof input.batchLimit === 'number' && Number.isInteger(input.batchLimit) && input.batchLimit >= 1 && input.batchLimit <= 128);
        require(['execute', 'resume', 'tail'].filter(key => input[key] !== undefined).length === 1);
        if (input.execute !== undefined)
            query(input.execute, true);
        if (input.resume !== undefined)
            cursor(input.resume);
        if (input.tail !== undefined) {
            require(input.batchLimit === 1);
            const tail = object(input.tail);
            query(tail.query, true);
            if (tail.cursor !== undefined) {
                cursor(tail.cursor);
                require(tail.historicalRows === undefined);
            }
            if (tail.historicalRows !== undefined)
                require(uint(tail.historicalRows) > 0n && uint(tail.historicalRows) <= 128n);
            if (tail.acknowledgement !== undefined) {
                require(tail.cursor !== undefined);
                digest(object(tail.acknowledgement).digest);
            }
        }
    }
}
