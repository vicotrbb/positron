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
/* GENERATED_METHODS */
}
