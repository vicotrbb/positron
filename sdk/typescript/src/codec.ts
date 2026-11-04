// Public Interface package adapter. Wire shape is generated from canonical metadata.
import type {WireTypes} from './types.js';
import { schemas, descriptor } from './contract.js';

type ObjectValue = { [key: string]: unknown };
type Schema = { readonly $ref?: string; readonly type?: string | readonly string[]; readonly enum?: readonly unknown[]; readonly oneOf?: readonly Schema[]; readonly anyOf?: readonly Schema[]; readonly properties?: Readonly<Record<string, Schema>>; readonly required?: readonly string[]; readonly items?: Schema; readonly pattern?: string; readonly format?: string; readonly contentEncoding?: string; readonly minimum?: number; readonly maximum?: number; readonly minLength?: number; readonly maxLength?: number; readonly const?: unknown; readonly nullable?: boolean; readonly additionalProperties?: boolean | Schema };
const definitions: Readonly<Record<string, Schema>> = schemas;
export class WireError extends Error { constructor() { super('Invalid Positron wire data'); this.name = 'WireError'; } }
export function object(value: unknown): ObjectValue {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new WireError();
  return value as ObjectValue;
}
export function base64(value: unknown, limit = 262144): string {
  if (typeof value !== 'string' || value.length > Math.ceil(limit / 3) * 4 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value) || Buffer.from(value, 'base64').toString('base64') !== value || Buffer.byteLength(value, 'base64') > limit) throw new WireError();
  return value;
}
// Parse bounded JSON without losing 64-bit producer integers or accepting duplicates.
export function parseWireJson(text: string): unknown {
  if (Buffer.byteLength(text) > 262144) throw new WireError();
  let position = 0;
  function space() { while (/[ \t\r\n]/.test(text[position] ?? '') && position < text.length) position++; }
  function value(depth: number): unknown {
    if (depth > 64) throw new WireError();
    space();
    const start = position;
    if (text[position] === '"') {
      position++;
      while (position < text.length) {
        const current = text[position++];
        if (current === '\\') position++;
        else if (current === '"') return JSON.parse(text.slice(start, position));
      }
      throw new WireError();
    }
    if (text[position] === '{' || text[position] === '[') {
      const array = text[position++] === '[';
      const result: ObjectValue = Object.create(null);
      const items: unknown[] = [];
      space();
      if (text[position] === (array ? ']' : '}')) { position++; return array ? items : result; }
      while (position < text.length) {
        if (array) items.push(value(depth + 1));
        else {
          space();
          if (text[position] !== '"') throw new WireError();
          const key = value(depth + 1);
          space();
          if (typeof key !== 'string' || text[position++] !== ':' || Object.hasOwn(result, key)) throw new WireError();
          result[key] = value(depth + 1);
        }
        space();
        if (text[position] === (array ? ']' : '}')) { position++; return array ? items : result; }
        if (text[position++] !== ',') throw new WireError();
      }
      throw new WireError();
    }
    const literal = /^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)/.exec(text.slice(position))?.[0];
    if (!literal) throw new WireError();
    position += literal.length;
    const parsed: unknown = JSON.parse(literal);
    return typeof parsed === 'number' && Number.isInteger(parsed) && !Number.isSafeInteger(parsed) && /^-?[0-9]+$/.test(literal) ? BigInt(literal) : parsed;
  }
  const result = value(0); space();
  if (position !== text.length) throw new WireError();
  return result;
}
function validate(schema: Schema, value: unknown, depth: number): unknown {
  if (depth > 64) throw new WireError();
  if (Array.isArray(schema.type)) {
    for (const type of schema.type) { try { return validate({...schema, type}, value, depth + 1); } catch (error) { if (!(error instanceof WireError)) throw error; } }
    throw new WireError();
  }
  if (Object.hasOwn(schema, 'const') && value !== schema.const) throw new WireError();
  if (value === null && schema.nullable) return null;
  if (schema.$ref) return validate(definitions[schema.$ref.slice(schema.$ref.lastIndexOf('/') + 1)] ?? {}, value, depth + 1);
  const variants = schema.oneOf ?? schema.anyOf;
  if (variants) {
    for (const variant of variants) { try { return validate(variant, value, depth + 1); } catch (error) { if (!(error instanceof WireError)) throw error; } }
    throw new WireError();
  }
  if (schema.enum && !schema.enum.includes(value)) throw new WireError();
  if (schema.format === 'uint64-json' || schema.format === 'int64-json') {
    if (typeof value !== 'number' && typeof value !== 'bigint' || typeof value === 'number' && !Number.isSafeInteger(value)) throw new WireError();
    let integer: bigint;
    try { integer = BigInt(value); } catch { throw new WireError(); }
    const signed = schema.format === 'int64-json';
    if (integer < (signed ? -(1n<<63n) : 0n) || integer >= (signed ? 1n<<63n : 1n<<64n) || schema.minimum !== undefined && integer < BigInt(schema.minimum) || schema.maximum !== undefined && integer > BigInt(schema.maximum)) throw new WireError();
    return integer >= BigInt(Number.MIN_SAFE_INTEGER) && integer <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(integer) : integer;
  }
  if (schema.type === 'string') {
    if (typeof value !== 'string' || (schema.minLength !== undefined && value.length < schema.minLength) || (schema.maxLength !== undefined && value.length > schema.maxLength) || (schema.pattern && !new RegExp(schema.pattern).test(value))) throw new WireError();
    if (schema.contentEncoding === 'base64') base64(value);
    if (schema.format === 'int64' || schema.format === 'uint64') {
      const integer = BigInt(value);
      if (integer < (schema.format === 'int64' ? -(1n << 63n) : 0n) || integer >= (schema.format === 'int64' ? 1n << 63n : 1n << 64n)) throw new WireError();
    }
  } else if (schema.type === 'integer' || schema.type === 'number') {
    if (typeof value !== 'number' || !Number.isFinite(value) || (schema.type === 'integer' && !Number.isSafeInteger(value)) || (schema.minimum !== undefined && value < schema.minimum) || (schema.maximum !== undefined && value > schema.maximum)) throw new WireError();
  } else if (schema.type === 'boolean') { if (typeof value !== 'boolean') throw new WireError(); }
  else if (schema.type === 'null') { if (value !== null) throw new WireError(); }
  else if (schema.type === 'array') {
    if (!Array.isArray(value)) throw new WireError();
    return value.map(item => validate(schema.items ?? {}, item, depth + 1));
  } else if (schema.type === 'object') {
    const input = object(value);
    const output: ObjectValue = {};
    for (const key of schema.required ?? []) if (!Object.hasOwn(input, key)) throw new WireError();
    for (const [key, item] of Object.entries(input)) {
      const field = schema.properties?.[key];
      if (field) output[key] = validate(field, item, depth + 1);
      else if (schema.additionalProperties === false) throw new WireError();
      else output[key] = item;
    }
    return output;
  }
  return value;
}
type Field = { readonly name: string | null; readonly json_name: string | null; readonly type: number | null; readonly type_name: string | null; readonly optional: boolean; readonly repeated: boolean; readonly oneof: number | null; readonly number: number | null };
const messages: Readonly<Record<string, readonly Field[]>> = descriptor.messages;
export function decode<N extends keyof WireTypes>(name:N,text:string): WireTypes[N];
export function decode(name:string,text:string):unknown;
export function decode(name: string, text: string): unknown {
  if (Buffer.byteLength(text) > 262144 || !Object.hasOwn(definitions, name)) throw new WireError();
  const input = parseWireJson(text);
  const result = validate(definitions[name] ?? {}, normalize(name, input, 0), 0);
  if (name === 'LogQuerySessionRequest') {
    const request = object(result);
    if (typeof request.batchLimit !== 'number' || request.batchLimit < 1 || request.batchLimit > 128) throw new WireError();
    if (request.resume !== undefined && base64(request.resume,8192) === '') throw new WireError();
  }
  if (name === 'LogQueryCancelRequest') {
    const request = object(result);
    if (base64(request.query ?? request.tail,8192) === '') throw new WireError();
  }
  return result;
}
function normalize(name: string, value: unknown, depth: number): unknown {
  if (!name.startsWith('LogQuery') || depth > 64) return value;
  const fields = messages[name];
  if (!fields) throw new WireError();
  const input = object(value);
  const output: ObjectValue = {};
  const groups = new Set<number>();
  for (const [key, item] of Object.entries(input)) {
    const field = fields.find(field => field.name === key || field.json_name === key);
    if (!field || !field.json_name || Object.hasOwn(output, field.json_name)) throw new WireError();
    if (item === null) continue;
    if (field.oneof !== null) {
      if (groups.has(field.oneof)) throw new WireError();
      groups.add(field.oneof);
    }
    const convert = (value: unknown): unknown => {
      if (field.type === 11 && field.type_name) return normalize(field.type_name.split('.').at(-1) ?? '', value, depth + 1);
      if ([3,4,6,16,18].includes(field.type ?? 0) && (typeof value === 'number' || typeof value === 'bigint')) { if (typeof value === 'number' && !Number.isSafeInteger(value)) throw new WireError(); return String(value); }
      if (field.type === 12 && typeof value === 'string') {
        if (!/^[A-Za-z0-9+/_-]*={0,2}$/.test(value) || value.replace(/=+$/, '').length % 4 === 1) throw new WireError();
        return Buffer.from(value, 'base64').toString('base64');
      }
      return value;
    };
    if (field.repeated) { if (!Array.isArray(item)) throw new WireError(); output[field.json_name] = item.map(convert); }
    else output[field.json_name] = convert(item);
  }
  return output;
}
export function encode(name: string, value: unknown): string {
  function stringify(value: unknown, depth: number): string {
    if (depth > 64) throw new WireError();
    if (typeof value === 'bigint') return value.toString();
    if (value === null || typeof value === 'string' || typeof value === 'boolean' || typeof value === 'number' && Number.isFinite(value)) return JSON.stringify(value);
    if (Array.isArray(value)) return `[${value.map(item=>stringify(item,depth+1)).join(',')}]`;
    return `{${Object.entries(object(value)).filter(([,value])=>value !== undefined).map(([key,value])=>`${JSON.stringify(key)}:${stringify(value,depth+1)}`).join(',')}}`;
  }
  const text = stringify(value,0);
  decode(name, text);
  return text;
}
