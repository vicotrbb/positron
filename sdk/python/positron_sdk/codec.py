"""Generated Public Interface JSON adapter; all shapes come from Rust metadata."""
import base64
import binascii
import json
import math
import re
from pathlib import Path

CONTRACT = json.loads(Path(__file__).with_name('contract.json').read_text())
API_VERSION = CONTRACT['api_version']
SCHEMA_DIGEST = CONTRACT['schema_digest']

class WireError(ValueError):
    def __init__(self):
        super().__init__('Invalid Positron wire data')

def require(condition):
    if not condition:
        raise WireError()

def obj(value):
    require(isinstance(value, dict))
    return value

def base64_value(value, limit=262144):
    require(isinstance(value, str) and len(value) <= ((limit + 2) // 3) * 4)
    try:
        raw = base64.b64decode(value, validate=True)
    except (ValueError, binascii.Error):
        raise WireError() from None
    require(len(raw) <= limit and base64.b64encode(raw).decode() == value)
    return value

def parse_json(text):
    require(isinstance(text, str) and len(text.encode()) <= 262144)
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result)
            result[key] = value
        return result
    try:
        return json.loads(text, object_pairs_hook=pairs, parse_constant=lambda _: (_ for _ in ()).throw(WireError()))
    except (ValueError, RecursionError):
        raise WireError() from None

def validate(schema, value, depth=0):
    require(depth <= 64)
    if value is None and schema.get('nullable'):
        return value
    if '$ref' in schema:
        return validate(CONTRACT['schemas'][schema['$ref'].rsplit('/', 1)[-1]], value, depth + 1)
    variants = schema.get('oneOf', schema.get('anyOf'))
    if isinstance(schema.get('type'), list):
        variants = [dict(schema, type=kind) for kind in schema['type']]
    if variants:
        for variant in variants:
            try:
                return validate(variant, value, depth + 1)
            except WireError:
                pass
        raise WireError()
    if 'const' in schema:
        require(value == schema['const'])
    if 'enum' in schema:
        require(value in schema['enum'])
    kind = schema.get('type')
    if kind == 'string':
        require(isinstance(value, str))
        require(len(value) >= schema.get('minLength', 0) and len(value) <= schema.get('maxLength', 262144))
        if 'pattern' in schema:
            require(re.search(schema['pattern'], value) is not None)
        if schema.get('contentEncoding') == 'base64':
            base64_value(value)
        if schema.get('format') in ('int64', 'uint64'):
            require(re.fullmatch(r'-?(0|[1-9][0-9]*)', value) is not None)
            signed = schema['format'] == 'int64'
            require((-(1 << 63) if signed else 0) <= int(value) < (1 << (63 if signed else 64)))
    elif kind in ('integer', 'number'):
        require(type(value) in ((int,) if kind == 'integer' else (int, float)))
        require(not isinstance(value, float) or math.isfinite(value))
        require(value >= schema.get('minimum', -math.inf) and value <= schema.get('maximum', math.inf))
        if schema.get('format') in ('int64-json', 'uint64-json'):
            signed = schema['format'] == 'int64-json'
            require((-(1 << 63) if signed else 0) <= value < (1 << (63 if signed else 64)))
    elif kind == 'boolean':
        require(type(value) is bool)
    elif kind == 'null':
        require(value is None)
    elif kind == 'array':
        require(isinstance(value, list))
        return [validate(schema.get('items', {}), item, depth + 1) for item in value]
    elif kind == 'object':
        obj(value)
        require(all(key in value for key in schema.get('required', [])))
        result = {}
        for key, item in value.items():
            field = schema.get('properties', {}).get(key)
            if field is not None:
                result[key] = validate(field, item, depth + 1)
            else:
                require(schema.get('additionalProperties') is not False)
                result[key] = item
        return result
    return value

def normalize(name, value, depth=0):
    require(depth <= 64)
    fields = CONTRACT['descriptor']['messages'].get(name)
    if not fields:
        return value
    output, groups = {}, set()
    for key, item in obj(value).items():
        field = next((field for field in fields if key in (field['name'], field['json_name'])), None)
        require(field is not None and field['json_name'] not in output)
        if item is None:
            continue
        if field['oneof'] is not None:
            require(field['oneof'] not in groups)
            groups.add(field['oneof'])
        def convert(value):
            if field['type'] == 11 and field['type_name']:
                return normalize(field['type_name'].rsplit('.', 1)[-1], value, depth + 1)
            if field['type'] in (3, 4, 6, 16, 18) and type(value) is int:
                return str(value)
            if field['type'] == 12 and isinstance(value, str):
                require(re.fullmatch(r'[A-Za-z0-9+/_-]*={0,2}', value) is not None and len(value.rstrip('=')) % 4 != 1)
                try:
                    return base64.b64encode(base64.urlsafe_b64decode(value + '=' * (-len(value) % 4))).decode()
                except (ValueError, binascii.Error):
                    raise WireError() from None
            return value
        if field['repeated']:
            require(isinstance(item, list))
            output[field['json_name']] = [convert(value) for value in item]
        else:
            output[field['json_name']] = convert(item)
    return output

def decode(name, text):
    require(name in CONTRACT['schemas'])
    value = parse_json(text)
    if name.startswith('LogQuery'):
        value = normalize(name, value)
    result = validate(CONTRACT['schemas'][name], value)
    if name == 'LogQuerySessionRequest':
        require(type(result.get('batchLimit')) is int and 1 <= result['batchLimit'] <= 128)
        if 'resume' in result:
            require(bool(base64_value(result['resume'], 8192)))
    if name == 'LogQueryCancelRequest':
        require(bool(base64_value(result.get('query', result.get('tail')), 8192)))
    return result

def encode(name, value):
    try:
        text = json.dumps(value, separators=(',', ':'), allow_nan=False, ensure_ascii=False)
    except (ValueError, TypeError, RecursionError):
        raise WireError() from None
    decode(name, text)
    return text
