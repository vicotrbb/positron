import type { WireTypes } from './types.js';
type ObjectValue = {
    [key: string]: unknown;
};
export declare class WireError extends Error {
    constructor();
}
export declare function object(value: unknown): ObjectValue;
export declare function base64(value: unknown, limit?: number): string;
export declare function parseWireJson(text: string): unknown;
export declare function decode<N extends keyof WireTypes>(name: N, text: string): WireTypes[N];
export declare function decode(name: string, text: string): unknown;
export declare function encode(name: string, value: unknown): string;
export {};
