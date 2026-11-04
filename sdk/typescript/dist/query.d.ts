import type { LogQueryResponse, LogQueryBatch, LogQueryAcknowledgement, LogQueryTerminal } from './types.js';
export type QueryMode = 'execute' | 'session' | 'tail';
export declare function decodeQuery(text: string, mode?: QueryMode): LogQueryResponse;
export type TerminalStatus = {
    readonly kind: 'complete';
} | {
    readonly kind: 'continued';
    readonly cursor: string;
} | {
    readonly kind: 'incomplete';
    readonly reason: string;
    readonly cursor?: string;
};
export declare function terminalStatus(terminal: LogQueryTerminal): TerminalStatus;
export declare class BatchTracker {
    #private;
    readonly mode: 'session' | 'tail';
    constructor(mode?: 'session' | 'tail');
    filter(response: LogQueryResponse): readonly LogQueryBatch[];
    acknowledgement(): LogQueryAcknowledgement | undefined;
}
export declare function validateQueryRequest(rpc: string, request: unknown): void;
