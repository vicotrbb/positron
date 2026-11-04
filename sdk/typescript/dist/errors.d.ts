export declare class QueryError extends Error {
    readonly failure: string;
    readonly retryClass: string;
    readonly completionState: string;
    constructor(failure: string, retryClass: string, completionState: string);
}
export declare function queryError(status: number, text: string, cancellation?: boolean): QueryError;
