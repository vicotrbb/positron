import {BatchTracker, PositronClient, terminalStatus, type LogQueryRequest} from '@positron/sdk';

/** Consume a bounded finite query using a caller-supplied secret. */
export async function query(endpoint: string, bearer: string, request: LogQueryRequest) {
  const client = new PositronClient({endpoint});
  const response = await client.logQueryExecute(request,{bearer});
  const tracker = new BatchTracker();
  const batches = tracker.filter(response);
  const terminal = response.events?.at(-1)?.terminal;
  if (!terminal) throw new Error('Missing query terminal');
  return {batches,status:terminalStatus(terminal)};
}
