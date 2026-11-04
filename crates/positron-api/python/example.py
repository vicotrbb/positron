"""Read one finite query. Credentials arrive on stdin, never command arguments."""
import json
import sys
from positron_sdk import PositronClient, terminal_status
from positron_sdk.types import LogQueryRequest

def query(endpoint: str, bearer: str, request: LogQueryRequest):
    response = PositronClient(endpoint).log_query_execute(request, bearer=bearer)
    for event in response['events']:
        if 'batch' in event:
            yield event['batch']
        elif 'terminal' in event:
            if terminal_status(event['terminal'])['kind'] != 'complete':
                raise RuntimeError('Query did not complete')

if __name__ == '__main__':
    arguments = json.load(sys.stdin)
    for batch in query(arguments['endpoint'], arguments['bearer'], arguments['request']):
        print(json.dumps(batch))
