"""Installed actual wheel against the candidate native Rust server."""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[3]

def conformance():
    # The test process uses the build interpreter selected by CI/local validation.
    from test_package import build_wheel
    with tempfile.TemporaryDirectory(prefix='positron-live-python-') as temporary:
        temporary = pathlib.Path(temporary)
        wheel = build_wheel(ROOT / 'sdk/python', temporary)
        consumer = temporary / 'consumer'
        subprocess.run([sys.executable, '-m', 'venv', str(consumer)], check=True, capture_output=True)
        python = consumer / 'bin/python'
        env = {key: value for key, value in os.environ.items() if key != 'PYTHONPATH'}
        subprocess.run([str(python), '-m', 'pip', 'install', '--no-deps', '--no-index', str(wheel)], env=env, cwd=temporary, check=True, capture_output=True)
        child = subprocess.run([str(python), __file__, '--installed'], input=sys.stdin.buffer.read(), env=env, capture_output=True)
        sys.stdout.buffer.write(child.stdout)
        sys.stderr.buffer.write(child.stderr)
        return child.returncode

def installed():
    from positron_sdk import PositronClient, BatchTracker, QueryError, terminal_status
    arguments = json.load(sys.stdin)
    client = PositronClient(arguments['endpoint'], allow_plaintext=True)
    options = dict(bearer=arguments['bearer'], timeout=30)
    query = dict(pipeline='pipeline:v1 logs | range query_time 0 100 | project commit_position | limit 2', budget=dict(scannedBytes='1048576', decodedRecords='16', outputRows='16', outputBytes='16384', memoryBytes='1048576', cpuWorkUnits='16', wallSeconds='5', maximumTimeRangeNanoseconds='100'))
    def admitted(call):
        for _ in range(5):
            try:
                return call()
            except QueryError as error:
                if error.failure != 'CapacityUnavailable':
                    raise
                time.sleep(1)
        raise RuntimeError('Query admission exhausted')
    phase = 'capability'
    try:
        assert client.capability_negotiate({'api_major': 1})['api_major'] == 1
        assert client.capability_negotiate({'api_major': 1, 'capability': 3})['availability'] == 3
        phase = 'execute'
        first = admitted(lambda: client.log_query_execute(query, **options))
        assert terminal_status(first['events'][-1]['terminal'])['kind'] == 'complete'
        assert sum(len(batch['rows']) for batch in BatchTracker().filter(first)) == 2
        phase = 'session'
        tracker = BatchTracker()
        page = admitted(lambda: client.log_query_session({'execute': query, 'batchLimit': 1}, **options))
        tracker.filter(page)
        terminal = terminal_status(page['events'][-1]['terminal'])
        assert terminal['kind'] == 'continued'
        phase = 'resume'
        next_page = admitted(lambda: client.log_query_session({'resume': terminal['cursor'], 'batchLimit': 1}, **options))
        assert sum(len(batch['rows']) for batch in tracker.filter(next_page)) == 1
        assert terminal_status(next_page['events'][-1]['terminal'])['kind'] == 'complete'
        assert next_page['events'][0]['header']['snapshot'] == page['events'][0]['header']['snapshot']
        phase = 'cancel'
        page = admitted(lambda: client.log_query_session({'execute': query, 'batchLimit': 1}, **options))
        assert client.log_query_cancel({'query': page['events'][0]['header']['initialCursor']}, **options)['cancelled'] is True
        phase = 'tail'
        tail_query = dict(query, pipeline=query['pipeline'].replace('limit 2', 'limit all'), budget=dict(query['budget'], wallSeconds='60'))
        tail = admitted(lambda: client.log_query_session({'tail': {'query': tail_query}, 'batchLimit': 1}, **options))
        BatchTracker('tail').filter(tail)
        assert client.log_query_cancel({'tail': tail['events'][-1]['terminal']['continuationCursor']}, **options)['cancelled'] is True
        phase = 'authentication refusal'
        try:
            client.log_query_execute(query, bearer='invalid')
            raise RuntimeError('Authentication accepted')
        except QueryError as error:
            assert error.failure == 'AuthenticationRejected' and error.completion_state == 'COMPLETION_STATE_REJECTED'
        phase = 'administration'
        assert isinstance(client.tenant_list({}, bearer=arguments['admin'])['tenants'], list)
        print('Python live conformance passed')
        return 0
    except Exception as error:
        # No credential, raw request, cursor or response diagnostics.
        print(f'Python conformance failed at {phase}: {type(error).__name__}', file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(installed() if '--installed' in sys.argv else conformance())
