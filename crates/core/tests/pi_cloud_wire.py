"""Probe the installed Pi release against a loopback gateway without provider credentials."""

import http.server
import json
import os
import pathlib
import queue
import subprocess
import sys
import tempfile
import threading
import unittest

EXECUTABLE = sys.argv.pop(1)
SOURCE = pathlib.Path(__file__).resolve().parents[1] / 'src/muniment_cloud_provider.mjs'


class CloudWire(unittest.TestCase):
    def exchange(self, failures=(), tool=False, terminal=False, expect_reply=True, oauth=False, naming=False):
        with tempfile.TemporaryDirectory(prefix='muniment-pi-wire-') as directory:
            root = pathlib.Path(directory)
            (root / 'agent').mkdir()
            (root / 'sessions').mkdir()
            (root / 'provider.mjs').write_text(SOURCE.read_text())
            (root / 'identity.mjs').write_text(SOURCE.with_name('assistant_identity.mjs').read_text())
            titles = []
            credential = ({'type': 'oauth', 'access': 'stored-access', 'refresh': 'stored-refresh', 'expires': 0}
                          if oauth else {'type': 'api_key', 'key': 'conflicting-stored-key'})
            stored_credentials = json.dumps({'muniment': credential})
            (root / 'agent/auth.json').write_text(stored_credentials)
            requests = []
            failure_queue = list(failures)
            tool_sent = False

            class Gateway(http.server.BaseHTTPRequestHandler):
                def do_POST(self):
                    nonlocal tool_sent
                    body = json.loads(self.rfile.read(int(self.headers['Content-Length'])))
                    requests.append((self.path, self.headers['Authorization'], body))
                    if failure_queue and (not tool or tool_sent):
                        status, code = failure_queue.pop(0)
                        denial = json.dumps({'protocol': 'muniment.desktop-access/1',
                                             'error': {'code': code, 'message': 'The request failed.'}}).encode()
                        self.send_response(status)
                        self.send_header('Content-Type', 'application/json')
                        self.send_header('Content-Length', str(len(denial)))
                        self.end_headers()
                        self.wfile.write(denial)
                        return
                    self.send_response(200)
                    self.send_header('Content-Type', 'text/event-stream')
                    self.end_headers()
                    if tool and not tool_sent:
                        tool_sent = True
                        delta = {'role': 'assistant', 'tool_calls': [{'index': 0, 'id': 'call_one',
                                 'type': 'function', 'function': {'name': 'write',
                                 'arguments': json.dumps({'path': str(root / 'tool-result'), 'content': 'once'})}}]}
                        finish = 'tool_calls'
                    else:
                        is_name = any('Name this thread in one to three words.' in str(message.get('content')) for message in body['messages'])
                        delta = {'role': 'assistant', 'content': 'Lease comparison' if is_name else 'The gateway replied.'}
                        finish = 'stop'
                    for part, reason in [(delta, None), ({}, finish)]:
                        chunk = {'id': 'wire', 'object': 'chat.completion.chunk', 'created': 1,
                                 'model': body['model'], 'choices': [{'index': 0, 'delta': part, 'finish_reason': reason}]}
                        self.wfile.write(('data: ' + json.dumps(chunk) + '\n\n').encode())
                    self.wfile.write(b'data: [DONE]\n\n')

                def log_message(self, *_):
                    pass

            server = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Gateway)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            env = {k: v for k, v in os.environ.items()
                   if not any(secret in k for secret in ('TOKEN', 'API_KEY', 'ANTHROPIC', 'PI_'))}
            gateway_url = f'http://127.0.0.1:{server.server_port}/v1'
            env.update(HOME=str(root), PI_CODING_AGENT_DIR=str(root / 'agent'),
                       OPENAI_BASE_URL=gateway_url, PI_DEFAULT_MODEL='allowed-model')
            command = [EXECUTABLE, '--mode', 'rpc', '--approve', '--session-dir', str(root / 'sessions'),
                       '--extension', str(root / 'provider.mjs'), '--provider', 'muniment', '--model', 'allowed-model',
                       '--api-key', 'muniment-runtime-boundary']
            if naming:
                command.extend(['--extension', str(root / 'identity.mjs')])
            process = subprocess.Popen(command, cwd=root, env=env, stdin=subprocess.PIPE,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            lines = queue.Queue()
            threading.Thread(target=lambda: [lines.put(line) for line in process.stdout], daemon=True).start()
            events = []
            boundaries = []
            key_number = 1
            try:
                process.stdin.write(json.dumps({'id': 'wire', 'type': 'prompt', 'message': 'Reply briefly.'}) + '\n')
                process.stdin.flush()
                while True:
                    event = json.loads(lines.get(timeout=45))
                    if event.get('type') == 'extension_ui_request' and event.get('title') == 'muniment:thread-title':
                        request = json.loads(event['prefill'])
                        if request['action'] == 'request':
                            answer = {'prompt': 'Compare lease terms'}
                        else:
                            titles.append(request['title'])
                            answer = {'saved': True}
                        process.stdin.write(json.dumps({'type': 'extension_ui_response', 'id': event['id'], 'value': json.dumps(answer)}) + '\n')
                        process.stdin.flush()
                    elif event.get('type') == 'extension_ui_request' and event.get('title') == 'muniment:chat-grant':
                        denial = json.loads(event['prefill'])
                        boundaries.append(denial)
                        if denial:
                            key_number += 1
                        if terminal and denial:
                            answer = {'error': 'The capability is not authorized.'}
                        else:
                            answer = {'gateway_url': gateway_url, 'virtual_key': f'ephemeral-wire-key-{key_number}',
                                      'model': 'allowed-model'}
                        process.stdin.write(json.dumps({'type': 'extension_ui_response', 'id': event['id'],
                                                        'value': json.dumps(answer)}) + '\n')
                        process.stdin.flush()
                    else:
                        events.append(event)
                    if event.get('type') == 'agent_end':
                        break
                # Pi announces automatic retries after agent_end. Keep its default retry policy enabled.
                while True:
                    try:
                        event = json.loads(lines.get(timeout=0.5))
                    except queue.Empty:
                        break
                    self.assertNotEqual(event.get('type'), 'auto_retry_start', event)
                    self.assertNotEqual(event.get('type'), 'extension_ui_request', event)
                    events.append(event)
                self.assertEqual((root / 'agent/auth.json').read_text(), stored_credentials)
                self.assertTrue(requests)
                self.assertTrue(all(path == '/v1/chat/completions' for path, _, _ in requests))
                self.assertTrue(all(key.startswith('Bearer ephemeral-wire-key-') for _, key, _ in requests))
                self.assertTrue(all(body['model'] == 'allowed-model' for _, _, body in requests))
                self.assertNotIn('ephemeral-wire-key-', json.dumps(events))
                if not terminal and expect_reply:
                    self.assertIn('The gateway replied.', json.dumps(events))
                if tool:
                    self.assertEqual((root / 'tool-result').read_text(), 'once')
                    self.assertEqual(sum(event.get('type') == 'tool_execution_end' for event in events), 1)
                    self.assertEqual(requests[-1][2]['messages'], requests[-2][2]['messages'])
                for path in root.rglob('*'):
                    if path.is_file():
                        self.assertNotIn(b'ephemeral-wire-key-', path.read_bytes(), str(path))
                if naming:
                    self.assertEqual(titles, ['Lease comparison'])
                    self.assertEqual(len(requests), 2)
                    self.assertNotIn('Lease comparison', json.dumps(events))
                return requests, boundaries
            finally:
                process.terminate()
                process.wait(timeout=10)
                server.shutdown()
                server.server_close()
                process.stdin.close()
                process.stdout.close()
                error = process.stderr.read()
                process.stderr.close()
                self.assertNotIn('ephemeral-wire-key-', error)

    def test_first_message_names_the_thread_before_the_reply(self):
        self.exchange(naming=True)

    def test_stored_credentials_cannot_override_the_grant(self):
        requests, boundaries = self.exchange()
        self.assertEqual(len(requests), 1)
        self.assertEqual(boundaries, [None])

    def test_stored_oauth_cannot_block_the_grant(self):
        requests, _ = self.exchange(oauth=True)
        self.assertEqual(len(requests), 1)

    def test_canonical_gateway_denials_renew_only_the_failed_request(self):
        for status, code in [(401, 'grant_expired'), (401, 'grant_replaced'),
                             (401, 'grant_revoked'), (409, 'entitlement_changed')]:
            with self.subTest(code=code):
                requests, boundaries = self.exchange([(status, code)])
                self.assertEqual(len(requests), 2)
                self.assertEqual(requests[0][2], requests[1][2])
                self.assertNotEqual(requests[0][1], requests[1][1])
                self.assertEqual(boundaries[1]['body']['error']['code'], code)

    def test_tool_results_survive_expiry_without_tool_replay(self):
        requests, boundaries = self.exchange([(401, 'grant_expired')], tool=True)
        self.assertEqual(len(requests), 3)
        self.assertEqual(boundaries[:2], [None, None])

    def test_budget_and_model_denials_do_not_retry(self):
        for status, code in [(429, 'budget_exhausted'), (403, 'model_not_allowed')]:
            requests, _ = self.exchange([(status, code)], terminal=True)
            self.assertEqual(len(requests), 1)

    def test_gateway_recovery_has_one_retry(self):
        requests, boundaries = self.exchange([(401, 'grant_expired')] * 2, expect_reply=False)
        self.assertEqual(len(requests), 2)
        self.assertTrue(boundaries[-1]['terminal'])


if __name__ == '__main__':
    version = subprocess.check_output([EXECUTABLE, '--version'], text=True, stderr=subprocess.STDOUT).strip()
    if version not in ('0.85.1', '0.87.1'):
        raise SystemExit(f'The wire test requires Pi 0.85.1 or 0.87.1. The executable reports {version}.')
    unittest.main()
