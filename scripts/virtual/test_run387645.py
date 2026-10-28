# SPDX-License-Identifier: MIT
"""Regressions for retained MIME-cache and mapping acceptance failures."""
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import Mock, patch

import guest
import prepare


class ClientsReply(unittest.TestCase):
    def phase(self, results, clock):
        with tempfile.TemporaryDirectory(prefix='vm-clients-') as temporary:
            root = Path(temporary); runtime = root/'runtime'; runtime.mkdir()
            wayland = socket.socket(socket.AF_UNIX); wayland.bind(str(runtime/'wayland-0'))
            self.addCleanup(wayland.close)
            compositor, client = Mock(), Mock(); client.pid = 42
            for process in (compositor, client): process.poll.return_value = None
            compositor.returncode = 0
            collectors = [Mock(process=compositor, error=None), Mock(process=client, error=None)]
            def launch(argv, log, **options):
                log.write_text('inert log\n')
                if 'Hyprland' in argv[0]:
                    private = runtime/'hypr/fixture/hyprland.log'
                    private.parent.mkdir(parents=True); private.write_text('inert private log\n')
                    return collectors[0]
                return collectors[1]
            replies = iter(results)
            def bounded(argv, **options):
                if argv[-1] == 'monitors': text = '[{"width":1024,"height":768}]'
                else: text = ''
                return {'returncode': 0, 'error': None, 'stdout': text, 'stderr': ''}
            def query_clients(env, deadline, check):
                check()
                result = next(replies)
                return json.loads(result['stdout'])
            def terminate(process): process.poll.return_value = -15
            compositor.wait.side_effect = lambda **options: setattr(compositor.poll, 'return_value', 0)
            env = {'XDG_RUNTIME_DIR': str(runtime)}
            with patch('guest.LoggedProcess', side_effect=launch), patch('guest.wait_for_ipc', return_value=env), \
                 patch('guest.image_decode_preflight'), patch('guest.bounded', side_effect=bounded), \
                 patch('guest.capture_window', side_effect=lambda stage, monitors, pid, env, check: (check(), guest.emit('frame_ready', stage=stage, monitors=monitors, clients=[{'pid': pid}]))), \
                 patch('guest.shutdown_compositor', side_effect=lambda env, compositor, check: (check(), compositor.wait(timeout=15))), \
                 patch('guest.query_clients', side_effect=query_clients), \
                 patch('guest.terminate', side_effect=terminate), patch('guest.time.monotonic', side_effect=clock), \
                 patch('guest.time.sleep'), patch('guest.emit') as events:
                try: guest.phase('minimal', root/'config', env, root)
                except ValueError as error: failure = error
                else: failure = None
            collectors[0].finish.assert_called_once()
            self.assertEqual(collectors[1].finish.call_count, 2 if failure is None else 1)
            return failure, events.call_args_list

    def test_empty_reply_retries_then_requires_real_mapped_client(self):
        empty = {'returncode': 0, 'error': None, 'stdout': '[]', 'stderr': ''}
        mapped = {'returncode': 0, 'error': None, 'stdout': '[{"pid":42,"mapped":true,"visible":true,"hidden":false,"size":[420,220]}]', 'stderr': ''}
        failure, events = self.phase([empty, mapped], [0, 0, 1, 2, 3, 3, 20])
        self.assertIsNone(failure)
        self.assertEqual(sum(row.args == ('frame_ready',) for row in events), 1)
        self.assertEqual(sum(row.args == ('phase_pass',) for row in events), 1)

    def test_timeout_cannot_accept_mapping_after_original_deadline(self):
        empty = {'returncode': 0, 'error': None, 'stdout': '[]', 'stderr': ''}
        failure, events = self.phase([empty], [0, 0, 45])
        self.assertEqual(str(failure), 'Wayland client mapping deadline')
        self.assertFalse(any(row.args == ('frame_ready',) for row in events))
        states = [row.kwargs['boundary'] for row in events if row.args == ('process_state',)]
        self.assertEqual(states, ['before_cleanup', 'after_cleanup'])



class MimeMetadata(unittest.TestCase):
    def test_missing_hook_cache_is_generated_only_under_staged_root(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); mime = root/'usr/share/mime'; (mime/'packages').mkdir(parents=True)
            source = mime/'packages/freedesktop.org.xml'; source.write_bytes(b'packaged input fixture')
            report = {'fixture_changes': []}
            def generate(argv, timeout):
                self.assertEqual(argv, ['/usr/bin/update-mime-database', str(mime)])
                self.assertEqual(timeout, 30)
                (mime/'mime.cache').write_bytes(b'generated fixture')
            prepare.prepare_mime_database(root, generate, report)
            self.assertEqual(source.read_bytes(), b'packaged input fixture')
            self.assertEqual(report['fixture_changes'][0]['mime_cache_sha256'], prepare.digest(mime/'mime.cache'))
            self.assertEqual(report['fixture_changes'][0]['path'], 'usr/share/mime')

    def test_missing_output_or_symlinked_stage_never_counts_as_generated_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); mime = root/'usr/share/mime'; (mime/'packages').mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, 'generated staged MIME cache'):
                prepare.prepare_mime_database(root, Mock(), {'fixture_changes': []})
            (mime/'packages').rmdir(); (mime/'packages').symlink_to(root, target_is_directory=True)
            generator = Mock()
            with self.assertRaisesRegex(ValueError, 'staged MIME package directory'):
                prepare.prepare_mime_database(root, generator, {'fixture_changes': []})
            generator.assert_not_called()


if __name__ == '__main__': unittest.main()
