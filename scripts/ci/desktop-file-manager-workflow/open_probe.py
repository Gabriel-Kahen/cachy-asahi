# SPDX-License-Identifier: MIT
"""Private MIME launch receipt. No editor or interactive-input claim."""
import os
from pathlib import Path
import sys
import importlib.util
spec = importlib.util.spec_from_file_location('file_manager_handler', Path(__file__).with_name('file_manager.py'))
T = importlib.util.module_from_spec(spec);spec.loader.exec_module(T)
CONTENT, need, publish, read, sha = T.CONTENT, T.need, T.publish, T.read, T.sha


def main():
    need(os.getuid() == 23001 and 'cachy_asahi_file_manager=1' in
         Path('/proc/cmdline').read_text().split(), 'private guest handler only')
    need(len(sys.argv) == 4, 'handler argument count')
    root = Path(sys.argv[1]); nonce = sys.argv[2]; path = Path(sys.argv[3])
    need(root.is_absolute() and root.parent == Path('/home/desktop574') and
         root.name.startswith('files-') and path == root / 'Files' / 'renamed.txt',
         'owned handler path differs')
    data = read(path, 4096);need(data == CONTENT, 'opened bytes differ')
    publish(root / 'opened.json', dict(nonce=nonce, path=str(path), sha256=sha(data),
            bytes=len(data), uid=os.getuid(), pid=os.getpid()))


if __name__ == '__main__':main()
