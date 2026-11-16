#!/usr/bin/env -S python3 -I -B
# SPDX-License-Identifier: MIT
"""Finite byte and AST preservation checks against immutable Reader14."""
import ast
from pathlib import Path
import sys
import unittest


def fence(event,args):
 if event.startswith(('subprocess.','socket.','ctypes.'))or event in('os.system','os.exec','os.fork','os.posix_spawn','fcntl.flock','resource.setrlimit'):
  raise AssertionError('Reader15 preservation controls forbid actor/network/authority: '+event)


sys.addaudithook(fence)
HERE=Path(__file__).resolve().parent
OLD=HERE.parent/'independent_reader_v14'

def functions(path):
 text=path.read_text()
 return {node.name:ast.get_source_segment(text,node)for node in ast.parse(text).body if isinstance(node,ast.FunctionDef)}


class PreservationControls(unittest.TestCase):
 def test_provider_package_and_elf_modules_preserved_whole(self):
  for name in('bindings.py','archives.py','elf.py'):
   self.assertEqual((HERE/name).read_bytes(),(OLD/name).read_bytes(),name)
 def test_ordinary_data_read_hash_and_namespace_guards_preserved(self):
  before,after=functions(OLD/'storage.py'),functions(HERE/'storage.py')
  for name in('need','pin','canonical','decode','digest','numeric','relative','identity','opened','hashed','read','namespace','git_tree','source_parent_inverse','source351_inverse'):
   self.assertEqual(before[name],after[name],name)
 def test_kernel_phase_commands_and_resource_guards_preserved(self):
  before,after=functions(OLD/'evidence.py'),functions(HERE/'evidence.py')
  for name in('kernel_mountinfo','kernel_proof','qualification_kernel','actor_output','natural','operations','qualification','producer','qualifier_inspected','private_bind','daemon_identity','lexical_absolute'):
   self.assertEqual(before[name],after[name],name)
 def test_source355_to351_historical_inverse_preserved(self):
  before=functions(OLD/'storage.py')['source_inverse'].replace('def source_inverse(', 'def source355_inverse(',1)
  self.assertEqual(before,functions(HERE/'storage.py')['source355_inverse'])
 def test_actual_source351_negative_bodies_preserved_whole(self):
  for name in('source351-public-failure.ACTUAL-r2.json','source351-mountinfo-data.ACTUAL.raw','source344-probe-mount.ACTUAL.json'):
   self.assertEqual((HERE/'fixtures'/name).read_bytes(),(OLD/'fixtures'/name).read_bytes(),name)


if __name__=='__main__':unittest.main()
