# SPDX-License-Identifier: MIT
"""Literal metadata expectation from the fixed caa3 template; no shell execution."""
import re,shlex
KEYS=('pkgdesc','pkgver','pkgrel','url','arch','license','makedepends','depends','provides','conflicts','backup','options','source','noextract','sha256sums')
def expected(recipe):
 rows={}
 for name in KEYS:
  matches=re.findall(r'^'+name+r'=(.*)$',recipe,re.M)
  if len(matches)!=1:raise ValueError('exact single literal recipe metadata assignment required: '+name)
  value=matches[0]
  if value=='("${source[@]}")':
   if name!='noextract':raise ValueError('only exact source-based noextract expansion allowed')
   rows[name]=rows['source']
  else:
   if any(c in value for c in ('$','`','\n')):raise ValueError('literal recipe metadata required')
   if value.startswith('(') and value.endswith(')'):value=value[1:-1]
   values=shlex.split(value)
   if not values:raise ValueError('nonempty literal metadata required')
   rows[name]=values
 if rows['pkgver']!=['2.43.caa3'] or rows['pkgrel']!=['1'] or rows['arch']!=['aarch64']:raise ValueError('exact caa3 native metadata identity required')
 if len(rows['source'])!=len(rows['sha256sums']) or rows['noextract']!=rows['source']:raise ValueError('complete source/hash/noextract metadata required')
 result=['# Literal reviewed caa3 expectation; actual makepkg output must equal it.','pkgbase = cachy-asahi-glibc-gnu-provider']
 for name,values in rows.items():result.extend('\t'+name+' = '+value for value in values)
 return '\n'.join(result+['','pkgname = cachy-asahi-glibc-gnu-provider',''])
