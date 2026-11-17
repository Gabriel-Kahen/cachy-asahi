# SPDX-License-Identifier: MIT
"""Exact fixed-name source TSV delivery through existing adapter.contents()."""
import hashlib
BEFORE={'bytes': 14435, 'sha256': 'a04aba8c5c4916662afdb3ea4fc960e74235ecbb559440cf21649ce5fe67606c'}
NEEDLE=b" for name in('rtc-clock.sh','guest-runtime.sh'):put('frozen/'+name,(HERE/'frozen'/name).read_bytes())"
ADDITION=b" put('expected-cache-transition.tsv',(HERE/'expected-cache-transition.tsv').read_bytes())\n"
def pin(body):return dict(bytes=len(body),sha256=hashlib.sha256(body).hexdigest())
def transform(adapter):
 if pin(adapter)!=BEFORE or adapter.count(NEEDLE)!=1 or b"put('expected-cache-transition.tsv'"in adapter:raise ValueError('exact Source339 adapter delivery preimage')
 return adapter.replace(NEEDLE,ADDITION+NEEDLE)
def inverse(generated,adapter):
 if generated!=transform(adapter):raise ValueError('exact one-name fixture delivery successor before inverse')
 return adapter
