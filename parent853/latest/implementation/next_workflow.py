# SPDX-License-Identifier: MIT
"""Four explicit extra immutable inputs; the full accepted581 workflow stays inverted."""
import re
import next_inputs as N
ENTRY='expanded604-code/latest/implementation/latest_run.py'
WF='.github/workflows/native-arm-current607-latest-tools.yml';ALIAS='.github/workflows/native-arm-build.yml'
def one(text,a,b):N.need(text.count(a)==1,'one exact six-tool workflow operand '+a[:100]);return text.replace(a,b,1)
def derive(text):
 marker='      - name: Checkout exact accepted Apps8 additional product DATA\n';blocks=''
 for role,(source,count)in N.SOURCES.items():
  blocks+='      - name: Checkout exact next '+role+' public input DATA\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: '+source+'\n          path: latest607-next-'+role+'-inputs\n          persist-credentials: false\n'
 text=one(text,marker,blocks+marker);text=one(text,'python3 -I -B expanded604-code/latest/test_source.py','python3 -I -B expanded604-code/next/test_source.py')
 operand=' '.join('--'+role+'-packet "$GITHUB_WORKSPACE/latest607-next-'+role+'-inputs"'for role in N.SOURCES);anchor='--apps8-packet "$GITHUB_WORKSPACE/latest607-apps8-inputs"';N.need(text.count(anchor)==2,'both actual input/owner argv receive all four extra packets');text=text.replace(anchor,anchor+' '+operand)
 order(text);return text

def order(text):
 import latest_workflow as W
 rows=W.steps(text);positions={}
 for role,(source,count)in N.SOURCES.items():
  selected=[i for i,r in enumerate(rows)if r['name']=='Checkout exact next '+role+' public input DATA'];N.need(len(selected)==1,'one exact new checkout '+role);i=selected[0];body=rows[i]['body'];N.need(re.findall(r'^          ref: (.+)$',body,re.M)==[source]and re.findall(r'^          path: (.+)$',body,re.M)==['latest607-next-'+role+'-inputs']and re.findall(r'^          persist-credentials: (.+)$',body,re.M)==['false'],'exact immutable new checkout fields');positions[role]=i
 consumers=[i for i,r in enumerate(rows)if '--native-inputs'in r['body']or any('--'+role+'-packet'in r['body']for role in N.SOURCES)or '${{ secrets.'in r['body']or 'docker build'in r['body']or 'docker run'in r['body']];N.need(consumers and max(positions.values())<min(consumers),'all new public data precedes every input consumer/private actor');return positions
