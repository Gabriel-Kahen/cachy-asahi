# SPDX-License-Identifier: MIT
"""One additional exact Apps8 checkout; original five baseline operands remain held."""
import re
import latest_plan as P
import latest_selection as S
CHECKOUT='      - name: Checkout exact accepted Apps8 additional product DATA\n        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1\n        with:\n          ref: 6dbfdbad6d9ec75a230ce366096206de933b1c28\n          path: latest607-apps8-inputs\n          persist-credentials: false\n'
OPERAND=' --apps8-packet "$GITHUB_WORKSPACE/latest607-apps8-inputs"'
def derive(before):
 marker='      - name: Latest five source and refusal controls before secrets\n';P.need(before.count(marker)==1 and CHECKOUT not in before,'one additional Apps8 public checkout')
 text=before.replace(marker,CHECKOUT+marker,1);anchor='--boot-packet "$GITHUB_WORKSPACE/boot79-native-inputs"';P.need(text.count(anchor)==2,'both actual baseline CLI lists');text=text.replace(anchor,anchor+OPERAND)
 control='python3 -I -B expanded604-code/latest/test_source.py';data_control='LATEST607_APPS8_TEST_PACKET="$GITHUB_WORKSPACE/latest607-apps8-inputs" '+control;P.need(text.count(control)==1,'one explicit public source-control DATA fixture');text=text.replace(control,data_control,1)
 P.need(text.replace(data_control,control,1).replace(CHECKOUT,'',1).replace(OPERAND,'')==before,'whole original568 workflow outside additional Apps8 carrier/argv')
 order(text);return text

def order(text):
 import latest_workflow as W
 held=W.order(text);rows=W.steps(text);matches=[i for i,r in enumerate(rows)if r['name']=='Checkout exact accepted Apps8 additional product DATA'];P.need(len(matches)==1 and rows[matches[0]]['body']==CHECKOUT,'exact additional checkout/source/path/action')
 commands=[r for r in rows if '--native-inputs'in r['body']or 'latest_run.py"'in r['body']]
 P.need(len(commands)==2 and all(r['body'].count(OPERAND)==1 for r in commands),'both real input/owner argv include exactly one Apps8 packet')
 consumers=[i for i,r in enumerate(rows)if 'LATEST607_APPS8_TEST_PACKET='in r['body']or '--native-inputs'in r['body']or 'latest_run.py"'in r['body']or '${{ secrets.'in r['body']or 'docker run'in r['body']or 'docker build'in r['body']]
 P.need(consumers and matches[0]<min(consumers),'additional public Apps8 dominates all consumers/private actors')
 return dict(original_five=held,apps8=matches[0],scope='SOURCE_STEP_AND_ACTUAL_ARGV_BINDING_ONLY')
