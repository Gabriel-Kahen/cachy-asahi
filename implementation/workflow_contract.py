# SPDX-License-Identifier: MIT
"""Finite whole574 workflow inverse and exact independent presecret command scalars."""
import hashlib,json

def need(ok,why):
 if not ok:raise ValueError(why)
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def derive(raw):
 text=raw.decode();seams=[]
 def change(a,b,count=1):
  nonlocal text
  need(a!=b and text.count(a)==count,'fixed workflow seam '+a[:100]);text=text.replace(a,b);seams.append(dict(before=a,after=b,count=count))
 change('gui606-source','gui607-source/parent574',20)
 change('"path": "gui607-source/parent574"','"path": "gui607-source"')
 change('"CURRENT": "gui607-source/parent574/native.py"','"CURRENT": "gui607-source/implementation/native.py"')
 change('native-arm-current606-welcome8-gui','native-arm-latest607-welcome8-gui')
 change('current606-welcome8-gui-${{ inputs.profile }}','latest607-welcome8-gui-${{ inputs.profile }}',2)
 old='--apps16 \\"$GITHUB_WORKSPACE/apps16-inputs\\"';change(old,old+' --six-record \\"$GITHUB_WORKSPACE/six22-inputs\\" --six-public \\"$RUNNER_TEMP/six991-inputs\\"')
 anchor='      -\n        "name": "Prove and assemble original immutable GUI native input roles"'
 record='''      - name: Checkout exact issued Six22 historical input record
        uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        timeout-minutes: 2
        with:
          ref: eea3f3022c9214deacc60c92dfca13704420756b
          path: six22-inputs
          persist-credentials: false
      - name: Stage exact original991 historical DATA without acquisition
        timeout-minutes: 2
        run: python3 -I -B gui607-source/implementation/stage_inputs.py --record "$GITHUB_WORKSPACE/six22-inputs" --output "$RUNNER_TEMP/six991-inputs"
''';change(anchor,record+anchor)
 anchor='      -\n        "name": "Whole source and original GUI source/refusal controls before secrets"'
 control='''      - name: Latest607 typed target and full source controls before secrets
        timeout-minutes: 3
        run: python3 -I -B -Werror gui607-source/implementation/test_source.py --record "$GITHUB_WORKSPACE/six22-inputs" --public "$RUNNER_TEMP/six991-inputs" --assets "$RUNNER_TEMP/welcome5-assets"
''';change(anchor,control+anchor)
 old='python3 -I -B gui607-source/parent574/apps16_common.py\npython3 -I -B gui607-source/parent574/service_controls.py';change(old,old.replace('\n','\\n'))
 back=text
 for row in reversed(seams):need(back.count(row['after'])==row['count'],'whole workflow inverse count');back=back.replace(row['after'],row['before'])
 need(back.encode()==raw,'entire574 workflow inverse');return text.encode(),dict(before=pin(raw),after=pin(text.encode()),seams=seams,whole_inverse=True,old574_control_omission='LITERAL_YAML_NEWLINE_FOLDED_SERVICE_CONTROL_INTO_PRECEDING_COMMAND',new_control_execution='FIVE_EXACT_SEPARATE_SOURCE_OWNED_LINES')

def commands(raw):
 text=raw.decode();name='        "name": "Whole source and original GUI source/refusal controls before secrets"';start=text.index('        "run": ',text.index(name))+len('        "run": ');end=text.index('\n        "env":',start);scalar=text[start:end];value=json.loads(scalar);need(scalar==json.dumps(value,ensure_ascii=True),'one exact canonical quoted JSON/YAML run scalar')
 expected=['python3 -I -B "$CURRENT" preflight','python3 -I -B gui607-source/parent574/apps16_common.py','python3 -I -B gui607-source/parent574/service_controls.py','python3 -I -B "$SLICE/test_lane.py"','python3 -I -B gui607-source/parent574/original/scripts/ci/test_maintained_desktop574.py'];need(value.splitlines()==expected and all(value.splitlines().count(s)==1 for s in expected),'each required current/default/source/refusal control exactly once on its own line')
 return expected

# The original five independent presecret controls retain order and all clocks.
_HISTORICAL_OLD_LINE='python3 -I -B "$SLICE/test_lane.py"'
_HISTORICAL_NEW_LINE='python3 -I -B gui607-source/implementation/historical_source.py legacy-source-tests --source "$GITHUB_WORKSPACE/gui607-source" --assets "$RUNNER_TEMP/welcome5-assets"'
_historical_prior_derive=derive
_historical_prior_commands=commands

def derive(raw):
 value,proof=_historical_prior_derive(raw);a=json.dumps(_HISTORICAL_OLD_LINE)[1:-1];b=json.dumps(_HISTORICAL_NEW_LINE)[1:-1]
 need(value.count(a.encode())==1,'one explicit historical source-suite command');after=value.replace(a.encode(),b.encode(),1)
 need(after.replace(b.encode(),a.encode(),1)==value,'entire historical source-suite workflow inverse')
 proof=dict(proof,after=pin(after),seams=proof['seams']+[dict(before=a,after=b,count=1)],historical_source_scope='SOURCE_ONLY_NOT_CURRENT_SIGNATURE_AUTHORITY')
 return after,proof

def commands(raw):
 a=json.dumps(_HISTORICAL_OLD_LINE)[1:-1].encode();b=json.dumps(_HISTORICAL_NEW_LINE)[1:-1].encode()
 need(raw.count(b)==1 and raw.count(a)==0,'only source suite uses the historical worker')
 rows=_historical_prior_commands(raw.replace(b,a,1))
 return [_HISTORICAL_NEW_LINE if row==_HISTORICAL_OLD_LINE else row for row in rows]
