# SPDX-License-Identifier: MIT
"""Passive fixed workflow/transport contract; no YAML execution or actor calls."""
import hashlib
from pathlib import Path
import re
HERE=Path(__file__).resolve().parent
REFERENCE=HERE.parent/'offline-source-builder-native/workflow.yml.in'
REFERENCE_SHA='098e54dc3a246065e07dfdcad89635ff03085a1f251d742f66cca60247078669'
ALIASES=('.github/workflows/native-arm-build.yml','.github/workflows/native-arm-zlib-pgo.yml')
TRANSPORT_STEP='Transport complete retained DATA directly outside the closed source'
STEP_MINUTES=(1,1,2,2,1,1,9,40,65,6,4,2)
PHASE_ROLES={'input-transport':'RETAINED_INPUT_TRANSPORT_DATA','bootstrap':'ORIGINAL341_PRODUCER',
 'pairs':'PGO_CANDIDATE_CONSUMERS','cleanup':'OWNED_CONSUMER_THEN_PRODUCER_RETIREMENT','retain':'BOUNDED_DATA_READER'}
SECRET_NAMES={
 'CACHY_RETAINED_BUBBLEWRAP_V1_PACKAGE_01','CACHY_RETAINED_BUBBLEWRAP_V1_PACKAGE_02','CACHY_RETAINED_BUBBLEWRAP_V1_SIGNATURE_01',
 *{'CACHY_OLD_FOUR_JBIGKIT_'+f'{i:02d}'for i in(1,2)},'CACHY_OLD_FOUR_JBIGKIT_SIG_01',
 *{'CACHY_OLD_FOUR_LIBTIFF_'+f'{i:02d}'for i in range(1,16)},'CACHY_OLD_FOUR_LIBTIFF_SIG_01'}


def need(ok,message):
    if not ok:raise ValueError(message)


def steps(text):
    head,*rows=re.split(r'(?=      - name: )',text)
    return head,[(row.splitlines()[0].split('- name: ',1)[1],row)for row in rows]


def transport_layout(text):
    first=text.index('      - name: Checkout complete original retained package inputs\n')
    bootstrap=text.index('      - name: Build fresh signed original341 producer with genuine image and package lock\n',first)
    after=text.index('      - name: Build two independent PGO candidates from fresh producer receipts\n',bootstrap)
    phase=text[bootstrap:after]
    phase=phase.replace('      - name: Build fresh signed original341 producer with genuine image and package lock\n',
        '      - name: '+TRANSPORT_STEP+'\n        id: transport\n',1)
    phase=phase.replace('timeout-minutes: 40','timeout-minutes: 9',1).replace('2300s','500s',1)
    phase=phase.replace('"$SLICE/owner.py" bootstrap','"$SLICE/owner.py" transport',1)
    phase=phase.replace('          set -euo pipefail\n',
        '          set -euo pipefail\n          set -o noclobber\n          transport_stream="$RUNNER_TEMP/pgo-hosted-work/input-transport"\n          set +e\n',1)
    phase=phase.replace('            --carrier "$RUNNER_TEMP/pgo-hosted-retained" --execute\n',
        '            --carrier "$RUNNER_TEMP/pgo-hosted-retained" --execute >"${transport_stream}.stdout" 2>"${transport_stream}.stderr"\n'
        '          transport_exit=$?\n          set -e\n          printf \'%s\\n\' "$transport_exit" >"${transport_stream}.exit-code"\n          exit "$transport_exit"\n',1)
    text=text[:first]+phase+text[bootstrap:]
    head,rows=steps(text);need(len(rows)==len(STEP_MINUTES),'complete transport schedule')
    result=head
    for (name,row),minutes in zip(rows,STEP_MINUTES):
        row,count=re.subn(r'^        timeout-minutes: [0-9]+$',f'        timeout-minutes: {minutes}',row,count=1,flags=re.M)
        need(count==1,'one outer step budget: '+name);result+=row
    return result


def derive(reference):
    need(hashlib.sha256(reference.encode()).hexdigest()==REFERENCE_SHA,'exact accepted source38 workflow reference')
    head,rows=steps(reference)
    head=re.sub(r'      feature_code_sha:\n(?:        .*\n){3}','',head)
    head=head.replace('      FEATURE_CODE_SHA: ${{ inputs.feature_code_sha }}\n','')
    excluded={'Checkout the exact canonical feature-code commit','Bind the exact feature checkout and seven reviewed tool files before secrets'}
    text=head+''.join(row for name,row in rows if name not in excluded)
    text=text.replace('native-arm-offline-source-builder','native-arm-zlib-pgo').replace('scripts/ci/offline-source-builder-native','scripts/ci/zlib-pgo-native-hosted')
    text=text.replace('    timeout-minutes: 95\n','    timeout-minutes: 135\n')
    text=text.replace('          [[ "$FEATURE_CODE_SHA" =~ ^[0-9a-f]{40}$ ]]\n','')
    text=text.replace(' FEATURE_CODE_SHA="$FEATURE_CODE_SHA"','').replace(' --feature-code-sha "$FEATURE_CODE_SHA"','')
    for old,new in [('offline-source-home','pgo-hosted-home'),('offline-source-proof.json','pgo-hosted-proof.json'),('offline-source-work','pgo-hosted-work'),('offline-source-public','pgo-hosted-public'),('offline-source-retained','pgo-hosted-retained')]:text=text.replace(old,new)
    for old,new in [
      ('Prove exact offline-builder source and workflow aliases before secrets','Prove complete hosted PGO source Git blobs and workflow aliases before secrets'),
      ('Run focused offline-builder source and owner controls before secrets','Run new hosted PGO source owner and retention controls before secrets'),
      ('Build fresh signed original341 environment for offline builds','Build fresh signed original341 producer with genuine image and package lock'),
      ('Build the pinned recipe twice offline and compare actual artifacts','Build two independent PGO candidates from fresh producer receipts'),
      ('Retain bounded public offline-builder evidence','Retain bounded complete public PGO evidence including nested profiles')]:text=text.replace(old,new)
    text=text.replace('        timeout-minutes: 27\n','        timeout-minutes: 65\n').replace('1500s','3850s')
    text=text.replace('# Two independent native builds use the exact feature-code SHA and signed341 image.','# Each independent candidate binds the fresh owned image and full emitted341 lock.')
    cleanup=text.index('      - name: Retire only owned build containers before original341 producer')
    start=text.index('      - name: Retain bounded complete public PGO evidence including nested profiles')
    text=text[:cleanup]+text[cleanup:start].replace('        timeout-minutes: 3\n','        timeout-minutes: 6\n',1).replace('150s','320s',1)+text[start:]
    start=text.index('      - name: Retain bounded complete public PGO evidence including nested profiles')
    text=text[:start]+text[start:].replace('        timeout-minutes: 3\n','        timeout-minutes: 4\n',1).replace('150s','200s',1)
    text=text.replace('name: offline-source-builder-native-${{ github.run_id }}-${{ github.run_attempt }}','name: zlib-pgo-native-${{ github.run_id }}-${{ github.run_attempt }}')
    text=text.replace("-p 'test_*.py'","-p 'test_owned*.py'")
    need('FEATURE_CODE'not in text and 'feature_code_sha'not in text,'single exact source checkout')
    return transport_layout(text)


def validate(text=None,reference=None):
    text=(HERE/'workflow.yml.in').read_text()if text is None else text
    reference=REFERENCE.read_text()if reference is None else reference
    need(text==derive(reference),'reviewed complete PGO workflow differs')
    head,rows=steps(text);names=[name for name,_ in rows]
    need(len(rows)==12 and len(names)==len(set(names)),'twelve unique fixed steps')
    inputs=head.split('    inputs:\n',1)[1].split('permissions:',1)[0]
    need(re.findall(r'^      ([a-z_]+):$',inputs,re.M)==['source_sha']and'default:'not in inputs,'one required source SHA without defaults')
    checkout=rows[0][1];proof=rows[1][1];controls=rows[2][1]
    need('ref: ${{ inputs.source_sha }}'in checkout and'persist-credentials: false'in checkout,'explicit source checkout without credentials')
    need(all(token in proof for token in('"$(git rev-parse HEAD)" = "$SOURCE_SHA"','"$GITHUB_SHA" = "$SOURCE_SHA"','"$GITHUB_WORKFLOW_SHA" = "$SOURCE_SHA"','cmp --silent '+ALIASES[0]+' '+ALIASES[1],"'@OWNER_SHA@'", "'@MAP_SHA@'")),'presecret source/workflow identity proof')
    secret_rows=[(i,row)for i,(_,row)in enumerate(rows)if'secrets.'in row]
    need(len(secret_rows)==1 and secret_rows[0][0]==3,'existing private transport after source proof and focused controls')
    secrets=set(re.findall(r'\$\{\{ secrets\.([A-Z0-9_]+) \}\}',text))
    need(secrets==SECRET_NAMES and len(secrets)==22,'exact existing22 secret references; no new credentials')
    original_seed=next(row for name,row in steps(reference)[1]if name=='Seed the six exact retained inputs using existing secrets only')
    need(secret_rows[0][1]==original_seed,'accepted retained seed step held byte-for-byte')
    need('discover -s "$SLICE" -p \'test_owned*.py\''in controls and'34'not in controls,'only new hosted controls; no frozen PGO rerun')
    transport=rows[6][1];bootstrap=rows[7][1];pairs=rows[8][1];cleanup=rows[9][1];retain=rows[10][1];upload=rows[11][1]
    need(names[6]==TRANSPORT_STEP and 'id: transport'in transport and 'owner.py" transport'in transport,'source-owned retained DATA transport before producer')
    need('500s'in transport and '--kill-after=30s'in transport and 'timeout-minutes: 9'in transport,'finite480/500/530/540 transport hierarchy')
    need('--carrier "$RUNNER_TEMP/pgo-hosted-retained" --execute'in transport and 'path: source-retained'not in text and '$GITHUB_WORKSPACE/source-retained'not in text,'retained DATA never enters closed source')
    need(all(token in transport for token in('set -o noclobber','set +e','transport_exit=$?','set -e','exit "$transport_exit"','${transport_stream}.stdout','${transport_stream}.stderr','${transport_stream}.exit-code')),'exclusive raw transport streams and exact wrapper exit preserved')
    need('owner.py" bootstrap'in bootstrap and'--carrier "$RUNNER_TEMP/pgo-hosted-retained" --execute'in bootstrap,'fresh producer entrypoint')
    need('owner.py" pairs'in pairs and'3850s'in pairs and'--image'not in text and'--expected-packages'not in text,'image and full lock come from runtime producer, never workflow inputs')
    need(all("if: always() && steps.proof.outcome == 'success'"in row for row in(cleanup,retain)),'cleanup and retention on any post-proof outcome')
    need('owner.py" cleanup'in cleanup and'owner.py" retain'in retain and'if: always()'in upload,'ordered cleanup then retain then upload')
    need('name: zlib-pgo-native-${{ github.run_id }}-${{ github.run_attempt }}'in upload and'${{ runner.temp }}/pgo-hosted-public/'in upload,'closed public artifact selection')
    for row in(proof,transport,bootstrap,pairs,cleanup,retain):need('env -i 'in row and'FEATURE_'not in row,'clean owner environment')
    caps=[int(v)for v in re.findall(r'^        timeout-minutes: ([0-9]+)$',text,re.M)]
    need(tuple(caps)==STEP_MINUTES and sum(caps)==134 and'    timeout-minutes: 135\n'in head,'finite134-minute declared schedule under unchanged135-minute job')
    return dict(status='PASS_FIXED_PGO_HOSTED_WORKFLOW_CONTRACT',steps=12,existing_private_secret_references=22,
        job_minutes=135,sum_step_minutes=134,transport_actor_seconds=480,transport_fetch_seconds=400,
        transport_wrapper_seconds=500,transport_kill_grace_seconds=30,transport_outer_seconds=540,
        phase_roles=dict(PHASE_ROLES),checkout='EXACT_SINGLE_SOURCE_SHA',actual=None,native_execution='NOT RUN',
        workflow_name='native-arm-zlib-pgo',artifact_prefix='zlib-pgo-native-',aliases=list(ALIASES))


def dispatch_contract(source_sha):
    need(type(source_sha)is str and re.fullmatch('[0-9a-f]{40}',source_sha)and source_sha!='0'*40,'concrete published source SHA required')
    return dict(workflow=ALIASES[0],dedicated_alias=ALIASES[1],workflow_name='native-arm-zlib-pgo',inputs=dict(source_sha=source_sha),
        required_equalities=['dispatch ref HEAD','source_sha','GITHUB_SHA','GITHUB_WORKFLOW_SHA','both alias bytes from complete source map'],
        image='FRESH_OWNED_PRODUCER_RUNTIME_RECEIPT_ONLY',packages='FULL_FRESH_PRODUCER_PACKAGES_LOCK_ONLY',actual=None,dispatch='NOT RUN')


def render(owner_sha,map_sha,text=None):
    for value in(owner_sha,map_sha):need(type(value)is str and re.fullmatch('[0-9a-f]{64}',value)and value!='0'*64,'concrete source hash required')
    text=(HERE/'workflow.yml.in').read_text()if text is None else text;validate(text)
    return text.replace('@OWNER_SHA@',owner_sha).replace('@MAP_SHA@',map_sha).encode()


def check_aliases(aliases,owner_sha,map_sha):
    need(type(aliases)is dict and set(aliases)==set(ALIASES),'complete registered and dedicated aliases')
    expected=render(owner_sha,map_sha)
    need(all(type(body)is bytes and body==expected for body in aliases.values()),'alias bytes must equal source-bound template')
    return dict(status='PASS_REGISTERED_AND_DEDICATED_WORKFLOW_BYTES',aliases=list(ALIASES),bytes=len(expected))
