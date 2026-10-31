#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
"""Explicit offline-source v2 adapter for the existing finite batch scheduler."""
import argparse
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = next(p for p in Path(__file__).resolve().parents if (p/'scripts/build/build_v2.py').is_file())
INTERFACE = 'offline-build-v2'
KIND = 'PINNED_OCI_BUILD_V2_OFFLINE_SOURCES'
V2_FILES = ('scripts/build/build_v2.py', 'scripts/build/compare_v2.py',
    'scripts/build/container-entry-v2.sh', 'scripts/build/source_materials.py',
    'scripts/maintenance/source_cache.py', 'scripts/release/source_delivery.py')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value


B = load('offline_v2_batch_legacy', ROOT/'scripts/maintenance/build_batch.py')
SM = load('offline_v2_batch_materials', ROOT/'scripts/build/source_materials.py')
need = B.need
encoded = B.encoded


def interface(value):
    need(value == INTERFACE, 'explicit offline-build-v2 interface required')


def dependencies(planner):
    result = B.dependencies(planner)
    result.update({str(ROOT/p):B.digest(ROOT/p) for p in V2_FILES})
    result[str(Path(__file__).resolve())] = B.digest(__file__)
    return result


def selection(prepared):
    return dict(schema_version=1, purpose='offline-build-sources',
        plan_sha256=B.sha(prepared['plan_raw']), catalog_sha256=prepared['plan']['catalog_sha256'],
        recipe_inputs=prepared['plan']['recipe_inputs'], sources=prepared['selected'],
        legal_acceptance=False, source_completeness_accepted=False)


def material_files(prepared):
    chosen = selection(prepared)
    result = {'source-plan.json':B.sha(prepared['plan_raw']),
        'source-catalog.json':B.sha(prepared['catalog_raw']), 'selection.json':B.sha(encoded(chosen))}
    for item in prepared['selected']:
        row = item['record']; material = row['material']
        receipt = dict(schema_version=1, purpose='source-cache-receipt',
            inputs_sha256=chosen['catalog_sha256'], source=row,
            object_path='objects/'+material['sha256'], legal_acceptance=False,
            source_completeness_accepted=False)
        result['srcdest/'+item['filename']] = material['sha256']
        result['receipts/'+material['id']+'.json'] = B.sha(encoded(receipt))
    result.update({'notices/'+key:B.sha(body) for key,body in prepared['notices'].items()})
    return result


def source_dependencies(binding, prepared):
    expected = {binding['source_plan']:B.sha(prepared['plan_raw']),
        binding['source_catalog']:prepared['plan']['catalog_sha256'],
        str(Path(binding['source_cache'])/'FORMAT'):B.sha(SM.cache.MARKER)}
    for item in prepared['selected']:
        row = item['record']; material = row['material']
        expected[str(Path(binding['source_cache'])/'objects'/material['sha256'])] = material['sha256']
        receipt = dict(schema_version=1, purpose='source-cache-receipt',
            inputs_sha256=prepared['plan']['catalog_sha256'], source=row,
            object_path='objects/'+material['sha256'], legal_acceptance=False,
            source_completeness_accepted=False)
        receipt_path = Path(binding['source_cache'])/'receipts'/(prepared['plan']['catalog_sha256']+'-'+material['id']+'.json')
        expected[str(receipt_path)] = B.sha(encoded(receipt))
        for notice in row['license_evidence']:
            expected[str(Path(binding['source_catalog']).parent/notice['path'])] = notice['sha256']
    result = {}
    for path,checksum in expected.items():
        path = str(B.regular(path))
        need(B.digest(path)==checksum, 'source dependency changed after preparation: '+path)
        result[path] = checksum
    return result


def prepare_task(task):
    binding = task['offline_sources']
    build = B.module('offline_batch_reviewed_v2', ROOT/'scripts/build/build_v2.py')
    report = build.recipe(Path(task['recipe'])/'PKGBUILD')
    return SM.prepare(report, binding['source_plan'], binding['source_plan_sha256'],
                      binding['source_catalog'], binding['source_cache'])


def admission(input_path, input_sha, config_path, config_sha, planner_path, planner_sha,
              sources_path, sources_sha, *, builder_interface):
    interface(builder_interface)
    before = dependencies(planner_path)
    bindings = B.selected(sources_path, sources_sha)
    B.fields(bindings, 'schema_version builder_interface tasks')
    need(type(bindings['schema_version']) is int and bindings['schema_version']==1, 'v2 bindings schema')
    interface(bindings['builder_interface'])
    admit = B.admission(input_path,input_sha,config_path,config_sha,planner_path,planner_sha)
    need(not admit['global_holds'] and all(not g['held'] for g in admit['groups']), 'finite offline batch has planner/dependency/provider holds')
    need(type(bindings['tasks']) is dict and set(bindings['tasks']) == set(admit['tasks']), 'exact offline source task coverage required')
    external = {str(B.regular(p)):B.digest(p) for p in (input_path,config_path,sources_path)}
    for name,task in admit['tasks'].items():
        binding = dict(bindings['tasks'][name])
        B.fields(binding,'source_plan source_plan_sha256 source_catalog source_cache')
        for key in ('source_plan','source_catalog'):
            binding[key] = str(B.regular(binding[key]))
        directory = Path(binding['source_cache']).absolute()
        need(directory == directory.resolve() and directory.is_dir(), 'existing nonsymlink source cache required')
        binding['source_cache'] = str(directory)
        task['offline_sources'] = binding
        prepared = prepare_task(task)
        binding['catalog_sha256'] = prepared['plan']['catalog_sha256']
        task['source_material'] = selection(prepared)
        task['source_material_files'] = material_files(prepared)
        for path,checksum in source_dependencies(binding,prepared).items():
            need(path not in external or external[path]==checksum, 'source dependency changed during admission')
            external[path] = checksum
    need(dependencies(planner_path)==before, 'v2 implementation changed during admission')
    need(all(B.digest(p)==checksum for p,checksum in external.items()), 'reviewed source dependency changed during admission')
    B.selected(sources_path,sources_sha)
    admit['implementation'].update(before);admit['implementation'].update(external)
    admit.update(builder_interface=INTERFACE, sources_sha256=sources_sha,
        dependency_bytes_delivery='REVIEWED_PREEXISTING_IMAGES_AND_OFFLINE_SOURCE_CACHE_ONLY')
    return admit


def verify_material(task, output):
    """Validate complete retained source evidence without accessing the old cache."""
    output = Path(output)
    tree = B.snapshot(output/'source-material')
    need(tree == task['source_material_files'], 'retained source-material tree differs from admission')
    expected = task['source_material']
    need(B.read(output/'source-material/selection.json')==encoded(expected), 'retained source selection differs')
    record = B.decode(B.read(output/'provenance.json'))
    need(encoded(record.get('source_material'))==encoded(expected), 'source-material provenance differs')
    for name,checksum in tree.items():
        need(record.get('files',{}).get('source-material/'+name)==checksum,
             'source-material absent/different in build provenance: '+name)
    return expected


class Builder(B.Builder):
    kind = KIND

    def __init__(self, admit):
        self.admit = admit

    def start(self, task, output, log, lock_fd):
        B.revalidate(self.admit,task)
        prepared = prepare_task(task)
        need(encoded(selection(prepared))==encoded(task['source_material']) and
             material_files(prepared)==task['source_material_files'], 'offline source selection drift before launch')
        binding = task['offline_sources']
        command = [sys.executable,'-B',str(ROOT/'scripts/build/build_v2.py'),task['recipe'],
            '--image',task['image'],'--output',str(output),'--mode',task['mode'],
            '--source-date-epoch',str(task['source_date_epoch']),'--network','none',
            '--timeout',str(task['timeout']),'--expected-packages',task['expected_packages'],
            '--reviewed-inputs',task['reviewed_inputs'],'--source-plan',binding['source_plan'],
            '--source-plan-sha256',binding['source_plan_sha256'],'--source-catalog',binding['source_catalog'],
            '--source-cache',binding['source_cache']]
        return subprocess.Popen(command,stdout=log,stderr=subprocess.STDOUT,start_new_session=True,pass_fds=(lock_fd,))

    def verify(self, task, output):
        B.revalidate(self.admit,task)
        prepared = prepare_task(task)
        need(encoded(selection(prepared))==encoded(task['source_material']) and
             material_files(prepared)==task['source_material_files'], 'offline source selection drift after build')
        tree = B.snapshot(output)
        compare = B.module('offline_batch_compare_v2',ROOT/'scripts/build/compare_v2.py')
        record,reports = compare.verify(output)
        build = B.module('offline_batch_result_v2',ROOT/'scripts/build/build_v2.py')
        expected = dict(recipe_metadata=build.recipe(Path(task['recipe'])/'PKGBUILD')['metadata'],
            image=task['image'],mode=task['mode'],source_date_epoch=task['source_date_epoch'],
            recipe_inputs=task['recipe_inputs'],expected_packages_sha256=task['expected_packages_sha256'],
            entry_script_sha256=B.digest(ROOT/'scripts/build/container-entry-v2.sh'),network='none')
        need(all(encoded(record.get(k))==encoded(v) for k,v in expected.items()), 'v2 result does not match admitted inputs')
        verify_material(task,output)
        need(B.decode(B.read(output/'validation.json')).get('errors')==[], 'v2 recorded validation errors')
        need(len(reports)==1, 'one v2 package result required')
        need(B.read(output/'artifacts/packages.lock')==B.read(task['expected_packages']), 'v2 result lock mismatch')
        need(B.snapshot(output)==tree, 'v2 result changed during verification')
        B.revalidate(self.admit,task)
        return next(iter(record['artifacts'].values()))

    def cleanup(self, task, output):
        path = output/'provenance.json'
        if not path.exists():return
        record = B.decode(B.read(path));name = record.get('clean_environment_id')
        if name is None:return
        need(type(name) is str and re.fullmatch('cachy-asahi-[0-9a-f]{16}',name), 'invalid owned v2 container')
        need(type(record.get('image_id')) is str and re.fullmatch('sha256:[0-9a-f]{64}',record['image_id']), 'owned v2 image identity missing')
        verify_material(task,output)
        mounts = {(str(output/'inputs'),'/inputs',False),(str(output/'artifacts'),'/out',True),
            (str(ROOT/'scripts/build/container-entry-v2.sh'),'/builder-entry.sh',False),
            (str(output/'expected-packages.lock'),'/expected-packages.lock',False),
            (str(output/'source-material/srcdest'),'/offline-sources',False)}
        expected = {'type=bind,src='+s+',dst='+d+(''if rw else',readonly')for s,d,rw in mounts}
        command = record.get('command',[])
        need(type(command)is list and command[:5]==['docker','run','--rm','--name',name]and
             command[-2]==task['image']and record.get('image')==task['image']and
             {command[i+1]for i,arg in enumerate(command[:-1])if arg=='--mount'}==expected,
             'v2 cleanup command/image/mount ownership mismatch')
        def absent():
            result=subprocess.run(['docker','ps','-aq','--filter','name=^/'+name+'$'],capture_output=True,timeout=30,text=True)
            need(result.returncode==0 and not result.stdout.strip(),'owned v2 container absence not established')
        result=subprocess.run(['docker','container','inspect',name],capture_output=True,timeout=30,text=True)
        if result.returncode!=0:absent();return
        items=B.decode(result.stdout.encode());need(type(items)is list and len(items)==1,'v2 cleanup inspect identity missing')
        actual=items[0];actual_mounts=actual.get('Mounts',[])
        binds={(p.get('Source'),p.get('Destination'),p.get('RW'))for p in actual_mounts if p.get('Type')=='bind'}
        other=all(p.get('Type')=='bind'or(p.get('Type')=='tmpfs'and p.get('Destination')=='/tmp'and p.get('RW')is True)for p in actual_mounts)
        need(actual.get('Name')=='/'+name and actual.get('Config',{}).get('Image')==task['image']and actual.get('Image')==record['image_id']and binds==mounts and other,
             'live v2 container ownership differs')
        removed=subprocess.run(['docker','rm','-f',name],capture_output=True,timeout=30,text=True)
        need(removed.returncode==0,'owned v2 container removal failed');absent()


def run(admit, output, resume=False, retry=(), builder=None, stop=None, *, builder_interface):
    interface(builder_interface);interface(admit.get('builder_interface'))
    output=Path(output).absolute()
    for task in admit['tasks'].values():
        cache=Path(task['offline_sources']['source_cache'])
        need(not(output==cache or output.is_relative_to(cache)or cache.is_relative_to(output)), 'batch output overlaps source cache')
    return B.run(admit,output,resume,retry,builder or Builder(admit),stop)


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action',choices=('plan','execute'))
    parser.add_argument('--builder-interface',required=True,choices=(INTERFACE,))
    for name in ('input','config','planner','sources'):
        parser.add_argument('--'+name,type=Path,required=True);parser.add_argument('--'+name+'-sha256',required=True)
    parser.add_argument('--admission-sha256');parser.add_argument('--output',type=Path)
    parser.add_argument('--resume',action='store_true');parser.add_argument('--retry',action='append',default=[])
    args=parser.parse_args(argv)
    try:
        admit=admission(args.input,args.input_sha256,args.config,args.config_sha256,args.planner,args.planner_sha256,args.sources,args.sources_sha256,builder_interface=args.builder_interface)
        need(len(encoded(admit))<=B.MAX_JSON,'v2 admission byte bound')
        if args.action=='plan':
            need(not(args.resume or args.retry or args.output or args.admission_sha256),'v2 execution options require execute')
            sys.stdout.buffer.write(encoded(admit));return 0
        need(args.output is not None and args.admission_sha256==B.sha(encoded(admit)), 'v2 execute needs selected admission hash and output')
        result=run(admit,args.output,args.resume,args.retry,builder_interface=args.builder_interface)
        print(json.dumps({'status':result['status'],'kind':KIND,'output':str(args.output.absolute())},sort_keys=True))
        return 0 if result['status']in('COMPLETE','NO_WORK')else 1
    except (OSError,ValueError,KeyError,TypeError,IndexError,argparse.ArgumentTypeError,subprocess.SubprocessError)as error:
        print('offline batch v2: '+str(error),file=sys.stderr);return 2


if __name__=='__main__':sys.exit(main())
