# SPDX-License-Identifier: MIT
"""Strict completed copy/preservation DATA verifier; explicitly rejects updates."""
BEFORE = '72818a8a2ae488281b08486b92c435ec244ef3b5313f23b97473d1684ecb68b4'
PURPOSE='generic16k-fullcopy-capacity'
def need(ok,why):
 if not ok:raise ValueError(why)
def verify(row,case):
 need(case=='normal','capacity internal case only')
 need(row.get('status')=='PASS'and type(row.get('package_count'))is int and row['package_count']==row.get('final_package_count')==607 and row.get('installed_inventory_sha256')==row.get('final_inventory_sha256')==BEFORE and row.get('dependency_checks')=='PASS-no-waivers'and row.get('payload_ownership')=='PASS','full actual607 outer dependency/payload preservation')
 hook=row['full_root_upgrade'];driver=hook['driver']
 need(hook['status']=='PASS'and hook['scope']=='FULL_COPY_CAPACITY_DATA_NOT_ACCEPTANCE'and hook['persistent_source_preserved']is True and hook['persistent_source']['source_manifest_sha256']==hook['persistent_source_after']['source_manifest_sha256'],'complete original source preservation required')
 for value in(hook,driver):
  need(type(value.get('committed_transactions'))is int and value['committed_transactions']==0 and all(value.get(k)is False for k in('commit_started','packages_committed','checkpoint_changed')),'capacity cannot report transaction/checkpoint commit')
 need(driver['status']=='PASS'and driver['scope']=='FULL_COPY_CAPACITY_DATA_NOT_ACCEPTANCE'and driver['copy_cleanup']=='PASS-owned-workspace-removed'and driver['initialization_started']is False and driver['root_initialized']is False and driver['acceptance']is False and driver['normal_updater_acceptance']is False,'copy-only result and verified cleanup')
 need(driver.get('initial_copy_byte_identical')is True and driver['copy']['copy_complete']is True,'complete byte-identical measured copy')
 cleanup=driver['capacity_cleanup'];need(cleanup['status']=='PASS'and cleanup['workspace_absence_verified']is True and[entry['role']for entry in cleanup['ordered']]==['copy_workspace','control_lease']and cleanup['ordered'][0]['status']=='PASS-owned-workspace-removed'and cleanup['ordered'][1]['status']=='PASS_OWNED_CONTROL_LEASE_REMOVED','ordered owned workspace then lease disposal')
 trace=driver['capacity_telemetry'];need(trace['purpose']==PURPOSE and trace['closed']is True and trace['acceptance']is trace['updater_acceptance']is False and trace['totals_available']is True,'closed mandatory capacity DATA')
 totals=trace['source_totals'];need(type(totals)is dict and set(totals)=={'groups','members','copy_bytes','logical_bytes','nodes','directories','symlinks'}and all(type(v)is int and 0<=v<2**63 for v in totals.values()),'complete actual source denominator')
 events=trace['events'];need(type(events)is list and 0<len(events)<=96 and trace['event_count']==len(events),'bounded whole capacity telemetry')
 need([e['sequence']for e in events]==list(range(1,len(events)+1)),'complete mandatory capacity event sequence')
 for event in events:need(type(event['elapsed_ns'])is int and event['elapsed_ns']>=0 and type(event['cpu_ns'])is int and event['cpu_ns']>=0,'typed actual capacity clocks')
 needed=('SOURCE_BEFORE','CAPACITY_AND_DESTINATION_OPEN','DIRECTORIES','REGULAR_FILES','SYMLINKS','DIRECTORY_METADATA','DESTINATION_OBSERVE','SOURCE_AFTER','FINAL_ROOT_CHECKS','COMPLETE')
 points=[e['phase']for e in events if e['event']=='POINT'];cursor=-1
 for phase in needed:
  matches=[i for i,p in enumerate(points)if p==phase and i>cursor];need(bool(matches),'all original complete-copy phase points');cursor=matches[0]
 ends=[e for e in events if e['phase']=='COPY'and e['event']=='END'];need(len(ends)==1,'one complete actual copy endpoint')
 final=ends[0]['counters'];need(final['completed_groups']==totals['groups']and final['completed_members']==totals['members']and final['completed_bytes']==totals['copy_bytes'],'complete regular-group work plus later copy phases')
 need(len(driver['observations'])==3 and[o['phase']for o in driver['observations']]==['SOURCE_BEFORE','DESTINATION','SOURCE_AFTER'],'all original fresh snapshot/checkpoint/DB observations')
 for observed in driver['observations']:need(observed['package_count']==607 and observed['inventory_sha256']==BEFORE,'exact607 raw DB and payload observations')
 return hook
