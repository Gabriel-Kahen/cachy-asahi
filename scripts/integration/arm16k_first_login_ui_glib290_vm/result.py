# SPDX-License-Identifier: MIT
"""Accept only joined full ARM seat, real GTK and exact trusted ALPM restoration."""
import re
FILES={'.config/fish/config.fish','.local/state/cachy-asahi/setup/lock','.local/state/cachy-asahi/setup/state.json','.zshrc'}
def accept_ui(value):
 user,root=value['client'],value['root'];assert user['status']=='PASS_REAL_SEAT_UI_CLIENT'and user['uid']==1000 and user['tty']=='/dev/tty1'
 assert user['removal_preserved_user_files']is True and user['private_X_server_and_session_bus_retired']is True
 gui=user['gui'];assert gui['status']=='PASS_REAL_INSTALLED_GTK_CONTROLS'and gui['uid']==1000 and set(gui['user_files'])==FILES
 for key in ['initial_inspect_read_only','preview_read_only','explicit_apply','repeat_apply_preserved_user_edit']:assert gui[key]is True
 rendering=gui['rendering'];assert rendering['display_type']=='GdkX11Display'and rendering['renderer_type']=='GskCairoRenderer'and 0<rendering['root_image_bytes']<=4*1024**2 and rendering['image_exported']is False and re.fullmatch('[0-9a-f]{64}',rendering['root_image_sha256'])
 assert root['status']=='PASS_UI_GUEST_ALPM_LIFECYCLE'and root['architecture']=='aarch64'and root['pagesize']==16384
 for key in ['baseline_inventory_restored','package_owned_nondirectory_paths_absent','original_PAM_policy_preserved','unrelated_user_file_preserved']:assert root[key]is True
 assert root['glib_rollback']=={'normal_trusted_ALPM':True,'exact_old_version':'2.88.3-1','old_archive_sha256':'a1498d94c3ff5e52ea157a09bb55bceaa7f94e47ded7c74ac5611d0e0b9b5ec8','ownership_checked':True,'new_only_paths_absent':True,'baseline_namespace_restored':True}
 assert root['installed']=={'status':'INSTALLED_EXACT_173_TOUCHED_172_ADDED_1_UPGRADED','baseline_count':111,'installed_count':283,'dependency_and_ownership_checks':True};assert root['user_files_preserved']==gui['user_files']
 assert root['trust']['private_keys']is False and root['trust']['freshness_or_production_acceptance']is False
 assert all(v in root['trust']['configuration']for v in ['Architecture = aarch64','SigLevel = Required TrustedOnly','LocalFileSigLevel = Required TrustedOnly'])
 session=root['client_session_corroboration'];assert session['pid']==user['pid']and session['process_session']==user['process_session'];props=session['login1'];assert props['Active']is True and props['Seat'][0]=='seat0'and props['User'][0]==1000 and props['TTY']=='tty1'and props['Service']=='login'and props['Remote']is False
 retired=user['owned_GUI_process_retirement'];assert retired['passed']is True and retired['group_census']=='EMPTY_TWICE'
 receipt=root['installation_receipt'];assert receipt['baseline_count']==111 and receipt['installed_count']==283 and receipt['archive_count']==173
 for key in ['trusted_ALPM_completed','exact_inventory','dependencies','ownership','project_hashes','filesystem_synced']:assert receipt[key]is True
 assert all(root['filesystem_sync'].get(k)is True for k in ['post-install','post-remove','post-rollback','terminal-pass'])
def join(seat,ui,nonce):
 accept_ui(ui);assert seat['status']=='PASS_ARM16K_VIRTIO_SEAT_REFERENCE_ONLY'and seat['nonce']==nonce and seat['architecture']=='aarch64'and seat['pagesize']==16384
 checks=seat['independent_checks'];assert set(checks)=={'bus-credentials','logind-session','process-vt','keyboard-record','gpu-record','seat-status'}and all(row['passed']is True for row in checks.values())
 assert seat['user']['logind']['Id']==ui['root']['client_session_corroboration']['login1']['Id']and seat['user']['process_session']==ui['client']['process_session'];return {'status':'PASS_EMULATED_ARM16K_GLIB290_REAL_SEAT_UI_LIFECYCLE_ONLY','foundation':seat,'ui_journey':ui,'native_M2_release':'NOT RUN'}
