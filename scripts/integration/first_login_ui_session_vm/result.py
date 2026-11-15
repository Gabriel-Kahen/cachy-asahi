# SPDX-License-Identifier: MIT
"""Require both real user GTK actions and independent root ALPM restoration."""
def accept(value):
    user, root = value['client'], value['root']
    assert user['status']=='PASS_REAL_SEAT_UI_CLIENT' and user['uid']==1000 and user['tty']=='/dev/tty1'
    for k in ['removal_preserved_user_files','private_X_server_and_session_bus_retired']:assert user[k] is True,k
    gui=user['gui'];assert gui['status']=='PASS_REAL_INSTALLED_GTK_CONTROLS' and gui['uid']==1000
    for k in ['initial_inspect_read_only','preview_read_only','explicit_apply','repeat_apply_preserved_user_edit']:assert gui[k] is True,k
    rendering=gui['rendering'];assert rendering['display_type']=='GdkX11Display' and rendering['renderer_type']=='GskCairoRenderer' and rendering['root_image_bytes']>0 and rendering['image_exported']is False
    assert root['status']=='PASS_UI_GUEST_ALPM_LIFECYCLE'
    for k in ['baseline_inventory_restored','package_owned_nondirectory_paths_absent','original_PAM_policy_preserved','unrelated_user_file_preserved']:assert root[k]is True,k
    assert root['installed']=={'status':'INSTALLED_EXACT_128_TRUSTED_PACKAGES','baseline_count':164,'installed_count':292,'dependency_and_ownership_checks':True}
    assert root['user_files_preserved']==gui['user_files']
    assert root['trust']['private_keys']is False and root['trust']['freshness_or_production_acceptance']is False
    assert 'LocalFileSigLevel = Required TrustedOnly' in root['trust']['configuration']

    session=root['client_session_corroboration'];assert session['pid']==user['pid'] and session['process_session']==user['process_session']
    props=session['login1'];assert props['Active']is True and props['Seat'][0]=='seat0' and props['User'][0]==1000 and props['TTY']=='tty1' and props['Service']=='login' and props['Remote']is False
    assert user['owned_GUI_process_retirement']['passed']is True and user['owned_GUI_process_retirement']['group_census']=='EMPTY_TWICE'
    receipt=root['installation_receipt'];assert receipt['stage']=='installed' and receipt['trusted_ALPM_completed']is True and receipt['exact_inventory']is True and receipt['dependencies']is True and receipt['ownership']is True and receipt['project_hashes']is True and receipt['filesystem_synced']is True
    assert all(root['filesystem_sync'].get(k)is True for k in ['post-install','post-remove','terminal-pass'])
