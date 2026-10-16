# Separate profile integration API

Keep this trial independent of the separate Waybar/Mako candidate until managed
startup is proven in a real owned VM. No other desktop lane's files are edited.

prepare.transform_guest(text) adapts a selected copied base guest while preserving
phase/emit functions and existing timers. Load managed_session.py next to it and
call managed_session.bind(base) before base.main(). Binding supplies the helper
API/base reference, wraps the existing guard with the managed VM marker, and
leaves phase/emit untouched. It does not require sys.modules registration.

A future Root-selected combination must retain both adapters' guards, install
managed_session.py alongside the transformed base, add the packaged user-sessions
service to fixture Requires/After, and add cachy_asahi_managed_user=1 to the VM
command. The modified base supplies /run/user/23001 and its real session bus;
Waybar/Mako phase code using base.RUNTIME and inherited env needs no private bus.
Add managed_contract.verify_result(events) alongside that candidate's existing
client/visual gates and freeze its separate exact source/derived manifest.

Direct APIs: ManagedSession(base,logs,env,seconds=60).start() returns joined user
env; .diagnose() emits at most one bounded failure capture; .stop() confirms exact
owned disposal; validate_user(base,logs,env) repeats identity checks. Expected
managed events are root ready, user ready, original phase/session events, exact
cleanup, then complete. Managed success establishes no bar, notification, sound,
hardware or complete-session acceptance. Root owns adoption, actors and pixels.
