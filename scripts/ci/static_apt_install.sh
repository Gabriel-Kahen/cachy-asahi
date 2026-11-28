static_package_names=$(python3 -I -B scripts/ci/static_apt_trial.py packages)
test -n "$static_package_names"
mapfile -t static_packages <<< "$static_package_names"
if [[ "${CAA_CACHE_HIT:-}" == true ]]; then
    # The same authenticated bytes supply both the install stage and the receipt.
    python3 -I -B - <<'PY'
import hashlib
import json
import os
from pathlib import Path
import runpy

trial = runpy.run_path('scripts/ci/static_apt_trial.py')
cache, require = trial['archive_cache'], trial['require']
root = Path(os.environ['RUNNER_TEMP'])
state_path = root / 'static-apt-trial-state.json'
state = json.loads(state_path.read_text())
require(state['phase'] in ('normal', 'warm'), 'cold sample restored archives')
rows = cache.read_plan(root / 'static-apt-uris')
require(cache.plan_key(rows) == state['plan_digest'], 'archive plan changed after cache key binding')
require(hashlib.sha256(Path(cache.__file__).read_bytes()).hexdigest() == state['helper_digest'],
        'archive helper changed after cache key binding')
report = cache.transfer(rows, root / 'static-apt-cache', root / 'static-apt-verified', fresh=True)
require(state['phase'] != 'warm' or report['verified'] == len(rows) > 0,
        'warm cache lacks complete verified archive set')
state.update(cache_hit='true', archive_count=len(rows), verified_before_install=report['verified'])
state_path.write_text(json.dumps(state, sort_keys=True) + '\n')
print(json.dumps(report, sort_keys=True))
PY
else
    python3 -I -B scripts/ci/static_apt_cache.py stage "$RUNNER_TEMP/static-apt-uris" "$RUNNER_TEMP/static-apt-cache" "$RUNNER_TEMP/static-apt-verified"
fi
static_apt_source=(-o Dir::Etc::sourcelist=/etc/apt/sources.list.d/ubuntu.sources -o Dir::Etc::sourceparts=-)
static_apt_source+=(-o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 -o Acquire::Retries=2)
sudo apt-get "${static_apt_source[@]}" -o Dir::Cache::archives="$RUNNER_TEMP/static-apt-verified" -o APT::Keep-Downloaded-Packages=true --no-install-recommends -y install "${static_packages[@]}"
for tool in bash fish zsh vim cc clang ld.lld gpg gpgconf pacman-key pacman-conf unshare repo-add bsdtar vercmp pacman mkfs.ext4 debugfs nmcli makepkg fakeroot zstd bwrap; do command -v "$tool"; done
dpkg-query -W "${static_packages[@]}"
if [[ "${CAA_CACHE_HIT:-}" != true ]]; then
    python3 -I -B scripts/ci/static_apt_cache.py export "$RUNNER_TEMP/static-apt-uris" "$RUNNER_TEMP/static-apt-verified" "$RUNNER_TEMP/static-apt-cache"
fi
