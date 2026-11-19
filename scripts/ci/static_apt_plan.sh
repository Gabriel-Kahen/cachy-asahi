static_package_names=$(python3 -I -B scripts/ci/static_apt_trial.py packages)
test -n "$static_package_names"
mapfile -t static_packages <<< "$static_package_names"
python3 -I -B scripts/ci/test_static_apt_cache.py -v
# Static prerequisites are from the Ubuntu archive on the Noble runner.
static_apt_source=(-o Dir::Etc::sourcelist=/etc/apt/sources.list.d/ubuntu.sources -o Dir::Etc::sourceparts=-)
static_apt_source+=(-o Acquire::http::Timeout=20 -o Acquire::https::Timeout=20 -o Acquire::Retries=2)
# A stalled index mirror must release the CI runner with an explicit failure.
timeout --kill-after=15s 240s sudo apt-get "${static_apt_source[@]}" -o APT::Update::Error-Mode=any --no-list-cleanup update
mkdir "$RUNNER_TEMP/static-apt-plan"
sudo apt-get "${static_apt_source[@]}" -o Dir::Cache::archives="$RUNNER_TEMP/static-apt-plan" -o Acquire::ForceHash=sha256 --print-uris --no-install-recommends -y install "${static_packages[@]}" > "$RUNNER_TEMP/static-apt-uris"
digest=$(python3 -I -B scripts/ci/static_apt_cache.py key "$RUNNER_TEMP/static-apt-uris")
echo "digest=$digest" >> "$GITHUB_OUTPUT"
test -n "${ImageVersion:-}"
echo "image=$ImageVersion" >> "$GITHUB_OUTPUT"
