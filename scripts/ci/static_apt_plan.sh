static_package_names=$(python3 -I -B scripts/ci/static_apt_trial.py packages)
test -n "$static_package_names"
mapfile -t static_packages <<< "$static_package_names"
python3 -I -B scripts/ci/test_static_apt_cache.py -v
sudo apt-get -o APT::Update::Error-Mode=any update
mkdir "$RUNNER_TEMP/static-apt-plan"
sudo apt-get -o Dir::Cache::archives="$RUNNER_TEMP/static-apt-plan" -o Acquire::ForceHash=sha256 --print-uris --no-install-recommends -y install "${static_packages[@]}" > "$RUNNER_TEMP/static-apt-uris"
digest=$(python3 -I -B scripts/ci/static_apt_cache.py key "$RUNNER_TEMP/static-apt-uris")
echo "digest=$digest" >> "$GITHUB_OUTPUT"
test -n "${ImageVersion:-}"
echo "image=$ImageVersion" >> "$GITHUB_OUTPUT"
