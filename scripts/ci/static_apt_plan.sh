python3 -I -B scripts/ci/test_static_apt_cache.py -v
sudo apt-get -o APT::Update::Error-Mode=any update
mkdir "$RUNNER_TEMP/static-apt-plan"
sudo apt-get -o Dir::Cache::archives="$RUNNER_TEMP/static-apt-plan" -o Acquire::ForceHash=sha256 --print-uris --no-install-recommends -y install bash fish zsh vim build-essential clang lld gnupg libarchive-tools pacman-package-manager makepkg e2fsprogs network-manager pkg-config libgtk-3-dev > "$RUNNER_TEMP/static-apt-uris"
digest=$(python3 -I -B scripts/ci/static_apt_cache.py key "$RUNNER_TEMP/static-apt-uris")
echo "digest=$digest" >> "$GITHUB_OUTPUT"
test -n "${ImageVersion:-}"
echo "image=$ImageVersion" >> "$GITHUB_OUTPUT"
