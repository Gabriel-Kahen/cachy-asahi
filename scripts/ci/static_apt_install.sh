static_package_names=$(python3 -I -B scripts/ci/static_apt_trial.py packages)
test -n "$static_package_names"
mapfile -t static_packages <<< "$static_package_names"
python3 -I -B scripts/ci/static_apt_cache.py stage "$RUNNER_TEMP/static-apt-uris" "$RUNNER_TEMP/static-apt-cache" "$RUNNER_TEMP/static-apt-verified"
sudo apt-get -o Dir::Cache::archives="$RUNNER_TEMP/static-apt-verified" -o APT::Keep-Downloaded-Packages=true --no-install-recommends -y install "${static_packages[@]}"
for tool in bash fish zsh vim cc clang ld.lld gpg gpgconf pacman-key pacman-conf unshare repo-add bsdtar vercmp pacman mkfs.ext4 debugfs nmcli makepkg fakeroot zstd bwrap; do command -v "$tool"; done
dpkg-query -W "${static_packages[@]}"
python3 -I -B scripts/ci/static_apt_cache.py export "$RUNNER_TEMP/static-apt-uris" "$RUNNER_TEMP/static-apt-verified" "$RUNNER_TEMP/static-apt-cache"
