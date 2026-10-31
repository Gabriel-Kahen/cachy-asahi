python3 -I -B scripts/ci/static_apt_cache.py stage "$RUNNER_TEMP/static-apt-uris" "$RUNNER_TEMP/static-apt-cache" "$RUNNER_TEMP/static-apt-verified"
sudo apt-get -o Dir::Cache::archives="$RUNNER_TEMP/static-apt-verified" -o APT::Keep-Downloaded-Packages=true --no-install-recommends -y install bash fish zsh vim build-essential clang lld gnupg libarchive-tools pacman-package-manager makepkg e2fsprogs network-manager pkg-config libgtk-3-dev
for tool in bash fish zsh vim cc clang ld.lld gpg gpgconf pacman-key pacman-conf unshare repo-add bsdtar vercmp pacman mkfs.ext4 debugfs nmcli; do command -v "$tool"; done
dpkg-query -W bash fish zsh vim build-essential clang lld gnupg libarchive-tools pacman-package-manager makepkg e2fsprogs network-manager pkg-config libgtk-3-dev
python3 -I -B scripts/ci/static_apt_cache.py export "$RUNNER_TEMP/static-apt-uris" "$RUNNER_TEMP/static-apt-verified" "$RUNNER_TEMP/static-apt-cache"
