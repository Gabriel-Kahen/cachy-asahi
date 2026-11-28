#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
set -euo pipefail
umask 022
export LC_ALL=C

readonly recipe_commit=289e009831f6d00a5401059aeb1199bd834c3ebf
readonly setup_path=packages/tools/cachy-asahi-setup8-v3
readonly first_path=packages/tools/cachy-asahi-first-login-v4
readonly setup_tree=376e9c5e2d81f8b6327208f6df9a018a6f9d393c
readonly first_tree=c660594f2443ea857f4a0499f2cb06e778b03c0e
readonly base_image=ghcr.io/menci/archlinuxarm@sha256:d2064fd353031cebad94bbc16dd3d5b30c77b8f68314d49b66d2784b7d65637b
readonly base_config=sha256:f80130fa7055713d9ed52c75a2237134ebf84af7a939d256007097736d652964
readonly supplement_mirror=https://ca.us.mirror.archlinuxarm.org/aarch64/extra
readonly slice="$(cd -- "$(dirname -- "$0")" && pwd)"
mode=${1:?expected source or build}
checkout=${2:?expected pinned recipe checkout}
output=${3:?expected output directory}

verify_source() {
    test "$(git -C "$checkout" rev-parse HEAD)" = "$recipe_commit"
    test "$(git -C "$checkout" rev-parse "HEAD:$setup_path")" = "$setup_tree"
    test "$(git -C "$checkout" rev-parse "HEAD:$first_path")" = "$first_tree"
}

if [[ $mode == source ]]; then
    verify_source
    mkdir -- "$output"
    mkdir -- "$output/public" "$output/input"
    git -C "$checkout" archive --format=tar "$recipe_commit" "$setup_path" "$first_path" |
        tar --extract --directory "$output/input"
    cp -- "$slice/container.sh" "$output/input/container.sh"
    cp -- "$slice/supplement.sha256" "$output/input/supplement.sha256"
    epoch="$(git -C "$checkout" show -s --format=%ct "$recipe_commit")"
    printf '%s\n' "$epoch" > "$output/input/source-date-epoch"
    (
        cd -- "$output/input"
        find . -type f -print0 | sort -z | xargs -0 sha256sum
    ) > "$output/public/input-sha256.txt"
    printf 'recipe_commit=%s\nsetup_tree=%s\nfirst_login_tree=%s\nsource_date_epoch=%s\n' \
        "$recipe_commit" "$setup_tree" "$first_tree" "$epoch" > "$output/public/source.txt"
    exit
fi

# Only the disposable hosted ARM job runs the Docker portion of this workflow.
test "$mode" = build
test "${GITHUB_ACTIONS:-}" = true
test "${GITHUB_REPOSITORY:-}" = Gabriel-Kahen/cachy-asahi
test "${RUNNER_ARCH:-}" = ARM64
test "$(uname -m)" = aarch64
test "$(getconf PAGESIZE)" = 4096
verify_source
(cd -- "$output/input" && sha256sum --check "$output/public/input-sha256.txt")
printf 'workflow_commit=%s\nrunner=%s\nkernel=%s\npage_size=4096\nbase_image=%s\nbase_config=%s\n' \
    "${GITHUB_SHA:?}" "$RUNNER_ARCH" "$(uname -r)" "$base_image" "$base_config" > "$output/public/runner.txt"

docker pull --platform linux/arm64 "$base_image" 2>&1 | tee "$output/public/pull.log"
test "$(docker image inspect --format '{{.Os}}/{{.Architecture}} {{.Id}}' "$base_image")" = "linux/arm64 $base_config"
supplement="$output/public/build-inputs"
mkdir -- "$supplement"
cp -- "$output/input/supplement.sha256" "$supplement/"
while read -r digest filename; do
    [[ $digest =~ ^[a-f0-9]{64}$ && $filename =~ ^(fish|zsh)-[0-9.]+-[0-9]+-aarch64\.pkg\.tar\.xz(\.sig)?$ ]]
    curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' \
        --max-time 120 --max-filesize 4194304 --output "$supplement/$filename" "$supplement_mirror/$filename"
done < "$supplement/supplement.sha256"
(cd -- "$supplement" && sha256sum --check supplement.sha256)

readonly mount_spec="type=bind,src=$output/input,dst=/input,readonly"
readonly -a limits=(--platform linux/arm64 --cpus 1 --memory 768m --memory-swap 768m --pids-limit 128
                    --security-opt no-new-privileges --entrypoint /bin/bash --user 0:0)
run="${GITHUB_RUN_ID:?}-${GITHUB_RUN_ATTEMPT:?}"
[[ $run =~ ^[0-9]+-[0-9]+$ ]]
read -r nonce < /proc/sys/kernel/random/uuid
readonly owner="first-login-v4-${run}-${nonce}"
readonly label=org.cachy-asahi.first-login-v4-owner
readonly provision_name="$owner-provision"
readonly image_tag="cachy-asahi-first-login-v4-build:$owner"
readonly -a lanes=(lane-1 lane-2)
pending_create=
pending_commit=
printf 'resource_owner=%s\nbuild_image_tag=%s\n' "$owner" "$image_tag" >> "$output/public/runner.txt"

container_ids() {
    docker container ls --all --no-trunc --quiet --filter "name=^/$1$"
}

cleanup_container() {
    local name=$1 id identity remaining
    id=$(container_ids "$name") || return 1
    if [[ -z $id ]]; then
        # A request that lost its reply could still be in flight on the daemon.
        [[ $pending_create != "$name" ]]
        return
    fi
    [[ $id =~ ^[0-9a-f]{64}$ ]] || return 1
    identity=$(docker container inspect --format "{{.Name}} {{index .Config.Labels \"$label\"}}" "$id") || return 1
    [[ $identity == "/$name $owner" ]] || return 1
    docker container rm --force "$id" || :
    remaining=$(container_ids "$name") || return 1
    [[ -z $remaining ]]
}

image_ids() {
    docker image ls --all --no-trunc --quiet --filter "$1" | sort -u
}

cleanup_image() {
    local id tagged identity remaining
    id=$(image_ids "label=$label=$owner") || return 1
    tagged=$(image_ids "reference=$image_tag") || return 1
    [[ -z $tagged || $tagged == "$id" ]] || return 1
    if [[ -z $id ]]; then
        [[ -z $pending_commit ]]
        return
    fi
    [[ $id =~ ^sha256:[0-9a-f]{64}$ ]] || return 1
    identity=$(docker image inspect --format "{{index .Config.Labels \"$label\"}}" "$id") || return 1
    [[ $identity == "$owner" ]] || return 1
    docker image rm --no-prune "$id" || :
    remaining=$(image_ids "label=$label=$owner") || return 1
    tagged=$(image_ids "reference=$image_tag") || return 1
    [[ -z $remaining && -z $tagged ]]
}

cleanup() {
    local status=$? failed=0 name remaining
    trap - EXIT
    for name in "$owner-lane-2" "$owner-lane-1" "$provision_name"; do
        if ! cleanup_container "$name"; then
            printf 'Could not confirm cleanup of container %s\n' "$name" >&2
            failed=1
        fi
    done
    if ! remaining=$(docker container ls --all --no-trunc --quiet --filter "label=$label=$owner") ||
        [[ -n $remaining ]]; then
        printf 'Could not confirm absence of containers owned by %s\n' "$owner" >&2
        failed=1
    fi
    if ! cleanup_image; then
        printf 'Could not confirm cleanup of image %s\n' "$image_tag" >&2
        failed=1
    fi
    printf 'build_exit=%s\ncleanup_exit=%s\n' "$status" "$failed" > "$output/public/cleanup.txt"
    if (( status == 0 && failed != 0 )); then exit "$failed"; fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

pending_create=$provision_name
provisioner="$(docker create "${limits[@]}" --name "$pending_create" --label "$label=$owner" \
    --network none --mount "$mount_spec" \
    --mount "type=bind,src=$supplement,dst=/seed,readonly" \
    "$base_image" /input/container.sh provision)"
[[ $provisioner =~ ^[0-9a-f]{64}$ ]]
pending_create=
docker start --attach "$provisioner" 2>&1 | tee "$output/public/provision.log"
test "$(docker inspect --format '{{.State.ExitCode}}' "$provisioner")" = 0
docker cp "$provisioner:/work/base-packages.txt" "$output/public/base-packages.txt"
tagged=$(image_ids "reference=$image_tag")
test -z "$tagged"
pending_commit=$image_tag
image="$(docker commit --pause=false --change "LABEL $label=$owner" "$provisioner" "$image_tag")"
[[ $image =~ ^sha256:[0-9a-f]{64}$ ]]
pending_commit=
test "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "$image")" = linux/arm64
printf '%s\n' "$image" > "$output/public/build-image.txt"

for lane in "${lanes[@]}"; do
    destination="$output/public/$lane"
    mkdir -- "$destination"
    pending_create="$owner-$lane"
    id="$(docker create "${limits[@]}" --name "$pending_create" --label "$label=$owner" \
        --network none --mount "$mount_spec" \
        "$image" /input/container.sh build)"
    [[ $id =~ ^[0-9a-f]{64}$ ]]
    pending_create=
    actual="$(docker inspect --format '{{.Id}} {{.Image}} {{.HostConfig.NetworkMode}} {{.HostConfig.Privileged}}' "$id")"
    test "$actual" = "$id $image none false"
    printf '%s\n' "$actual" > "$destination/container.txt"
    status=0
    docker start --attach "$id" 2>&1 | tee "$destination/container.log" || status=$?
    if (( status != 0 )); then
        docker cp "$id:/work/result/." "$destination" || true
        exit "$status"
    fi
    test "$(docker inspect --format '{{.State.ExitCode}}' "$id")" = 0
    docker cp "$id:/work/result/." "$destination"
done
python3 -I -B "$slice/verify.py" "$output/public" "$output/input"
