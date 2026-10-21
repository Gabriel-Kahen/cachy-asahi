# Source proposal only. Root supplies a freshly reviewed native exact574 base ID.
ARG BASE_IMAGE
FROM ${BASE_IMAGE}
COPY deps/ /core-deps/
COPY expected574.lock expected638.lock base-config.sha256 disabled-hooks.txt /core-contract/
RUN cd /core-deps && sha256sum -c SHA256SUMS \
 && cd / && sha256sum -c /core-contract/base-config.sha256 \
 && pacman -Q | LC_ALL=C sort > /core-contract/observed-before.lock \
 && cmp /core-contract/expected574.lock /core-contract/observed-before.lock \
 && mkdir -p /core-builder-masked-hooks \
 && while IFS= read -r hook; do ln -s /dev/null "/core-builder-masked-hooks/$hook"; done < /core-contract/disabled-hooks.txt \
 && pacman --config /etc/pacman.conf --hookdir /core-builder-masked-hooks -U --noconfirm --noscriptlet /core-deps/*.pkg.tar.xz \
 && ldconfig \
 && pacman -Q | LC_ALL=C sort > /core-contract/observed-after.lock \
 && cmp /core-contract/expected638.lock /core-contract/observed-after.lock \
 && rm -rf /core-deps /var/cache/pacman/pkg/*
