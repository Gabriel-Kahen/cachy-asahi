# Exact glibc public source acquisition

Primary sourceware gitweb resolves installed version suffix `g8362e8ce10b2` to commit `8362e8ce10b24068bacc19552c128dd10e082fd9`, tree `912828afc79878e39e0e771d461f11080c25b715`. Its cache-format sources are retained with every acquisition URL, success pin and bounded refusal in `acquisition.DATA.json`. The release2.43 generic cache header is byte-identical; release commit is `f762ccf84f122d1354f103a151cba8bde797d521`. GitHub bminor mirror lacked that revision/tag at acquisition; no substitution was made.

The upstream revision correspondence is through the retained installed package version suffix and independently recovered full upstream commit. Package source-to-binary correspondence has not been reproduced here, and no installed package is reclassified as project-built. No actor, VM, guest disk, package installation, key or credential was accessed.

`COPYING.LIB` is retained as its literal16-byte symlink target text `COPYING.LESSERv2`; the actual target license and GNU GPLv2 text are retained as `COPYING.LESSERv2` and `COPYINGv2`. The requested bare `COPYING` path returned404 and is not silently invented. Source-file notices designate LGPL2.1-or-later; upstream program/license scopes still require their own review.

For the parent decoder, cache.c creates `cache_name~` with no-follow, writes fresh cache, chmods0644, fsyncs/closes and renames over final cache. This directly explains why cache inode/timestamps and containing directory mtime may legitimately change, without qualifying any particular cache body.
