# Package ownership and removal proposal

The package stages three headers, two versioned shared libraries plus relative
unversioned symlinks, four tools, two section1 manpages, a licence directory and
the exact self-contained filtered-source rebuild pack. All writes use pkgdir.
It owns no user data/configuration or services and has no installation hooks.

Conflicts with jbigkit are explicit; no automatic replaces is proposed. Root
must select the transaction and retained signed rollback package after actual
dependency/ABI inspection. Normal package removal would remove package-owned
files. Install/remove/rollback and both-size M2 testing are NOT RUN.
