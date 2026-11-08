# Maintained zlib1.3.2 source carrier proposal

This carrier contains the complete, unmodified upstream zlib1.3.2 source archive:1,502,830 bytes, SHA256 bb329a0a2cd0274d05519d61c667c062e06990d72e125ee2dfa8de64f0119d16. The archive retains every original source file and notice. LICENSE.zlib and notices/ are exact convenience copies of the identified upstream license files, including contributed dotzlib and minizip notices. Every original remains inside the full archive. SOURCE.json records fixed inputs and retained official acquisition provenance.

A carrier manifest supplies whole-file SHA256/length/mode pins. Obtain the manifest pin through the coordinator's authenticated source/publication process; a checksum supplied alongside an untrusted download alone is not authentication. This is a local source-carrier proposal, not a published endpoint or accepted release.

The proposed helper accepts --local-archive /absolute/path/to/zlib-1.3.2.tar.gz with --output /absolute/new/destination/zlib-1.3.2.tar.gz and optional --receipt /absolute/new/destination/zlib-source-retrieval.json. It copies from an owned, stable, single-link ordinary0600/0644 file after exact gzip/size/SHA validation, with no overwrite, extraction, build, installation or execution. Parent directories must be nonsymlink; output uses the same exclusive mode0600 publication path as network retrieval.

This delivers zlib's finite upstream source archive and original notices. It does not establish historical compiler/linker correspondence, source closure for a whole system/toolchain/runtime, native ARM or M2 validation, performance, or release acceptance. Root owns any repository/public carrier integration, source maintenance and CI decision.
