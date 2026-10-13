# Read-only image reader tool contract adoption

October 13, 2026. Root admits the reviewed v3 tool contract by changing only `TOOL_CONTRACT_SHA` in the reader. All other reader AST nodes are unchanged. The candidate reader SHA256 is `485913978598a444f86de17c7583e14b96fb7fdb9b25334f4f59d054af09c16a`; contract SHA256 is `4f53cd7be7a9f23c526007bd846b4c09b040be364504959dbf4273b5591d3ef6`.

V3 changes only 32 UID/GID metadata scalars from the former tool contract. Tool bytes, sizes, modes, symlink targets and the image remain identical. Current metadata was inspected; the cause of the old namespace ownership difference remains UNKNOWN. No ownership or host tool was changed.

Root authenticated 58 artifacts in independent reader-custody correction receipt `8fd2e37aa9022f830e1a6c389655cfc2ba5849b4283b211cc1a4ea117b541a26`. Both report-custody findings close under finite filesystem controls. The adopted reader's cold 60-test suite passes with zero skips. Adoption receipt `artifacts/reviews/platform-installed-payload-tool-v3-root-adoption-20261012/adoption.json` has SHA256 `512dae5c3e453b9bfd8ec0fd073b0bfaef7ba1e4361ffba11be6f0b156977eee`.

Any actual probe requires a new exact Root selection/grant because the primary source identity changed and the old proposal must stay immutable. Scope remains three read-only inode2 requests, `stat`, `ls -p`, `stat`, under the same 1200-second/8GiB ledger and fixed process limits. It does not select archive extraction, recursive traversal, image mutation, installation or full correspondence. Actual probe is NOT RUN at source admission; 259/261 archives, 26 signer joins, issuer/key-owner trust, hardware and performance remain unfinished. Same-inode generations and metadata/query-operation races retain their documented limits.
