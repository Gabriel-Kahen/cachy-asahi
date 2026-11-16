# Versioned canonical-Python staging correction

`stage_materials_current_v3_python_v1.py` is a separately versioned successor to
c640. The c640 body stays byte-exact31630 bytes /
`2e2bf75fb6c59e400cf21aadb719ee687d7b8c12e21ace872637b47f7304fede`.
No numerical resource, clock, URL, secret, source-helper, grant or data contract
changes: API and PROPOSAL remain the reviewed V3 proposal, not an issued grant.

The exact read-only reproduction supplied by the domain author shows that actual
executor53735 bytes/aee41c09… qualifies candidate `/usr/bin/python3` and returns
canonical `/usr/bin/python3.14`. C640 then incorrectly requires that canonical
return to equal the candidate pathname. This rejects a valid root-owned alias
before acquisition; it is not an ARM, transport, package or native result.

The successor uses the actual held `inspect_tool('/usr/bin/<name>')` and
`checked_tool(row)` contract for Python and systemctl. It retains each complete
qualified row, selects its returned canonical executable, and rejoins that row
immediately before every outer spawn. Public14, transport, private-seed and
prepare Python children use that same canonical path. It adds no PATH search,
root-owner override, alternate tool provider, unreviewed executable allowance or
body/alias check waiver. The argv NUL check is explicit. The caller also selects
its physical-scope Python path from the same existing checked-tool contract.

Nineteen fenced controls pass on Python3.12/3.14: inherited staging/grant/secret/
HTTP/refusal controls plus actual held-inspector tests over tiny inert filesystem
fixtures. Tests demonstrate the old alias guard refusal, successful canonical
qualification, operational root-ownership refusal for user-owned fixtures,
writable/unreviewed tool refusal and changed-body rejection before Popen. The
fixture root/UID overrides belong only to the held inspector's existing explicit
MODEL seams; production uses its normal root filesystem and UID0. No actual
staging, network, secret injection, process, privilege, transport, GPG or native
role was run. The existing complete517 local-reference evidence remains DATA-only.

The domain executor and constructor must select this new complete program pin as
`programs.materials_stager`; its hardcoded checkpoint must be updated in a domain
successor. Actual Source closure, Root policy/grant, resources, session proof and
execution remain unissued. Do not freeze an incomplete19-role Source or relabel
the alias fix as an operational delivery qualification.
