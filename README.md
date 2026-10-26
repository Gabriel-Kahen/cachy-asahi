# Accepted signed607 fresh installer on generic ARM16K

Source 1e777ec5a0612af37305f93f87f2c7b2f7a36de8, run40390192017, attempt1.
The owned generic ARM VM installs the exact signed TEST607 package set, including
Apps16, with ordinary-parent and root-guest payload, database, ownership,
preservation, namespace and process-retirement checks. The complete post-parent
root observation covers124513 nodes with no missing database nodes. Its observed
readback takes262108ms within the original600s limit. The VM exits naturally in2234.392s within4500.

The new source measures capacity on the actual target filesystem. Its exact11
fields report4096-byte allocation units,6295699456 required bytes including
536870912 reserve,14905962496 available bytes,132047 required inodes and1186592
available inodes. Schema, integer types and arithmetic are independently
revalidated; private raw node-sizing/statvfs inputs remain source-enforced.
capacity_reserved=false: concurrent writes, quotas and COW pressure are not
reserved or admitted by this finite test.

The independently matched2619 reader passes its selected replay in34.618s/300;
all1206 source Git blobs, the reader map, retained originals and ten public
members join. The kernel profile selects16384-byte pages and the guest numeric
namespace/page checks remain source enforced. Private raw node/hash/ownership
maps remain unexported; this record is not a fresh raw-map readback. Cleanup is
source-bound retained evidence, not live reobservation.

Package builds reuse already accepted native archive pairs. Hooks/scriptlets are
disabled. Native-container P0 remains UNCHANGED_FAILED. Physical installation,
Apple boot/session recovery, Asahi/both M2 sizes, GUI, performance and supported
release acceptance remain separate. The result does not claim that the mount
backend selected statx rather than its original fdinfo fallback.
