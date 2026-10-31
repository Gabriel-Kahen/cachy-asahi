# Native ARM Apps parser experiment

[Run39101634659](https://github.com/Gabriel-Kahen/cachy-asahi/actions/runs/39101634659), source `83e521df9ca687d14592237173882549bc86a43f`, measured the selected Apps6 and Apps7 parser functions over all574 original builder ALPM `files` records. Root accepted the retained experiment receipts after strict replay. The baseline source was `eac600bd4f256068a78eb793dd464277eed6ce23`; candidate source was `134e02ba0c73dab4eb4a22cbfd562599b9e7a411`.

The fixed corpus contained6047984 bytes and135441 linefeeds, dataset SHA256 `e26dd7cab4f85e0409e6ae9fd10db5cdfb91c6e112825785e6e24cf0a7c1543c`. The source-enforced comparison reports exact ordered output agreement for every record and all eight refusal controls, before clocks and at each repetition. No record was skipped. Raw records and ordered outputs are unexported; Root replay checks their retained identities and source-bound receipts rather than recomputing them.

Two warmups per variant preceded six measured whole-corpus repetitions per variant in alternating AB/BA order. Timings cover the parser plus identical result capture; comparison and hashing are outside the interval.

| Variant | Median wall time | Wall range | Median process CPU time |
| --- | --- | --- | --- |
| Apps6 baseline |1.610384279s|1.606862500–1.616925804s|1.608408040s|
| Apps7 candidate |0.416945683s|0.415739933–0.423618823s|0.416871416s|

The observed median baseline/candidate wall ratio is3.8623 for this selected parser workload. This measures neither full inventory scanning nor application responsiveness. The consumer reported aarch64,4096-byte pages and CPython3.14.8, with one CPU, read-only input/root, zero capabilities and no network. Physical hardware and thermal/power/background conditions were not independently attested. No M2, full-system performance, power or release-policy acceptance follows.

The prospective native corpus profile used production limits:4MiB per record,64MiB aggregate and32768 FILES values per record. The original standalone microbenchmark's smaller synthetic domain remains unchanged. Worker300s/owner330s bounds stayed fixed. Consumer-before-producer absence is retained source-enforced evidence; private cleanup details are unexported.

Original artifact:2784 bytes, SHA256 `f2236f302ad11114ceebeb210aca1f9ee76322bd3c947cc6353cc615a30bba79`. Original logs:74914 bytes, SHA256 `c8ad043d8594a63dfcd72d698431f00595066edc03823f88a3dbe9682284c69e`. All twelve raw timing samples and the scoped Root decision are retained locally. The first passive reader failed on a missing bounded JSON-read helper; a separate corrected reader added only that helper and replayed the same cached originals. No native rerun, recollection or semantic predicate change occurred. The canonical workflow remains unbound until explicit source selection.
