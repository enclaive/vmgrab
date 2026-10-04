# Memory capture and search results

`dump`, `search`, `attack` and `demo` work with captured memory, independently of
which application produced it. On a CRI node, use `--backend=pod` and a
`namespace/pod` target. `crictl` must be configured for the node's runtime endpoint.

```sh
sudo vmgrab --backend=pod dump test/example -o /var/tmp
vmgrab search /var/tmp/example.dump 'RECORD-[0-9a-f]{32}'
sudo vmgrab --backend=pod attack test/example --pattern='RECORD-[0-9a-f]{32}'
```

Use the actual dump path printed by `dump`. Preserve its `.meta.json` sidecar.

## What is captured

For process containers, the pod backend enumerates running containers and finds
processes through their container cgroups, including exec-created processes.
It captures readable application mappings, including read-only data and shared
memory. Device MMIO and kernel-only special mappings are excluded.

For a QEMU sandbox, it captures readable QEMU userspace mappings. The presence
of guest_memfd is recorded separately: these mappings are not a capture of the
private memory backed by guest_memfd. The largest mapping is not assumed to
represent every relevant byte of a sandbox.

This is a live capture of selected processes and mappings, not an atomic
snapshot. Processes may exit and memory may change while being read. A capture
is complete only with respect to its recorded selection, not all possible
memory of a workload or the inaccessible private memory of a guest.

Sidecar version 4 records scope, process identities, mapping offsets, actual
bytes read, padding, errors and observed guest_memfd descriptors. Unread bytes
may be padded to preserve offsets, but that makes the capture incomplete and
`dump` returns an error. Partial artifacts and their metadata are retained for
inspection; `attack` and `demo` remove their own artifacts by default, including
on failure. Use `--cleanup=false` to retain them.

## Interpreting search

- `MATCH_FOUND`: the matched data is readable in the captured bytes. This alone
  does not establish exposure of guest-private memory: the data might be in
  shared I/O, a process buffer, the container specification or application logs.
- `NOT_FOUND`: the requested pattern was not observed in the inspected bytes.
  It does not establish encryption or absence from memory that was not captured.
- `INCONCLUSIVE`: no match was found and the capture is known to be incomplete.

A partial capture can still contain a confirmed match; the command reports the
match and the incompleteness, and returns an error. Configured SEV/SNP/TDX is
reported as capture-time configuration, not as an attestation result.

Search uses Go regular expressions. For sidecars with mapping layouts, it avoids
joining unrelated virtual addresses and excludes synthetic padding. Without a
layout, it searches the file as provided. Legacy sidecars remain readable, but
unknown coverage is stated explicitly. `--max` limits displayed matches;
additional matches are reported as a limit, not an exact total count.

`search` and `attack` return zero for a completed search with or without matches.
They return nonzero for invalid input, an unreadable/changed dump or known
incompleteness. An empty dump is incomplete.

## A reproducible comparison

Run identical applications with a runtime-generated synthetic record retained
in memory. Confirm readiness without printing the record or putting it in the
pod specification, argv or environment. An ordinary container provides the
positive control; absence of the record there invalidates the comparison.
The helper under `tests/workloads/memory-holder` can provide such a workload.

`demo` builds its table from the actual phase results. It returns nonzero when
the positive control fails, capture/search is incomplete, the confidential
target's configuration or coverage is unknown, or the requested data is found
in its capture. A successful comparison establishes an observed contrast for
the selected mappings, not a proof of encryption.

Test specification/stdout visibility as a separate scenario. Host-readable
application output is still data exposure even when confidential computing is
configured; it should not be described as a hardware encryption failure solely
because a pattern was found.
