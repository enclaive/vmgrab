```
 ██╗   ██╗███╗   ███╗ ██████╗ ██████╗  █████╗ ██████╗
 ██║   ██║████╗ ████║██╔════╝ ██╔══██╗██╔══██╗██╔══██╗
 ██║   ██║██╔████╔██║██║  ███╗██████╔╝███████║██████╔╝
 ╚██╗ ██╔╝██║╚██╔╝██║██║   ██║██╔══██╗██╔══██║██╔══██╗
  ╚████╔╝ ██║ ╚═╝ ██║╚██████╔╝██║  ██║██║  ██║██████╔╝
   ╚═══╝  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

# VMgrab

VMgrab captures memory of a VM, pod or GPU from the host and searches it for
secrets. It reports which requested data is readable in the captured bytes,
along with the recorded capture scope and completeness.

Comparing standard and confidential targets provides evidence about those
captures. Absence of a pattern does not prove encryption or establish what is
present in memory that the host could not capture.

> **Authorized testing only.** Run only against systems you own or have explicit
> written permission to test. See `SECURITY.md`.

## What it does

- Acquires guest memory from the host through four backends and writes a dump
  plus a `.meta.json` sidecar describing what was captured.
- Detects SEV-SNP / SEV / TDX per target from the QEMU command line.
- Searches memory dumps for regex patterns and reports `MATCH_FOUND`,
  `NOT_FOUND` or `INCONCLUSIVE`, with capture coverage where available.
- Reads NVIDIA GPU VRAM from the host and proves whether a model loaded on the
  card is extractable when GPU confidential computing is off.

Intended for offensive security engineers, forensic analysts and architects
running authorized assessments, confidential-computing demos and compliance
evidence collection.

## Requirements

- Linux host with KVM/QEMU
- `sudo`, for `/proc/pid/mem` and QMP access
- Go 1.22+ to build
- `virsh` only for the libvirt backend, `crictl` only for the pod backend

## Install

Prebuilt static Linux binaries for `amd64`, `arm64`, `ppc64le` and `s390x` are
attached to each [GitHub release](https://github.com/enclaive/vmgrab/releases):

```bash
ARCH=amd64   # or arm64, ppc64le, s390x
curl -LO https://github.com/enclaive/vmgrab/releases/latest/download/vmgrab_linux_${ARCH}.tar.gz
tar -xzf vmgrab_linux_${ARCH}.tar.gz
sudo install vmgrab_linux_${ARCH}/vmgrab /usr/local/bin/
```

Each release also has a `checksums.txt` with SHA-256 sums. To build from source:

```bash
make build           # builds bin/vmgrab with version info
./bin/vmgrab --version
make install         # optional, installs to /usr/local/bin
```

## Commands

| Command | Purpose |
|---|---|
| `list` | List VMs and pods with detected security status |
| `dump` | Dump VM or pod memory to a file plus metadata sidecar |
| `search` | Search a dump for a pattern and classify the result |
| `attack` | Dump, search and clean up in one step against one target |
| `demo` | Automated side-by-side comparison of a standard and a confidential target |
| `disk-search` | Search VM disk images from the host, to show LUKS at rest |
| `gpu` | List GPUs and read VRAM: `list`, `search`, `dump`, `verify-model` |
| `config` | Manage configuration: `init`, `show`, `validate` |

## Backends

| Backend | Method | Best for |
|---|---|---|
| `procmem` | `/proc/pid/mem` | Default. Any QEMU process, including Kata |
| `qemu` | QMP `dump-guest-memory` | ELF core of guest RAM, direct or via virsh |
| `libvirt` | `virsh dump --memory-only` | libvirt-managed VMs |
| `pod` | `crictl` plus `/proc/pid/mem` | CRI process containers and QEMU sandboxes, including Kata and other QEMU-based runtimes |

Select one with `--backend`, otherwise VMgrab auto-detects.

## Usage

List targets and their detected protection:

```console
$ sudo vmgrab list
PID     NAME          STATE       KIND   SECURITY
1234    cvm-guest     ● running   vm     🔒 SEV-SNP
5678    plain-guest   ● running   vm     ⚠️  Unprotected
```

Dump and search a target:

```bash
sudo vmgrab dump cvm-guest --backend qemu -o /var/tmp
vmgrab search /var/tmp/cvm-guest-*.dump "POSTGRES_PASSWORD="
```

When the requested pattern is present:

```console
MATCH_FOUND: 1 displayed match(es)
```

When the requested pattern is absent from a capture with no known incompleteness:

```console
NOT_FOUND: 0 displayed match(es)
```

If no match is found and the capture is known to be incomplete, the result is
`INCONCLUSIVE`. Known incompleteness causes a nonzero exit status even when a
match is found. Legacy dumps with unknown coverage are identified explicitly.

### Reading readable bytes correctly

Readable data in a confidential target's capture may come from shared I/O,
process buffers, the pod specification or application output. A match shows
that those bytes are host-readable; it does not identify a guest-private memory
leak by itself. Absence of guest-kernel strings does not prove protection.

When guest_memfd is detected, VMgrab records that its QEMU userspace capture
does not capture the private memory backed by guest_memfd. Configured
SEV/SNP/TDX is reported separately from search results and is not attestation.

`demo` compares actual phase results and requires a successful positive control.
See [memory capture and result semantics](docs/memory-results.md) for coverage,
exit statuses and a reproducible comparison using synthetic data.

## Pods and GPUs

```bash
sudo vmgrab dump my-ns/my-pod --backend pod -o /var/tmp   # every container in the pod
sudo vmgrab gpu list                                      # cards, CC mode, VRAM readability
sudo vmgrab gpu verify-model d1:00.0 ./model.gguf         # is the model extractable from VRAM
```

## Configuration

```bash
vmgrab config init      # writes .vmgrab.yaml
vmgrab config show
```

See `.vmgrab.yaml.example` for the available options, and `CONTRIBUTING.md`
before opening a pull request.

---

(c) 2025 enclaive.io · MIT License · https://github.com/enclaive/vmgrab
