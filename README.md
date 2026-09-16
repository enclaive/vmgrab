```
 ██╗   ██╗███╗   ███╗ ██████╗ ██████╗  █████╗ ██████╗
 ██║   ██║████╗ ████║██╔════╝ ██╔══██╗██╔══██╗██╔══██╗
 ██║   ██║██╔████╔██║██║  ███╗██████╔╝███████║██████╔╝
 ╚██╗ ██╔╝██║╚██╔╝██║██║   ██║██╔══██╗██╔══██║██╔══██╗
  ╚████╔╝ ██║ ╚═╝ ██║╚██████╔╝██║  ██║██║  ██║██████╔╝
   ╚═══╝  ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
```

# VMgrab

VMgrab dumps the memory of a VM, pod or GPU from the host and searches it for
secrets. It answers one question empirically: **can the hypervisor operator read
what is inside the guest?**

On a standard VM the answer is yes, and VMgrab shows the plaintext. On an AMD
SEV-SNP or Intel TDX guest the answer should be no, and VMgrab shows that guest
memory is unreadable. That contrast is the demo, the audit evidence and the
regression test.

> **Authorized testing only.** Run only against systems you own or have explicit
> written permission to test. See `SECURITY.md`.

## What it does

- Acquires guest memory from the host through four backends and writes a dump
  plus a `.meta.json` sidecar describing what was captured.
- Detects SEV-SNP / SEV / TDX per target from the QEMU command line.
- Searches dumps for regex patterns and classifies the outcome: readable guest
  memory, protected guest memory, or host process memory.
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
| `pod` | `crictl` plus `/proc/pid/mem` | CRI pods: runc containers and Kata-SNP sandboxes |

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

On an unprotected VM the guest kernel is visible from the host:

```console
❌ NOT ENCRYPTED — Linux kernel banner found in dump
```

On a SEV-SNP guest the same command cannot reach guest memory:

```console
🔬 QEMU core dump of a VM — probing for guest-kernel fingerprints
   Linux version [0-9]+\.[0-9]+\.[0-9]+     ✓ not found
   swapper/0                                ✓ not found
   __init_task                              ✓ not found
   CONFIG_SEV_GUEST                         ✓ not found

✅ SEV-SNP PROTECTED — guest private memory is not readable from the host
```

### Reading readable bytes correctly

A confidential VM does not encrypt everything. Its shared I/O buffers, virtio
and DMA rings, firmware tables and the ELF core metadata are plaintext by
design. A SEV-SNP dump therefore still contains readable strings, and their
presence alone does not mean the guest is exposed.

VMgrab decides with the guest-kernel fingerprint probe instead of counting
readable bytes. If guest kernel structures are absent, private memory is
protected, and anything readable came from the shared surface. A secret found
there travelled over virtio and is a workload issue, not a SEV-SNP failure.

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
