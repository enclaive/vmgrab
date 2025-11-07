# vmgrab

**vmgrab** — dump VM memory fast, without breaking a sweat.

A CLI tool for demonstrating VM memory dump attacks and proving confidential computing protection (AMD SEV-SNP / Intel TDX).

## What it does

vmgrab helps security researchers and system administrators demonstrate the effectiveness of confidential computing by:

- Dumping KVM/libvirt VM memory via `virsh`
- Searching memory dumps for sensitive data (NHS numbers, SSNs, emails, etc.)
- Comparing standard VMs vs confidential VMs (cVMs with memory encryption)
- Running automated attack demonstrations

**Key insight**: Standard VMs expose sensitive data in memory dumps. Confidential VMs with AMD SEV-SNP or Intel TDX encrypt memory, preventing data extraction even with root access to the host.

## Quick Start

### Requirements

- Linux host with KVM/libvirt
- `virsh` command available
- `sudo` privileges (for virsh dump and disk access)
- Go 1.22+ (for building from source)

### Installation

```bash
# Build using Makefile (recommended - includes version info)
make build

# The binary will be in bin/vmgrab
./bin/vmgrab --version

# Or install to /usr/local/bin
make install

# Or build manually
go build -o bin/vmgrab
```

### Basic Usage

```bash
# List all VMs with security status
./bin/vmgrab list

# Dump VM memory
sudo ./bin/vmgrab dump <vm-name> /tmp/dump.bin

# Search memory dump for patterns
./bin/vmgrab search /tmp/dump.bin "123-45-6789"

# Run complete attack on single VM
sudo ./bin/vmgrab attack <vm-name> --pattern "sensitive-data"

# Run full demo (standard VM vs confidential VM)
sudo ./bin/vmgrab demo
```

### Configuration

Create a `.vmgrab.yaml` config file for custom settings:

```bash
./bin/vmgrab config init
```

See `.vmgrab.yaml.example` for configuration options.

## Commands

- `list` - List all VMs with security status (SEV-SNP vs Vulnerable)
- `dump` - Dump VM memory to file
- `search` - Search memory dump for patterns (regex supported)
- `attack` - Complete attack demo on single VM (dump + search + cleanup)
- `demo` - Full automated demonstration comparing standard vs confidential VMs
- `disk-search` - Search VM disk files from host (proves LUKS encryption)
- `config` - Manage configuration (init, show, validate)

## Example Output

```
🎯 Attacking VM: neo4j-vm1

📥 [1/3] Dumping memory...
━━━━━━━━━━━━━━━━━━━━━━━━ 100% | 4.2 GB

🔍 [2/3] Searching for pattern: 117-66-8129
Found at offset 0x2a4f8000:
  ...NHS:117-66-8129,Name:John Smith...

✅ Result: VULNERABLE - Sensitive data exposed!
```

## Use Cases

- Security research and penetration testing
- Confidential computing demonstrations
- Educational workshops on memory encryption
- Compliance audits (proving data protection)

---

Built for demonstrating the importance of memory encryption in cloud and edge computing environments.
