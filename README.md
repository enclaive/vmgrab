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
# Build from source
go build -o vmgrab

# Or use the pre-compiled binary
chmod +x vmgrab
```

### Basic Usage

```bash
# List all VMs with security status
./vmgrab list

# Dump VM memory
sudo ./vmgrab dump <vm-name> /tmp/dump.bin

# Search memory dump for patterns
./vmgrab search /tmp/dump.bin "117-66-8129"

# Run complete attack on single VM
sudo ./vmgrab attack <vm-name> --pattern "sensitive-data"

# Run full demo (standard VM vs confidential VM)
sudo ./vmgrab demo
```

### Configuration

Create a `.vmgrab.yaml` config file for custom settings:

```bash
./vmgrab config init
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

## Remote Mode

vmgrab supports remote KVM hosts via SSH:

```yaml
# .vmgrab.yaml
ssh:
  enabled: true
  host: "37.27.127.61"
  user: "ion"
  ssh_key: "/path/to/key"
```

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
