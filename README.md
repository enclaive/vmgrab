```                                                                                     
                        ____                                        ,-.----.           
                        ,'  , `.  ,----..   ,-.----.      ,---,       \    /  \          
           ,---.     ,-+-,.' _ | /   /   \  \    /  \    '  .' \      |   :    \         
          /__./|  ,-+-. ;   , |||   :     : ;   :    \  /  ;    '.    |   |  .\ :        
     ,---.;  ; | ,--.'|'   |  ;|.   |  ;. / |   | .\ : :  :       \   .   :  |: |        
    /___/ \  | ||   |  ,', |  ':.   ; /--`  .   : |: | :  |   /\   \  |   |   \ :        
    \   ;  \ ' ||   | /  | |  ||;   | ;  __ |   |  \ : |  :  ' ;.   : |   : .   /        
     \   \  \: |'   | :  | :  |,|   : |.' .'|   : .  / |  |  ;/  \   \;   | |`-'         
      ;   \  ' .;   . |  ; |--' .   | '_.' :;   | |  \ '  :  | \  \ ,'|   | ;            
       \   \   '|   : |  | ,    '   ; : \  ||   | ;\  \|  |  '  '--'  :   ' |            
        \   `  ;|   : '  |/     '   | '/  .':   ' | \.'|  :  :        :   : :            
         :   \ |;   | |`-'      |   :    /  :   : :-'  |  | ,'        |   | :            
          '---" |   ;/           \   \ .'   |   |.'    `--''          `---'.|            
                '---'             `---`     `---'                       `---`            
                                                                                     

                             VMgrab — VM memory dump validator
 
 OffSec tool to validate VM memory encryption and confidential computing enablement.
 Use for authorised penetration tests and security assessments only.

 [!] AUTHORIZED TESTING ONLY — Run only against systems you own or have explicit written permission to test.
 (c) 2025 enclaive.io   |  Repo: https://github.com/enclaive/vmgrab  |  License: MIT

🎯 Attacking VM: neo4j-vm1

📥 [1/3] Dumping memory...
━━━━━━━━━━━━━━━━━━━━━━━━ 100% | 4.2 GB

🔍 [2/3] Searching for pattern: 117-66-8129
Found at offset 0x2a4f8000:
  ...NHS:117-66-8129,Name:John Smith...

✅ Result: VULNERABLE - Sensitive data exposed!

```
## TL;TR

Standard virtual machines expose plaintext code and data in guest RAM. Confidential VMs (e.g., AMD SEV-SNP, Intel TDX) aim to keep guest memory encrypted at runtime and to minimize the hypervisor/host attack surface. VMgrab is an offensive security tool for technical assessors that automates VM memory acquisition techniques and produces forensic artifacts and test vectors to evaluate whether confidentiality guarantees hold in practice. It is designed for use by pentesters, red-teamers, auditors and incident responders to empirically validate encryption/attestation behaviour, identify implementation gaps, and document reproducible findings.

## What VMgrab is about
Virtual machines expose volatile guest state — code, secrets and runtime data — in RAM. Confidential VM technologies (notably AMD SEV-SNP and Intel TDX) provide runtime memory encryption and associated attestation mechanisms to constrain host/hypervisor visibility. VMgrab is an offensive engineering toolset that:

- automates controlled VM memory acquisition using host-level acquisition vectors common to cloud and on-prem hypervisors;
- produces canonical memory dumps and audit artifacts for repeatable analysis;
- exercises and verifies confidentiality and attestation assertions (e.g., whether pages remain encrypted at rest/in transit, whether firmware/host components leak guest plaintext, and how guest keys/TEEs are managed);
- helps quantify real-world attack surface and implementation gaps in SEV/TDX deployments, and generates evidence suitable for technical reports and remediation planning.

Intended audience: 
- experienced offensive security engineers
- forensic analysts 
- systems architects performing authorized security assessments

Use Cases:

- Security research and penetration testing
- Confidential computing demonstrations
- Educational workshops on memory encryption
- Compliance audits (proving data protection)


**Important note: Use only on assets for which you have explicit written permission.**

## Features

- Dump KVM/libvirt VM memory via `virsh`
- Search memory dumps for sensitive data (NHS numbers, SSNs, emails, etc.)
- Compare classical VMs vs confidential VMs (cVMs with memory encryption)
- Run automated attacks against the enclave


## Requirements

- Linux host OS with KVM/libvirt
- `virsh` command available
- `sudo` privileges (for virsh dump and disk access)
- Go 1.22+ (for building from source)

## Installation

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

## Configuration

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

## Usage Example

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




