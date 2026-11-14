# Linux packages

## Build the agent package

```bash
VERSION=0.1.0 bash packaging/build_linux_packages.sh
```

Produces:

- `dist/aidf-auditd_<version>_amd64.deb`
- `dist/aidf-auditd-<version>.tar.gz`
- `dist/aidf-auditd.spec` (rpmbuild spec)

The package installs:

- `/opt/aidf` — core, schemas, rules, `aidf_agent.py`, GUI, docs;
- `/etc/aidf/agent.toml`;
- `/lib/systemd/system/aidf-auditd.service`.

It does not auto-start the service. Review the config and the audit rules first.

## Build with eBPF objects and loader

```bash
sudo bash scripts/build_linux_ebpf.sh dist/ebpf
python3 scripts/linux_object_manifest.py --src dist/ebpf
python3 scripts/sign_linux_manifest.py          # dev key only
VERSION=0.1.0 bash packaging/build_linux_packages.sh --objects dist/ebpf
```

The objects are CO-RE against the build kernel's BTF. Production must build on
the supported kernel matrix and sign the manifest with an HSM/offline key.

## RPM

`rpmbuild` is optional; the build script writes the spec and builds an RPM only
when `rpmbuild` is installed. The spec uses `/opt/aidf`, `/etc/aidf` and the same
systemd unit.

## Windows

See [docs/windows-agent.md](../docs/windows-agent.md): PyInstaller EXE + WiX 3
MSI.

## Verification

```bash
dpkg-deb -c dist/aidf-auditd_0.1.0_amd64.deb | head
sudo dpkg -i dist/aidf-auditd_0.1.0_amd64.deb
sudo systemctl status aidf-auditd --no-pager
curl -s http://127.0.0.1:18080/api/overview | head -c 200
```

Remove:

```bash
sudo apt remove aidf-auditd
```
