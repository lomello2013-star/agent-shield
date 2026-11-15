#!/usr/bin/env bash
# Build Linux packages for the auditd agent.
#
#   VERSION=0.1.0 bash packaging/build_linux_packages.sh [--objects DIR]
#
# Produces:
#   dist/aidf-auditd_<version>_amd64.deb
#   dist/aidf-auditd-<version>.tar.gz
#   dist/aidf-auditd.spec (for rpmbuild, if rpmbuild is installed)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
VERSION=${VERSION:-0.1.0}
ARCH=${ARCH:-amd64}
OUT=${OUT:-"$ROOT/dist"}
OBJECTS=""
while [ $# -gt 0 ]; do
    case "$1" in
        --objects) OBJECTS=${2:?}; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT
mkdir -p "$STAGE/opt/aidf" "$STAGE/etc/aidf" "$STAGE/lib/systemd/system" \
         "$STAGE/DEBIAN" "$OUT"

cp -r "$ROOT/core" "$ROOT/schemas" "$ROOT/rules" "$STAGE/opt/aidf/"
find "$STAGE" -type d -name __pycache__ -prune -exec rm -rf {} +
find "$STAGE" -type f -name '*.pyc' -delete
chmod 0755 "$STAGE"
install -m 0755 "$ROOT/scripts/aidf_agent.py" "$STAGE/opt/aidf/aidf_agent.py"
install -m 0644 "$ROOT/packaging/linux/agent.toml" "$STAGE/etc/aidf/agent.toml"
install -d "$STAGE/etc/logrotate.d"
install -m 0644 "$ROOT/packaging/linux/aidf-logrotate" "$STAGE/etc/logrotate.d/aidf"
install -d "$STAGE/opt/aidf/wheels"
install -m 0644 "$ROOT/packaging/linux/wheels"/*.whl "$STAGE/opt/aidf/wheels/"
install -m 0644 "$ROOT/packaging/linux/aidf-auditd.service" \
    "$STAGE/lib/systemd/system/aidf-auditd.service"
install -d "$STAGE/opt/aidf/docs"
install -m 0644 "$ROOT/docs/linux-auditd.md" "$STAGE/opt/aidf/docs/linux-auditd.md"
install -m 0644 "$ROOT/docs/linux-ebpf-guard.md" "$STAGE/opt/aidf/docs/linux-ebpf-guard.md"
install -d "$STAGE/opt/aidf/agent/gui"
install -m 0644 "$ROOT/agent/gui/index.html" "$STAGE/opt/aidf/agent/gui/index.html"

if [ -n "$OBJECTS" ]; then
    if [ ! -x "$OBJECTS/loader" ]; then
        echo "error: $OBJECTS/loader not executable" >&2
        exit 2
    fi
    install -m 0755 "$OBJECTS/loader" "$STAGE/opt/aidf/loader"
    if [ -x "$OBJECTS/aidf-enforce" ]; then
        install -m 0755 "$OBJECTS/aidf-enforce" "$STAGE/opt/aidf/aidf-enforce"
    fi
    for obj in "$OBJECTS"/*.bpf.o; do
        [ -e "$obj" ] || continue
        install -m 0644 "$obj" "$STAGE/opt/aidf/"
    done
    install -m 0644 "$ROOT/packaging/linux/enforce.policy" "$STAGE/etc/aidf/enforce.policy"
    install -m 0644 "$ROOT/packaging/linux/aidf-ebpf-guard.service" \
        "$STAGE/lib/systemd/system/aidf-ebpf-guard.service"
    for extra in objects.sha256 objects.sha256.sig objects.sha256.pub; do
        if [ -f "$ROOT/packaging/linux/$extra" ]; then
            install -m 0644 "$ROOT/packaging/linux/$extra" "$STAGE/opt/aidf/$extra"
        fi
    done
fi

cat > "$STAGE/DEBIAN/control" <<EOF
Package: aidf-auditd
Version: $VERSION
Section: admin
Priority: optional
Architecture: $ARCH
Maintainer: AIDefender <local@localhost>
Depends: python3 (>= 3.10), python3-venv, auditd
Description: AIDefender Linux auditd agent
 Reads auditd records, normalizes them to Event v3 and writes report JSONL
 for the STML connector. No network access from the detector itself.
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
rm -rf /opt/aidf/venv
python3 -m venv --system-site-packages /opt/aidf/venv
/opt/aidf/venv/bin/pip install -q --upgrade --no-index --find-links /opt/aidf/wheels "pydantic>=2"
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable aidf-auditd >/dev/null 2>&1 || true
systemctl restart aidf-auditd >/dev/null 2>&1 || true
exit 0
EOF
cat > "$STAGE/DEBIAN/prerm" <<'EOF'
#!/bin/sh
set -e
systemctl stop aidf-auditd >/dev/null 2>&1 || true
exit 0
EOF
cat > "$STAGE/DEBIAN/postrm" <<'EOF'
#!/bin/sh
set -e
rm -rf /opt/aidf/venv
python3 -m venv --system-site-packages /opt/aidf/venv
/opt/aidf/venv/bin/pip install -q --upgrade --no-index --find-links /opt/aidf/wheels "pydantic>=2"
systemctl daemon-reload >/dev/null 2>&1 || true
exit 0
EOF
chmod 0755 "$STAGE/DEBIAN/postinst" "$STAGE/DEBIAN/prerm" "$STAGE/DEBIAN/postrm"

export SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-1700000000}"
find "$STAGE" -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
dpkg-deb --build --root-owner-group "$STAGE" "$OUT/aidf-auditd_${VERSION}_${ARCH}.deb" >/dev/null
tar -C "$STAGE" -czf "$OUT/aidf-auditd-${VERSION}.tar.gz" opt etc lib

cat > "$OUT/aidf-auditd.spec" <<EOF
Name:           aidf-auditd
Version:        $VERSION
Release:        1%{?dist}
Summary:        AIDefender Linux auditd agent
License:        Proprietary
BuildArch:      x86_64
Requires:       python3 >= 3.10, audit

%description
Reads auditd records, normalizes them to Event v3 and writes report JSONL
for the STML connector.

%install
mkdir -p %{buildroot}/opt/aidf %{buildroot}/etc/aidf %{buildroot}/lib/systemd/system
cp -r $STAGE/opt/aidf/* %{buildroot}/opt/aidf/
cp $STAGE/etc/aidf/agent.toml %{buildroot}/etc/aidf/agent.toml
cp $STAGE/lib/systemd/system/aidf-auditd.service %{buildroot}/lib/systemd/system/

%files
/opt/aidf
%config(noreplace) /etc/aidf/agent.toml
/lib/systemd/system/aidf-auditd.service

%post
systemctl daemon-reload >/dev/null 2>&1 || true
systemctl enable aidf-auditd >/dev/null 2>&1 || true
systemctl restart aidf-auditd >/dev/null 2>&1 || true

%preun
systemctl stop aidf-auditd >/dev/null 2>&1 || true

%postun
systemctl daemon-reload >/dev/null 2>&1 || true
EOF

if command -v rpmbuild >/dev/null 2>&1; then
    TOP=$(mktemp -d)
    mkdir -p "$TOP"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}
    cp "$OUT/aidf-auditd.spec" "$TOP/SPECS/"
    rpmbuild --define "_topdir $TOP" -bb "$TOP/SPECS/aidf-auditd.spec" >/dev/null
    find "$TOP/RPMS" -name '*.rpm' -exec cp {} "$OUT/" \;
    rm -rf "$TOP"
else
    echo "rpmbuild not found; wrote $OUT/aidf-auditd.spec" >&2
fi

echo "built:"
ls -1 "$OUT"/aidf-auditd* 2>/dev/null || true









