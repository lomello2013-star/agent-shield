#!/usr/bin/env python3
"""Enable the BPF LSM in GRUB (lab VM only)."""
from __future__ import annotations

import pathlib

PATH = pathlib.Path("/etc/default/grub")
OLD = 'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash"'
NEW = ('GRUB_CMDLINE_LINUX_DEFAULT="quiet splash '
       'lsm=lockdown,capability,landlock,yama,apparmor,bpf"')

text = PATH.read_text(encoding="utf-8")
if "lsm=" in text and "bpf" in text:
    print("default already enabled")
elif OLD in text:
    PATH.write_text(text.replace(OLD, NEW), encoding="utf-8")
    print("default updated")
else:
    print("default pattern not found")

# Cloud images set GRUB_CMDLINE_LINUX in /etc/default/grub.d/99-ima.cfg;
# that value wins over GRUB_CMDLINE_LINUX_DEFAULT.
IMA = pathlib.Path("/etc/default/grub.d/99-ima.cfg")
if IMA.exists():
    text = IMA.read_text(encoding="utf-8")
    if "lsm=" in text and "bpf" in text:
        print("ima already enabled")
    else:
        text = text.replace(
            'GRUB_CMDLINE_LINUX="',
            'GRUB_CMDLINE_LINUX="lsm=lockdown,capability,landlock,yama,apparmor,bpf ',
            1,
        )
        IMA.write_text(text, encoding="utf-8")
        print("ima updated")
