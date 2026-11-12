import io

for path in ("spikes/04-ebpf/exec_tp.bpf.c", "spikes/04-ebpf/file_open_lsm.bpf.c"):
    text = io.open(path, encoding="utf-8-sig").read()
    text = text.replace("real_parent, pid)", "real_parent, tgid)")
    io.open(path, "w", encoding="utf-8", newline="\n").write(text)
    print(path, "->", "real_parent, tgid" in text)

loader = io.open("spikes/04-ebpf/loader.c", encoding="utf-8-sig").read()
print("net ppid in printf:", '\\"ppid\\":%u' in loader)
print("exec/lsm ppid in printf:", loader.count('ppid'))
