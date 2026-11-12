"""Debug why the benign stream triggers FILE-MASS-WRITE-014."""

import sys
sys.path.insert(0, "scripts")
sys.path.insert(0, ".")

import f12_behavioral as h

clock = h.Clock()
writes = []
for day in range(h.DAYS):
    for ev in h.benign_day(day, clock):
        if ev.category == "file.write":
            writes.append(clock.t)

print("writes:", len(writes))
worst = 0
for i, t in enumerate(writes):
    n = sum(1 for u in writes[i:] if u - t <= 10)
    worst = max(worst, n)
print("max writes in any 10 s window:", worst)
print("first 6 times:", writes[:6])
