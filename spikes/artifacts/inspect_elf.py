import json,sys
p = sys.argv[1]
with open(p) as fh:
    line = fh.readline()
d = json.loads(line)
print("KEYS:", list(d.keys()))
for k,v in d.items():
    if isinstance(v, dict):
        print(k, "dict keys:", list(v.keys()))
    elif isinstance(v, list):
        print(k, "list len:", len(v), "head:", v[:4])
    else:
        print(k, "=", v)
