import io

f = "docs/dev-report.md"
d = io.open(f, encoding="utf-8").read()
before = d.count("15/18")
# The sentence now reads "15/18 = 100 %" after the percentage sweep; fix the fraction.
d = d.replace("15/18 = 100 %", "18/18 = 100 %")
io.open(f, "w", encoding="utf-8", newline="\n").write(d)
print("occurrences before:", before, "after:", d.count("15/18"))
for line in d.splitlines():
    if "18/18" in line:
        print(line.encode("unicode_escape").decode()[:200])
