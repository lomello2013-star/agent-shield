"""F10: allow a weak 'any validly signed binary' policy to be *measured* as a tradeoff."""

import io

PATH = "core/appcontrol.py"
text = io.open(PATH, encoding="utf-8").read()

old_init = '''    def __init__(self, signers: Iterable[str] = (), paths: Iterable[str] = (),
                 hashes: Iterable[str] = ()) -> None:
        self.signers = {s.lower() for s in signers}
        self.paths = tuple(paths)
        self.hashes = {h.lower() for h in hashes}'''
new_init = '''    def __init__(self, signers: Iterable[str] = (), paths: Iterable[str] = (),
                 hashes: Iterable[str] = (), signed_any: bool = False) -> None:
        self.signers = {s.lower() for s in signers}
        self.paths = tuple(paths)
        self.hashes = {h.lower() for h in hashes}
        # F10: "any validly signed binary" is a real (weak) WDAC option; measured as a
        # tradeoff against the publisher allowlist, not recommended as the default.
        self.signed_any = signed_any'''
if old_init not in text:
    raise SystemExit("init anchor not found")
text = text.replace(old_init, new_init, 1)

old_decide = '''        if entry.tbs_sha256 and entry.tbs_sha256.lower() in self.signers:
            return AllowlistDecision(True, "signer")'''
new_decide = '''        if self.signed_any and entry.signed:
            return AllowlistDecision(True, "signed_any")
        if entry.tbs_sha256 and entry.tbs_sha256.lower() in self.signers:
            return AllowlistDecision(True, "signer")'''
if old_decide not in text:
    raise SystemExit("decide anchor not found")
text = text.replace(old_decide, new_decide, 1)

io.open(PATH, "w", encoding="utf-8", newline="\n").write(text)
print("signed_any added:", "signed_any" in text)
