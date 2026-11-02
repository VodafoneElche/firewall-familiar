#!/usr/bin/env python3
"""Genera src/FirewallFamiliar/Assets/fabricantes.txt: qué fabricante corresponde a cada
principio de dirección MAC (lista OUI oficial del IEEE).

La lista se saca del paquete netaddr de PyPI (lleva una copia del oui.txt del IEEE), fijado por
versión y huella SHA-256, para que nadie pueda colar otra lista. El programa la lleva dentro
y nunca la descarga: saber de qué marca es un aparato no necesita Internet.

Uso:  python3 tools/fabricantes.py
"""
import hashlib, io, re, sys, urllib.request, zipfile
from pathlib import Path

URL = "https://files.pythonhosted.org/packages/py3/n/netaddr/netaddr-1.3.0-py3-none-any.whl"
SHA256 = "c2c6a8ebe5554ce33b7d5b3a306b71bbb373e000bbbf2350dd5213cc56e3dbbe"
OUT = Path(__file__).resolve().parent.parent / "src/FirewallFamiliar/Assets/fabricantes.txt"

SUFFIX = re.compile(r"[\s,.]+(co\.?,?\s*ltd|co|ltd|limited|inc|corp|corporation|gmbh|s\.?a\.?|s\.?l\.?|llc|ag|bv|b\.v|oy|ab|as|plc|pty|srl|spa|kg|technologies|technology|electronics)\.?$", re.I)

def clean(name: str) -> str:
    name = " ".join(name.split())
    for _ in range(3):
        name = SUFFIX.sub("", name).strip(" ,.")
    return name[:60]

def main(local=None):
    data = Path(local).read_bytes() if local else urllib.request.urlopen(URL, timeout=120).read()
    if hashlib.sha256(data).hexdigest() != SHA256:
        sys.exit("La huella SHA-256 del paquete no coincide: no se usa.")
    text = zipfile.ZipFile(io.BytesIO(data)).read("netaddr/eui/oui.txt").decode("utf-8", "replace")
    rows = {}
    for m in re.finditer(r"^([0-9A-F]{2})-([0-9A-F]{2})-([0-9A-F]{2})\s+\(hex\)\s+(.+?)\s*$", text, re.M):
        rows[m[1] + m[2] + m[3]] = clean(m[4])
    lines = ["# Fabricantes por MAC (IEEE OUI, vía netaddr 1.3.0). Generado por tools/fabricantes.py; no editar a mano."]
    lines += [f"{k}\t{v}" for k, v in sorted(rows.items())]
    OUT.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"{len(rows)} fabricantes -> {OUT}")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else None)
