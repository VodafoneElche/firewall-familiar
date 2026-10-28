"""Genera src/FirewallFamiliar/Assets/indicadores.txt: dominios, IPs y huellas (SHA-256)
de programas espía conocidos (spyware de gobiernos y "stalkerware").

Las listas son las públicas que usan Amnesty International (MVT), Citizen Lab y ECHAP,
las mismas que el proyecto Zero Breach Toolkit. Cada archivo se descarga en una versión
fija (commit) y se comprueba con su SHA-256 antes de usarlo: si alguien cambiara la
lista en origen, no entraría sin que lo revisemos.

Uso:  python tools/indicadores.py        (necesita Internet; solo la biblioteca estándar)
"""

import csv
import hashlib
import io
import ipaddress
import json
import os
import re
import sys
import urllib.request

RAW = "https://raw.githubusercontent.com/"
PINS = {
    "AmnestyTech/investigations": "3d8f248a0d015f183724ae7d096a5c46a8bb5fc7",
    "AssoEchap/stalkerware-indicators": "426156175adc84af7fbdd41486c046f9ecb40436",
    "citizenlab/malware-indicators": "7a7ae9278fa2c0252e9e40faed9b498d6a8d5248",
    "mvt-project/mvt-indicators": "b22ddf05e1a31e7732b8895676987c5c3482ef65",
}

# (familia, repositorio, ruta, formato, sha256)
SOURCES = [
    ("Pegasus (NSO)", "AmnestyTech/investigations", "2021-07-18_nso/pegasus.stix2", "stix2", "df1bcaa78abc7b85781b1ebc2daa3cc225371e2024d9ef96e84f80f927256586"),
    ("Predator (Intellexa)", "mvt-project/mvt-indicators", "intellexa_predator/predator.stix2", "stix2", "99938ba179216f73e54513c4c537e3951ae860bcc6eaa5a93055f4afbb689879"),
    ("RCS Lab", "mvt-project/mvt-indicators", "2022-06-23_rcs_lab/rcs.stix2", "stix2", "db7473900259bc28ef20145c315af5bcb99451715703bc78563338f656b213b2"),
    ("Stalkerware", "AssoEchap/stalkerware-indicators", "generated/stalkerware.stix2", "stix2", "60307b49256d726a55e5b29e5243113021b26f2c91b492da4bcd2eb579739a98"),
    ("Espía Android (2023)", "AmnestyTech/investigations", "2023-03-29_android_campaign/malware.stix2", "stix2", "28da50042006281d56c17dff08f06bba3ba310bc18cc23040780850131b2efdb"),
    ("QuaDream KingSpawn", "mvt-project/mvt-indicators", "2023-04-11_quadream/kingspawn.stix2", "stix2", "fd47acd30388738083fb1e4e09ce7f2032885ec1217a5edc75ef8e71a81fee3f"),
    ("Operation Triangulation", "mvt-project/mvt-indicators", "2023-06_01_operation_triangulation/operation_triangulation.stix2", "stix2", "320a3aa1147f7c87b92db46a6c977c75d721d74e8266978dc74d9ed2ca7383f5"),
    ("WyrmSpy / DragonEgg", "mvt-project/mvt-indicators", "2023-07-25_wyrmspy_dragonegg/wyrmspy_dragonegg.stix2", "stix2", "b5495ca605b2150e76bb8322cfc6f484382db6070f806672f70edf3b0511e4f3"),
    ("Wintego Helios", "AmnestyTech/investigations", "2024-05-02_wintego_helios/wintego_helios.stix2", "stix2", "d0d546c388207e8a162eb3901259ee20c0ddd03efeff145d3cc9b3a0a02a5419"),
    ("NoviSpy", "AmnestyTech/investigations", "2024-12-16_serbia_novispy/novispy.stix2", "stix2", "02bfceea5a2c32b159f11569736448398e35e7f0fc7d137385b943ec60697360"),
    ("EagleMsgSpy", "mvt-project/mvt-indicators", "2024-12-25_eaglemsgspy/eaglemsgspy.stix2", "stix2", "033af3e26f764ace084d8ed3cdb6eeba833b1d9d1f2708fd65289e12a45136b5"),
    ("Candiru (DevilsTongue)", "mvt-project/mvt-indicators", "candiru/candiru.stix2", "stix2", "684f9e60da472ec938c7cd003adb3e3b97d29a0a43fed7565c9ef29c19bedb86"),
    ("ResidentBat", "mvt-project/mvt-indicators", "ResidentBat/residentbat.stix2", "stix2", "d52ca6753a80578a25df2b907ae5dd3305b00e2345baa843d0c91dfac52c50c5"),
    ("Cellebrite", "mvt-project/mvt-indicators", "cellebrite/cellebrite.stix2", "stix2", "054436c35a1e715ff2ea55a9516364108239cde238afdd096b21c3da90f97d2a"),
    ("DarkSword", "mvt-project/mvt-indicators", "2026-03-30_darksword/darksword.stix2", "stix2", "a694a8f3a37866ae30d72aab84fffd3a89d848406adfc0eac3237805b1c6826c"),
    ("Coruna", "mvt-project/mvt-indicators", "2026-03-03_coruna_cryptowaters/coruna.stix2", "stix2", "653887014af347a107144036c9388af714f7a728661d6026dbe8b66db4acbfe4"),
    ("Morpheus", "mvt-project/mvt-indicators", "2026-04-23_ips_morpheus/morpheus.stix2", "stix2", "fa327338e33b017f8633a33ddc2a0364a1ecfa8fd99b821e53a5c2e4cdb33094"),
    ("BTMOB", "mvt-project/mvt-indicators", "2026-05-26_btmob/btmob.stix2", "stix2", "6bada3d46e6ac53019d80ccea991611125e8eefdd00b5bd0ea23ac48f2dca15a"),
    ("Spyrtacus", "mvt-project/mvt-indicators", "2026-04-09_sio_spyrtacus/spyrtacus.stix2", "stix2", "44a7f68629cfeb5952a646986f5ef24395656631d6cca636bf283c024714ad4e"),
    ("Pegasus (NSO, 2018)", "AmnestyTech/investigations", "2018-08-01_nso/indicators.csv", "csv-domain-ip", "4e450de9219a6cb9a6888c352abb5e8b62fa33ebadd70238e5f69a5a08329579"),
    ("Pegasus (NSO, Marruecos 2019)", "AmnestyTech/investigations", "2019-10-10_nso_morocco/domains.txt", "domains-txt", "29c183256cee9c04147e09bd50d29094f85a8b40dec500aa00ffcf02b368f63e"),
    ("Predator (Cytrox, 2021)", "AmnestyTech/investigations", "2021-12-16_cytrox/cytrox.stix2", "stix2", "6fe92193d9e17c21a16eb7abe93a418a2e40c0176dcb56fb30539f84136391bb"),
    ("FinFisher / FinSpy", "AmnestyTech/investigations", "2020-09-25_finfisher/domains.txt", "domains-txt", "cc5d59d5f868984bae06df93989d95f49670d808dafbbefadd4bc0df0573b6de"),
    ("Pegasus (NSO, 2016)", "citizenlab/malware-indicators", "201608_NSO_Group/iocs.csv", "misp-csv", "7c005140f65b4043c7fad35a7c39ceeb51da5133810c2b0b4b57428f33a3ceed"),
    ("Cyberbit", "citizenlab/malware-indicators", "201712_Cyberbit/iocs.csv", "misp-csv", "3ca53475a3c96630b5c9fb42fba688b9123fcd21a236de41ef0f53ba419e70d1"),
    ("Pegasus (NSO, 2018)", "citizenlab/malware-indicators", "201810_TheKingdomCameToCanada/iocs.csv", "misp-csv", "835b1a105a4f16b994013955bc41bfedc32eff56f586bf3faadea9888498c506"),
    ("Pegasus (NSO, México 2017)", "citizenlab/malware-indicators", "201706_RecklessExploit/iocs.csv", "misp-csv", "b260da1f4e1dd15cfc804be734431c602bb6abee00bf8c5cc4c4e41d3638280a"),
    ("Pegasus (NSO, México 2017)", "citizenlab/malware-indicators", "201706_RecklessRedux/iocs.csv", "misp-csv", "62d614e4f11a1652ef8020676269b9cfc85b6b0db36e45b43a4d397776387c5d"),
    ("Pegasus (NSO, México 2017)", "citizenlab/malware-indicators", "201707_InsiderInfo/indicators.csv", "misp-csv", "87cd4cb85b4a3808ff231f6c22e79f387328ba1b36ab576b61b455562f8afbc2"),
]

# Servicios públicos compartidos: en las listas aparecen enlaces concretos (bit.ly/xxx),
# pero el servicio entero no es malo. Nunca se marcan.
SHARED = set("""
bit.ly bitly.com j.mp tinyurl.com goo.gl t.co ow.ly is.gd v.gd buff.ly rebrand.ly cutt.ly
shorturl.at tiny.cc lnkd.in t.ly rb.gy s.id google.com googleusercontent.com googleapis.com
storage.googleapis.com docs.google.com drive.google.com sites.google.com blogspot.com
dropbox.com dropboxusercontent.com dl.dropboxusercontent.com github.com gist.github.com
api.github.com github.io githubusercontent.com raw.githubusercontent.com
gist.githubusercontent.com objects.githubusercontent.com pastebin.com mediafire.com mega.nz
wetransfer.com facebook.com fb.com instagram.com twitter.com x.com t.me telegram.me
telegram.org wa.me whatsapp.com youtube.com youtu.be firebaseio.com firebaseapp.com
web.app appspot.com amazonaws.com cloudfront.net azurewebsites.net herokuapp.com
000webhostapp.com ngrok.io duckdns.org no-ip.com ddns.net
""".split())

DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}$")
SHA_RE = re.compile(r"^[0-9a-f]{64}$")
STIX_RE = re.compile(r"(domain-name|ipv4-addr|ipv6-addr|url|file:hashes\.(?:'?SHA-?256'?|sha256))(?::value)?\s*=\s*'([^']*)'", re.I)


def fetch(repo, path, sha):
    url = RAW + repo + "/" + PINS[repo] + "/" + path
    with urllib.request.urlopen(url, timeout=60) as r:
        data = r.read(64 * 1024 * 1024)
    got = hashlib.sha256(data).hexdigest()
    if got != sha:
        sys.exit(f"HUELLA DISTINTA en {url}: {got} (esperada {sha}). No se usa.")
    return data.decode("utf-8-sig", "replace")


def clean(kind, value):
    v = (value or "").strip().strip('"').strip().lower().replace("[.]", ".").replace("[dot]", ".")
    if kind == "url":
        m = re.match(r"^[a-z][a-z0-9+.-]*://([^/:?#]+)", v.replace("hxxp", "http"))
        if not m:
            return None
        kind, v = "domain", m.group(1)
    if kind in ("domain", "ip"):
        v = v.rstrip(".")
        try:
            ip = ipaddress.ip_address(v)
            if not ip.is_global:
                return None
            return ("ip", str(ip))
        except ValueError:
            pass
        if kind == "ip":
            return None
        if v.startswith("www.") and v[4:] in SHARED:
            return None
        if v in SHARED or any(v.endswith("." + s) for s in SHARED):
            return None
        return ("domain", v) if DOMAIN_RE.match(v) else None
    if kind == "sha256":
        return ("sha256", v) if SHA_RE.match(v) else None
    return None


# "Watchware": apps de control parental que no se esconden (Microsoft Family, Life360,
# Qustodio, Kaspersky Safe Kids...). ECHAP las incluye en la misma lista, pero en casa
# pueden estar instaladas a propósito: no se avisan ni se bloquean.
WATCHWARE = ("AssoEchap/stalkerware-indicators", "watchware.yaml",
             "e1e54f8bcd762aa6309b297153b7aa6e55267fc6bac7f77a9347467b30967708")


def watchware_names():
    text = fetch(*WATCHWARE)
    names, in_names = set(), False
    for line in text.splitlines():
        m = re.match(r"^- name:\s*(.+)$", line)
        if m:
            names.add(m.group(1).strip().lower())
            in_names = False
            continue
        if re.match(r"^  names:\s*$", line):
            in_names = True
            continue
        m = re.match(r"^  - (.+)$", line)
        if in_names and m:
            names.add(m.group(1).strip().lower())
        elif not line.startswith("  -"):
            in_names = False
    return names


SKIP_NAMES = set()


def parse(text, fmt):
    out = []
    if fmt == "stix2":
        objs = json.loads(text).get("objects", [])
        malware = {o["id"]: (o.get("name") or "").lower() for o in objs if o.get("type") == "malware"}
        skip = {r.get("source_ref") for r in objs if r.get("type") == "relationship"
                and malware.get(r.get("target_ref")) in SKIP_NAMES}
        for obj in objs:
            if obj.get("type") != "indicator" or obj.get("id") in skip:
                continue
            for k, val in STIX_RE.findall(obj.get("pattern", "")):
                k = k.lower()
                kind = "domain" if k == "domain-name" else "ip" if k.endswith("-addr") else "url" if k == "url" else "sha256"
                out.append(clean(kind, val))
    elif fmt == "domains-txt":
        for line in text.splitlines():
            if line.strip() and not line.strip().startswith("#"):
                out.append(clean("domain", line))
    elif fmt == "csv-domain-ip":
        for row in csv.DictReader(io.StringIO(text)):
            for key, val in row.items():
                if val and key and "domain" in key.lower():
                    out.append(clean("domain", val))
                elif val and key and "ip" in key.lower():
                    out.append(clean("ip", val))
    elif fmt == "misp-csv":
        kinds = {"domain": "domain", "hostname": "domain", "ip-dst": "ip", "ip-src": "ip", "sha256": "sha256", "url": "url"}
        for row in csv.DictReader(io.StringIO(text)):
            kind = kinds.get((row.get("type") or "").strip().lower())
            if kind:
                out.append(clean(kind, row.get("value")))
    return [x for x in out if x]


def main():
    found = {}
    SKIP_NAMES.update(watchware_names())
    print("Control parental excluido:", len(SKIP_NAMES), "nombres")
    for family, repo, path, fmt, sha in SOURCES:
        items = parse(fetch(repo, path, sha), fmt)
        for kind, value in items:
            found.setdefault((kind, value), family)
        print(f"{family:35} {len(items):6}  {repo}/{path}")
    dest = os.path.join(os.path.dirname(__file__), "..", "src", "FirewallFamiliar", "Assets", "indicadores.txt")
    with open(dest, "w", encoding="utf-8", newline="\n") as f:
        f.write("# Indicadores de programas espía (Amnesty International / MVT, Citizen Lab, ECHAP).\n")
        f.write("# Generado por tools/indicadores.py a partir de versiones fijas comprobadas con SHA-256.\n")
        for (kind, value), family in sorted(found.items()):
            f.write(f"{kind}\t{value}\t{family}\n")
    counts = {}
    for kind, _ in found:
        counts[kind] = counts.get(kind, 0) + 1
    print("Total:", counts)


if __name__ == "__main__":
    main()
