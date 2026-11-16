"""Build the browser's root list from Mozilla's NSS certdata.txt.

Keeps only certificates that Mozilla trusts to issue website (server
authentication) certificates, i.e. CKA_TRUST_SERVER_AUTH ==
CKT_NSS_TRUSTED_DELEGATOR, and drops roots whose
CKA_NSS_SERVER_DISTRUST_AFTER date is already in the past (Mozilla stopped
trusting new website certificates from them).

Usage: python make_roots.py certdata.txt roots.pem
"""
import base64
import datetime
import sys


def parse(path):
    objs, cur, lines = [], None, open(path, encoding="utf-8").read().split("\n")
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        i += 1
        if not line or line.startswith("#"):
            continue
        if line.startswith("CKA_CLASS"):
            cur = {}
            objs.append(cur)
        if cur is None:
            continue
        parts = line.split(" ", 2)
        if len(parts) >= 2 and parts[1] == "MULTILINE_OCTAL":
            data = bytearray()
            while lines[i].strip() != "END":
                for o in lines[i].strip().split("\\")[1:]:
                    data.append(int(o, 8))
                i += 1
            i += 1
            cur[parts[0]] = bytes(data)
        elif len(parts) == 3:
            cur[parts[0]] = parts[2].strip('"') if parts[1] == "UTF8" else parts[2]
        elif len(parts) == 2:
            cur[parts[0]] = parts[1]
    return objs


def distrusted(value, now):
    if not isinstance(value, bytes):
        return False  # CK_FALSE
    stamp = value.decode("ascii")  # YYMMDDHHMMSSZ
    when = datetime.datetime.strptime(stamp, "%y%m%d%H%M%SZ").replace(tzinfo=datetime.timezone.utc)
    return when <= now


def main(src, dst):
    now = datetime.datetime.now(datetime.timezone.utc)
    objs = parse(src)
    trust = {}
    for o in objs:
        if o.get("CKA_CLASS") == "CKO_NSS_TRUST":
            trust[(o.get("CKA_ISSUER"), o.get("CKA_SERIAL_NUMBER"))] = o.get("CKA_TRUST_SERVER_AUTH")
    out, kept, skipped = [], 0, []
    for o in objs:
        if o.get("CKA_CLASS") != "CKO_CERTIFICATE":
            continue
        label = o.get("CKA_LABEL", "?")
        if trust.get((o.get("CKA_ISSUER"), o.get("CKA_SERIAL_NUMBER"))) != "CKT_NSS_TRUSTED_DELEGATOR":
            continue
        if distrusted(o.get("CKA_NSS_SERVER_DISTRUST_AFTER"), now):
            skipped.append(label)
            continue
        b64 = base64.b64encode(o["CKA_VALUE"]).decode()
        out.append("# " + label + "\n-----BEGIN CERTIFICATE-----\n"
                   + "\n".join(b64[j:j + 64] for j in range(0, len(b64), 64))
                   + "\n-----END CERTIFICATE-----\n")
        kept += 1
    open(dst, "w", encoding="utf-8", newline="\n").write("\n".join(out))
    print("kept", kept, "roots; skipped (distrust-after in the past):", skipped)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
