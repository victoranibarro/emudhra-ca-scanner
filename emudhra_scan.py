#!/usr/bin/env python3
"""
emudhra_scan.py - Auditoría remota del compromiso de las CAs de eMudhra
(raíz emSign ECC Root CA - G3; avisos GHSA-6q48-6c7w-9gw2 y CVE-2026-111943).

Desde UNA máquina recorre una lista de servidores y en cada uno:

  Modo SSH (por defecto): entra por SSH (sin agente, sin instalar nada) y revisa:
    * Si la raíz emSign ECC Root CA - G3 sigue en el almacén del sistema o en
      algún cacert.pem / ca-bundle embebido (apps, venvs, capas de Docker...)
    * La versión de ca-certificates contra la versión corregida de su distro
    * certifi (Python) >= 2026.10.19 y el archivo que realmente usa
    * Node.js >= 22.23.4 / 24.22.1 / 26.12.1
    * Go >= 1.26.10 / 1.27.3 (los binarios ya compilados hay que recompilarlos)
    * El cacerts de Java
    * Prueba real: curl desde el servidor a los sitios de prueba (opcional)

  Modo TLS (--tls-ports), sin credenciales: se conecta a los puertos indicados
    y avisa si el servidor PRESENTA un certificado de la jerarquía de eMudhra.

Uso:
  python3 emudhra_scan.py hosts.txt                       # tu usuario y ~/.ssh/config
  python3 emudhra_scan.py hosts.txt -u ubuntu -i ~/.ssh/llave.pem --sudo
  python3 emudhra_scan.py hosts.txt -u admin -p --sudo    # pide la contraseña una vez (sshpass)
  EMUDHRA_SSH_PASS='...' python3 emudhra_scan.py hosts.txt -u admin   # para CI
  python3 emudhra_scan.py hosts.txt --tls-only --tls-ports 443
  python3 emudhra_scan.py hosts.txt --csv reporte.csv

hosts.txt: un servidor por línea ("host", "usuario@host" o "host:puerto").
           Las líneas que empiezan con # se ignoran. "local" audita esta máquina.

Salida: una tarjeta por servidor + CSV opcional. Código de salida 1 si hay
algún servidor VULNERABLE.
Requisitos en tu equipo: Python 3.8+, ssh; openssl solo para --tls-ports.
"""
import argparse, concurrent.futures as cf, csv, getpass, os, re, shutil, subprocess, sys, threading, time

ROOT_FP = "86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B"  # emSign ECC Root CA - G3
TEST_HOSTS = ["dv-g3b-emudhra.we-have-a-problem.com", "dv-g3b-aaa-emudhra.we-have-a-problem.com"]

# Versiones corregidas de ca-certificates (fuente: Endor Labs, 2026-10)
CA_FIXED = {
    ("ubuntu", "22.04"): "20260816ubuntu0.22.04.1",
    ("ubuntu", "24.04"): "20260816ubuntu0.24.04.1",
    ("ubuntu", "26.04"): "20260816ubuntu0.26.04.1",
    ("ubuntu", "26.10"): "20260816ubuntu0.26.10.1",
    ("debian", "12"):    "20250419~deb12u2",
    ("debian", "13"):    "20250419+deb13u1",
    ("debian", "*"):     "20260816+nmu1",       # testing / sid
    ("alpine", "*"):     "20261020-r0",
    ("fedora", "*"):     "2026.2.92_v9.0.319",
    ("arch", "*"):       "3.131.1-1",           # ca-certificates-mozilla
    ("wolfi", "*"):      "20260909-r3",         # Chainguard
}
NODE_FIXED = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
GO_FIXED = {26: (1, 26, 10), 27: (1, 27, 3)}
CERTIFI_FIXED = (2026, 10, 19)

# ---------------------------------------------------------------------------
# Script que corre en cada servidor (solo lectura). Imprime líneas CLAVE=VALOR.
# ---------------------------------------------------------------------------
REMOTE = r'''
FP="__FP__"
export LC_ALL=C
T0=$(date +%s)
step() { echo "##PASO [+$(( $(date +%s) - T0 ))s] $*" >&2; }
command -v timeout >/dev/null 2>&1 || timeout() { shift; "$@"; }
step "conectado como $(id -un) en $(hostname)"
step "sistema operativo y paquete ca-certificates"
. /etc/os-release 2>/dev/null; echo "OS_ID=${ID:-?}"; echo "OS_VER=${VERSION_ID:-?}"
v=$(dpkg-query -W -f='${Version}' ca-certificates 2>/dev/null) && echo "CA_PKG=dpkg:$v" && REQ="__REQ_LIST__"
[ -z "$v" ] && v=$(rpm -q --qf '%{VERSION}-%{RELEASE}' ca-certificates 2>/dev/null) && echo "CA_PKG=rpm:$v"
[ -z "$v" ] && v=$(apk info -e -v ca-certificates 2>/dev/null | sed 's/^ca-certificates-//') && [ -n "$v" ] && echo "CA_PKG=apk:$v"
[ -z "$v" ] && v=$(pacman -Q ca-certificates-mozilla 2>/dev/null | awk '{print $2}') && [ -n "$v" ] && echo "CA_PKG=pacman:$v"
# Comparación exacta con dpkg (las versiones Debian con ~ y + son delicadas)
if command -v dpkg >/dev/null 2>&1 && [ -n "${v:-}" ]; then
  for pair in __REQ_LIST__; do
    key=${pair%%=*}; req=${pair#*=}
    if [ "$key" = "${ID:-}:${VERSION_ID:-}" ] || { [ "$key" = "${ID:-}:*" ] && [ -z "${DONE:-}" ]; }; then
      dpkg --compare-versions "$v" ge "$req" && echo "CA_DPKG_OK=yes" || echo "CA_DPKG_OK=no:$req"; DONE=1
    fi
  done
fi
# Bundles de CA: el del sistema y los embebidos en apps, venvs y contenedores
if command -v openssl >/dev/null 2>&1; then
  T=$(mktemp -d)
  if [ "__FAST__" = "1" ]; then step "buscando bundles: solo los del sistema (modo rápido)"; FDIRS=""; echo "FAST=1"
  else step "buscando bundles embebidos en disco (máx. __FINDT__s; usa --fast para saltarlo)"
       FDIRS="/opt /usr/lib /usr/local /srv /home /root /var/lib /var/www /app"; fi
  CW=$(timeout 15 $(command -v python3 || command -v python || echo false) -c 'import certifi,os;print(os.path.realpath(certifi.where()))' 2>/dev/null)
  [ -n "$CW" ] && echo "CERTIFI_WHERE=$CW"
  { for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/cert.pem /etc/ssl/ca-bundle.pem $CW; do [ -r "$f" ] && echo "$f"; done
    [ -n "$FDIRS" ] && timeout __FINDT__ find $FDIRS -xdev \
      \( -name cacert.pem -o -name 'ca-bundle*.crt' -o -name 'ca-bundle*.pem' -o -name ca-certificates.crt \) \
      -type f 2>/dev/null | grep -v '^/proc' | head -300; } | sort -u > "$T/list"
  n=0; hits=""; step "revisando $(wc -l < "$T/list" | tr -d ' ') bundles contra la huella de la raíz G3"
  PYB=$(command -v python3 || command -v python)
  if [ -n "$PYB" ]; then
    # Ruta rápida: decodifica cada PEM y calcula su SHA-256 en Python
    res=$(timeout 120 "$PYB" - "$T/list" "$FP" <<'PYEOF'
import sys, re, base64, hashlib
lst, fp = sys.argv[1], sys.argv[2].lower()
n, hits = 0, []
for f in open(lst).read().split("\n"):
    if not f: continue
    n += 1
    sys.stderr.write("##PASO   bundle %d: %s\n" % (n, f)); sys.stderr.flush()
    try: txt = open(f, errors="ignore").read()
    except Exception: continue
    for b in re.findall(r"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", txt, re.S):
        try:
            if hashlib.sha256(base64.b64decode("".join(b.split()))).hexdigest() == fp:
                hits.append(f); break
        except Exception: pass
print("%d|%s" % (n, " ".join(hits)))
PYEOF
)
    n=${res%%|*}; hits=${res#*|}
  else
  while read -r f; do
    n=$((n+1)); rm -f "$T"/c*.pem; step "  bundle $n: $f"
    awk -v d="$T" '/BEGIN CERT/{k++} k{print > (d "/c" k ".pem")}' "$f" 2>/dev/null
    for c in "$T"/c*.pem; do
      [ -f "$c" ] || continue
      x=$(openssl x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d :)
      [ "$x" = "$FP" ] && hits="$hits $f" && break
    done
  done < "$T/list"
  fi
  rm -rf "$T"; echo "BUNDLES_CHECKED=$n"; echo "G3_IN=${hits# }"
else echo "BUNDLES_CHECKED=no-openssl"; fi
# Runtimes (lenguajes)
step "python / certifi"
for py in python3 python; do command -v $py >/dev/null 2>&1 && { c=$(timeout 15 $py -c 'import certifi;print(certifi.__version__)' 2>/dev/null); [ -n "$c" ] && echo "CERTIFI=$c"; break; }; done
step "node / go"
command -v node >/dev/null 2>&1 && echo "NODE=$(timeout 10 node -v 2>/dev/null)"
command -v go   >/dev/null 2>&1 && echo "GO=$(timeout 10 go env GOVERSION 2>/dev/null)"
if command -v keytool >/dev/null 2>&1; then
  step "java cacerts"
  timeout 30 keytool -list -cacerts -storepass changeit -v 2>/dev/null | tr -d : | grep -qi "$FP" && echo "JAVA_G3=yes" || echo "JAVA_G3=no"
fi
if command -v docker >/dev/null 2>&1; then
  step "docker images"
  { [ -r /var/lib/containerd ] && [ -x /var/lib/containerd ]; } || { [ -r /var/lib/docker ] && [ -x /var/lib/docker ]; } && echo "LAYERS_READABLE=yes"
  echo "DOCKER_IMAGES=$(timeout 15 docker images -q 2>/dev/null | sort -u | wc -l | tr -d ' ')"
fi
# Prueba real desde el servidor
if [ "__LIVE__" = "1" ] && command -v curl >/dev/null 2>&1; then
  for h in __TEST_HOSTS__; do step "curl hacia $h (máx. 8s)"; curl -s -o /dev/null --max-time 8 "https://$h/"; echo "CURL_${h%%.*}=$?"; done
fi
step "terminado"
'''

def build_remote(args=None):
    req = " ".join(f"{d}:{v}={r}" for (d, v), r in CA_FIXED.items())
    fast = "1" if args is not None and args.fast else "0"
    findt = str(args.find_timeout) if args is not None else "60"
    return (REMOTE.replace("__FP__", ROOT_FP).replace("__REQ_LIST__", req)
                  .replace("__TEST_HOSTS__", " ".join(TEST_HOSTS))
                  .replace("__FAST__", fast).replace("__FINDT__", findt)
                  .replace("__LIVE__", "0" if getattr(args, "no_live_test", False) else "1"))

_print_lock = threading.Lock()
def log(host, msg):
    with _print_lock:
        print(f"\033[90m{time.strftime('%H:%M:%S')}\033[0m [{host}] {msg}", file=sys.stderr, flush=True)

def nums(s):
    return tuple(int(x) for x in re.findall(r"\d+", s or ""))

def run_ssh(target, args):
    if target == "local":
        cmd = ["bash", "-s"]
    else:
        host, port = target, None
        if re.match(r"^[^\[\]]+:\d+$", target) and target.count(":") == 1:
            host, port = target.rsplit(":", 1)
        cmd = ["ssh", "-o", f"BatchMode={'no' if args.password else 'yes'}",
               "-o", f"ConnectTimeout={args.timeout}", "-o", "StrictHostKeyChecking=accept-new"]
        if args.password:
            cmd = ["sshpass", "-e"] + cmd + ["-o", "NumberOfPasswordPrompts=1"]
        if port: cmd += ["-p", port]
        if args.identity: cmd += ["-i", args.identity]
        if args.user and "@" not in host: host = f"{args.user}@{host}"
        if args.verbose >= 2: cmd.insert(cmd.index("ssh") + 1, "-v")
        if not args.sudo:
            remote_cmd = "bash -s"
        elif args.password:
            # Lee la contraseña de la primera línea, guarda el script en un archivo temporal
            # y lo corre con sudo -S (también funciona si el usuario tiene NOPASSWD).
            remote_cmd = ("T=$(mktemp); IFS= read -r P; cat > \"$T\"; "
                          "printf '%s\\n' \"$P\" | sudo -S -p '' bash \"$T\"; r=$?; rm -f \"$T\"; exit $r")
        else:
            remote_cmd = "sudo -n bash -s"
        cmd += [host, remote_cmd]
    env = dict(os.environ, SSHPASS=args.password) if args.password else None
    script = build_remote(args)
    if args.sudo and args.password and target != "local":
        script = args.password + "\n" + script
    v = args.verbose
    if v:
        shown = " ".join(c for c in cmd)
        log(target, f"iniciando: {shown}")
    t0 = time.time()
    try:
        p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, text=True, env=env)
    except FileNotFoundError as e:
        return None, f"no se encontró el comando {e.filename} en esta máquina"
    err_lines = []
    def pump_err():
        for line in p.stderr:
            line = line.rstrip()
            if line.startswith("##PASO"):
                if v: log(target, line[7:])
            else:
                err_lines.append(line)
                if v >= 2 or (v and line and not line.startswith("debug")): log(target, "ssh: " + line)
    out_chunks = []
    th = threading.Thread(target=pump_err, daemon=True); th.start()
    to = threading.Thread(target=lambda: out_chunks.append(p.stdout.read()), daemon=True); to.start()
    limit = args.timeout + args.find_timeout + 120
    try:
        p.stdin.write(script); p.stdin.close()
    except BrokenPipeError:
        pass
    try:
        p.wait(timeout=limit)
    except subprocess.TimeoutExpired:
        p.kill(); p.wait()
        log(target, f"TIMEOUT tras {limit}s, se cancela")
        return None, f"timeout ({limit}s); usa -v para ver en qué paso se quedó, o --fast"
    th.join(5); to.join(5)
    out = "".join(out_chunks)
    if v: log(target, f"fin (código {p.returncode}, {time.time()-t0:.0f}s)")
    if p.returncode == 255 or (not out and p.returncode):
        msg = [l for l in err_lines if l and not l.startswith("debug")]
        if any("a password is required" in l or "sudo:" in l for l in msg):
            return None, "sudo pidió contraseña: quita --sudo o usa -p"
        return None, (msg or ["ssh error"])[-1][:140]
    data = {}
    for line in out.splitlines():
        if "=" in line:
            k, val = line.split("=", 1); data[k.strip()] = val.strip()
    return data, None

SYSTEM_BUNDLES = ("/etc/ssl/", "/etc/pki/")
SNAP_RE = re.compile(r"/var/lib/(?:containerd/[^/]+/snapshots/(\d+)|docker/overlay2/([0-9a-f]+))/")

def group_g3(paths):
    """Agrupa las rutas con la raíz G3 en categorías legibles."""
    g = {"system": [], "containers": [], "snapd": [], "apps": []}
    snaps = set()
    for p in paths:
        m = SNAP_RE.search(p)
        if m:
            g["containers"].append(p); snaps.add(m.group(1) or m.group(2))
        elif p.startswith("/var/lib/snapd/"):
            g["snapd"].append(p)
        elif p.startswith(SYSTEM_BUNDLES):
            g["system"].append(p)
        else:
            g["apps"].append(p)
    return g, len(snaps)

def evaluate(d):
    """Devuelve (estado, items). Cada item: (nivel, título, arreglo, detalle); nivel bad|warn|ok."""
    items = []
    bad  = lambda t, fix="", det="": items.append(("bad", t, fix, det))
    warn = lambda t, fix="", det="": items.append(("warn", t, fix, det))
    good = lambda t, det="": items.append(("ok", t, "", det))

    # --- Almacén del sistema / ca-certificates
    pkg = d.get("CA_PKG", "")
    have = pkg.split(":", 1)[-1] if pkg else ""
    osid, osver = d.get("OS_ID", "?"), d.get("OS_VER", "?")
    paths = d.get("G3_IN", "").split()
    g, nsnap = group_g3(paths)
    ca_bad = False
    if d.get("CA_DPKG_OK", "").startswith("no"):
        ca_bad = True
        bad(f"ca-certificates {have} es anterior a {d['CA_DPKG_OK'][3:]}",
            "sudo apt update && sudo apt install --only-upgrade ca-certificates")
    elif pkg and not pkg.startswith("dpkg"):
        req = CA_FIXED.get((osid, osver)) or CA_FIXED.get((osid, "*"))
        if req and nums(have) < nums(req):
            ca_bad = True
            bad(f"ca-certificates {have} es anterior a {req}", "actualiza el paquete ca-certificates")
        elif not req:
            warn(f"ca-certificates {have}: sin versión de referencia para {osid} {osver}",
                 "guíate por la revisión del almacén")
    elif not pkg:
        warn("no se encontró el paquete ca-certificates")
    if g["system"]:
        bad("El almacén del sistema contiene la raíz G3",
            "actualiza ca-certificates y luego: sudo update-ca-certificates --fresh", " ".join(g["system"]))
    elif not ca_bad and d.get("BUNDLES_CHECKED") not in (None, "no-openssl"):
        good(f"Almacén del sistema limpio (ca-certificates {have or '?'})")
    if d.get("BUNDLES_CHECKED") == "no-openssl":
        warn("sin openssl: no se pudieron revisar los bundles")

    # --- Bundles embebidos
    if g["containers"]:
        bad(f"Imágenes de contenedores: raíz G3 en {len(g['containers'])} bundles de {nsnap} capas",
            "reconstruye las imágenes (docker build --pull --no-cache), despliega y luego docker image prune -a",
            " ".join(g["containers"]))
    if g["snapd"]:
        bad("La caché de certificados de snapd contiene la raíz G3",
            "aparta /var/lib/snapd/pki/v1/merged/ca-certificates.crt, reinicia snapd y prueba: snap find hello", " ".join(g["snapd"]))
    if g["apps"]:
        shown = ", ".join(g["apps"][:2]) + (f" (+{len(g['apps'])-2} más)" if len(g["apps"]) > 2 else "")
        bad(f"Bundles de aplicaciones con la raíz G3: {shown}",
            "actualiza la app o el venv (pip install -U certifi) o reemplaza el PEM incluido", " ".join(g["apps"]))

    # --- Runtimes
    if "CERTIFI" in d:
        cw = d.get("CERTIFI_WHERE", "")
        if cw and cw in paths:
            bad(f"Python certifi {d['CERTIFI']}: su bundle contiene la raíz G3",
                'pip install -U "certifi>=2026.10.19"  (o apt install --only-upgrade python3-certifi)', cw)
        elif cw and nums(d["CERTIFI"]) < CERTIFI_FIXED:
            good(f"Python certifi {d['CERTIFI']} (versión vieja, pero usa {cw}, que está limpio)")
        elif nums(d["CERTIFI"]) < CERTIFI_FIXED:
            bad(f"Python certifi {d['CERTIFI']} es anterior a 2026.10.19",
                'pip install -U "certifi>=2026.10.19"  (o apt install --only-upgrade python3-certifi)')
        else:
            good(f"Python certifi {d['CERTIFI']}")
    if d.get("NODE"):
        n = nums(d["NODE"]); fix = NODE_FIXED.get(n[0]) if n else None
        if fix is None:
            bad(f"Node.js {d['NODE']} está en una rama sin parche", "pasa a Node 22.23.4 / 24.22.1 / 26.12.1+")
        elif n < fix:
            bad(f"Node.js {d['NODE']} es anterior a v{'.'.join(map(str, fix))}", "actualiza Node.js y reinicia sus servicios")
        else:
            good(f"Node.js {d['NODE']}")
    if d.get("GO"):
        gv = nums(d["GO"]); fix = GO_FIXED.get(gv[1]) if len(gv) > 1 else None
        if (fix is None and gv < (1, 27, 3)) or (fix and gv < fix):
            warn(f"Go {d['GO']} está desactualizado", "actualiza a 1.26.10 / 1.27.3+ y RECOMPILA cada binario Go")
    if d.get("JAVA_G3") == "yes":
        bad("El cacerts de Java contiene la raíz G3", "actualiza el JDK o quita el alias del cacerts")
    elif d.get("JAVA_G3") == "no":
        good("cacerts de Java limpio")
    if d.get("DOCKER_IMAGES", "0") not in ("", "0"):
        n_img = d["DOCKER_IMAGES"]
        layers_scanned = d.get("FAST") != "1" and d.get("LAYERS_READABLE") == "yes"
        if g["containers"]:
            pass  # ya se reportó arriba como crítico
        elif layers_scanned:
            good(f"{n_img} imagen(es) Docker: sin raíz G3 en sus capas")
        else:
            warn(f"{n_img} imagen(es) Docker cuyas capas no se pudieron revisar"
                 + (" (--fast)" if d.get("FAST") == "1" else " (usa --sudo)"),
                 "vuelve a escanear con --sudo y sin --fast, o verifica: docker run --rm -i --entrypoint bash <imagen> -s < check_emudhra.sh")

    # --- Prueba real
    curls = {k[5:]: v for k, v in d.items() if k.startswith("CURL_")}
    trusted = [h for h, v in curls.items() if v == "0"]
    rejected = [h for h, v in curls.items() if v in ("35", "51", "58", "60", "77")]
    if trusted:
        bad(f"Prueba real: curl CONFÍA en la cadena falsa ({', '.join(trusted)})", "actualiza el almacén del sistema")
    elif curls and len(rejected) == len(curls):
        good("Prueba real: curl rechaza las dos cadenas falsas")
    elif curls:
        warn("Prueba real no concluyente (¿sin salida a internet?)")

    lv = {i[0] for i in items}
    status = "VULNERABLE" if "bad" in lv else ("REVISAR" if "warn" in lv else "OK")
    order = {"bad": 0, "warn": 1, "ok": 2}
    items.sort(key=lambda i: order[i[0]])
    return status, items

def tls_check(host, port, timeout):
    host = host.split("@")[-1].split(":")[0]
    try:
        p = subprocess.run(["openssl", "s_client", "-connect", f"{host}:{port}", "-servername", host, "-showcerts"],
                           input="", capture_output=True, text=True, timeout=timeout)
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return f"{port}: sin respuesta" if isinstance(e, subprocess.TimeoutExpired) else "openssl no está instalado"
    chain = re.findall(r"^\s*\d+ s:.*$|^\s*i:.*$", p.stdout, re.M)
    if not chain:
        return None
    if re.search(r"emSign|eMudhra|EM (DV|OV|EV) TLS CA", "\n".join(chain), re.I):
        return f"{port}: PRESENTA un certificado de la jerarquía eMudhra (reemplázalo)"
    return None

def main():
    ap = argparse.ArgumentParser(description="Auditoría remota del compromiso de las CAs de eMudhra")
    ap.add_argument("hosts_file")
    ap.add_argument("-u", "--user"); ap.add_argument("-i", "--identity")
    ap.add_argument("--sudo", action="store_true", help="ejecuta con sudo (necesario para revisar capas de contenedores)")
    ap.add_argument("--tls-ports", default="", help="ej. 443,8443")
    ap.add_argument("--tls-only", action="store_true")
    ap.add_argument("--csv"); ap.add_argument("-j", "--jobs", type=int, default=10)
    ap.add_argument("--timeout", type=int, default=10)
    ap.add_argument("-p", "--ask-pass", action="store_true",
                    help="pide la contraseña SSH (una vez, para todos); requiere sshpass")
    ap.add_argument("-v", "--verbose", action="count", default=0,
                    help="muestra el avance en vivo; -vv añade el detalle SSH")
    ap.add_argument("--fast", action="store_true",
                    help="salta la búsqueda en disco (el paso más lento)")
    ap.add_argument("--no-live-test", action="store_true",
                    help="no hace la prueba con curl a los sitios de prueba de terceros")
    ap.add_argument("--find-timeout", type=int, default=60,
                    help="segundos máximos para la búsqueda en disco (por defecto 60)")
    args = ap.parse_args()
    args.password = os.environ.get("EMUDHRA_SSH_PASS")
    if args.ask_pass and not args.password:
        args.password = getpass.getpass("Contraseña SSH: ")
    if args.password and not shutil.which("sshpass"):
        sys.exit("Falta sshpass: brew install sshpass  |  apt install sshpass  |  dnf install sshpass")

    hosts = [l.strip() for l in open(args.hosts_file) if l.strip() and not l.strip().startswith("#")]
    ports = [p for p in args.tls_ports.split(",") if p.strip()]

    def scan(h):
        row = {"host": h, "status": "", "os": "", "items": []}
        tls = [r for p in ports if (r := tls_check(h, p.strip(), args.timeout))]
        if not args.tls_only:
            data, err = run_ssh(h, args)
            if err:
                row.update(status="SIN ACCESO", items=[("bad", err, "revisa VPN, IP, usuario y llave (-vv para detalle)", "")])
            else:
                st, items = evaluate(data)
                row.update(status=st, items=items, os=f"{data.get('OS_ID')} {data.get('OS_VER')}")
        for t in tls:
            row["items"].insert(0, ("warn", t, "reemplaza el certificado por uno de otra CA", ""))
            if row["status"] in ("", "OK"): row["status"] = "REVISAR"
        if not row["status"]: row["status"] = "OK"
        log(h, f"listo -> {row['status']}")
        return row

    print(f"Escaneando {len(hosts)} servidor(es), {args.jobs} en paralelo"
          + ("" if args.verbose else " (usa -v para ver el detalle)") + "...", file=sys.stderr)

    with cf.ThreadPoolExecutor(args.jobs) as ex:
        rows = list(ex.map(scan, hosts))

    tty = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    C = lambda code, t: f"\033[{code}m{t}\033[0m" if tty else t
    scol = {"VULNERABLE": "1;31", "REVISAR": "1;33", "OK": "1;32", "SIN ACCESO": "1;90"}
    icon = {"bad": C("31", "✗"), "warn": C("33", "!"), "ok": C("32", "✓")}
    width = 72
    for r in rows:
        print()
        print(C("90", "─" * width))
        left = f" {r['host']}" + (f"   {C('90', r['os'])}" if r["os"] else "")
        pad = width - len(r["host"]) - (len(r["os"]) + 3 if r["os"] else 0) - len(r["status"]) - 2
        print(C("1", left) + " " * max(pad, 1) + C(scol.get(r["status"], "0"), r["status"]))
        print(C("90", "─" * width))
        for lvl, title, fix, _ in r["items"]:
            print(f"  {icon[lvl]} {title}")
            if fix and lvl != "ok":
                print(C("90", f"      arreglo: {fix}"))
    tot = {s: sum(r["status"] == s for r in rows) for s in scol}
    print()
    print(C("1", "Resumen  ") + "   ".join(C(scol[k], f"{k} {v}") for k, v in tot.items()))

    if args.csv:
        with open(args.csv, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["servidor", "so", "estado", "severidad", "hallazgo", "arreglo", "rutas_afectadas"])
            sev = {"bad": "critico", "warn": "revisar", "ok": "ok"}
            for r in rows:
                for lvl, title, fix, det in r["items"] or [("ok", "-", "", "")]:
                    w.writerow([r["host"], r["os"], r["status"], sev[lvl], title, fix, det.replace(" ", "\n")])
        print(f"Detalle completo (una fila por hallazgo, con todas las rutas): {args.csv}")
    sys.exit(1 if tot["VULNERABLE"] else 0)

if __name__ == "__main__":
    main()
