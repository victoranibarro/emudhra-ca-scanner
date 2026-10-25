#!/usr/bin/env bash
# check_emudhra.sh - Comprueba si este servidor o contenedor todavía confía en
# las CAs intermedias comprometidas de eMudhra (raíz emSign ECC Root CA - G3).
#
# Uso:    ./check_emudhra.sh            (en cada servidor o dentro de cada contenedor)
# Salida: 0 = OK, 1 = VULNERABLE en algún cliente, 2 = resultados no concluyentes
#
# Lógica: se conecta a los sitios de prueba publicados por el investigador.
#   - Error de certificado    -> OK (el cliente rechaza la cadena)
#   - Conexión exitosa        -> VULNERABLE
#   - Error de red u otro     -> NO CONCLUYENTE (revisa firewall o proxy)

set -u
HOSTS=(
  "dv-g3b-emudhra.we-have-a-problem.com"
  "dv-g3b-aaa-emudhra.we-have-a-problem.com"   # cadena vía la firma cruzada de Sectigo
)
ROOT_FP="86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B"  # emSign ECC Root CA - G3
TIMEOUT=10
VULN=0; INCONCL=0; OK=0

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
ok()   { grn  "  [OK]          $*"; OK=$((OK+1)); }
bad()  { red  "  [VULNERABLE]  $*"; VULN=$((VULN+1)); }
unk()  { ylw  "  [?]           $*"; INCONCL=$((INCONCL+1)); }
have() { command -v "$1" >/dev/null 2>&1; }

echo "== Verificación eMudhra en $(hostname) - $(date -u +%FT%TZ) =="

# 1) ¿Raíz G3 en el almacén del sistema?
echo "-- Almacén de certificados del sistema"
BUNDLE=""
for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt \
         /etc/ssl/cert.pem /etc/ssl/ca-bundle.pem; do
  [ -r "$f" ] && BUNDLE="$f" && break
done
if [ -n "$BUNDLE" ] && have openssl; then
  TMP=$(mktemp -d); trap 'rm -rf "$TMP"' EXIT
  awk -v d="$TMP" '/BEGIN CERT/{n++} n{print > (d "/c" n ".pem")}' "$BUNDLE"
  FOUND=0
  for c in "$TMP"/c*.pem; do
    fp=$(openssl x509 -in "$c" -noout -fingerprint -sha256 2>/dev/null | cut -d= -f2 | tr -d :)
    [ "$fp" = "$ROOT_FP" ] && FOUND=1 && break
  done
  if [ $FOUND -eq 1 ]; then bad "emSign ECC Root CA - G3 sigue en $BUNDLE (actualiza ca-certificates)"
  else ok "la raíz G3 no está en $BUNDLE"; fi
else
  unk "no se encontró el almacén del sistema o falta openssl"
fi

# 2) Pruebas de conexión por cliente
for H in "${HOSTS[@]}"; do
  URL="https://$H/"
  echo "-- $H"

  # curl (usa el almacén del sistema o el de su librería TLS)
  if have curl; then
    curl -sS -o /dev/null --max-time $TIMEOUT "$URL" 2>/dev/null; rc=$?
    case $rc in
      0)        bad "curl confía en la cadena" ;;
      35|51|58|60|77) ok "curl rechaza el certificado (código $rc)" ;;
      *)        unk "curl: error de red u otro (código $rc)" ;;
    esac
  fi

  # openssl s_client
  if have openssl; then
    out=$(echo | timeout $TIMEOUT openssl s_client -connect "$H:443" -servername "$H" 2>&1)
    code=$(echo "$out" | sed -n 's/.*Verify return code: \([0-9]*\).*/\1/p' | tail -1)
    if   [ "$code" = "0" ]; then bad "openssl da la cadena por válida"
    elif [ -n "$code" ];   then ok  "openssl rechaza (código $code)"
    else unk "openssl: sin conexión"; fi
  fi

  # Python (ssl usa el almacén del sistema; requests/httpx usan certifi)
  PYOUT=$(mktemp)
  for PY in python3 python; do
    have $PY || continue
    $PY - "$H" > "$PYOUT" <<'EOF'
import ssl, socket, sys
h = sys.argv[1]
def test(ctx, label):
    try:
        with socket.create_connection((h, 443), timeout=10) as s:
            with ctx.wrap_socket(s, server_hostname=h): pass
        print("VULN", label)
    except ssl.SSLCertVerificationError: print("OK", label)
    except Exception as e: print("UNK", label, type(e).__name__)
test(ssl.create_default_context(), "python ssl (almacén del sistema)")
try:
    import certifi
    test(ssl.create_default_context(cafile=certifi.where()), "python certifi " + certifi.__version__)
except ImportError: pass
EOF
    break
  done
  while read -r st rest; do
    case $st in OK) ok "$rest";; VULN) bad "$rest";; *) unk "$rest";; esac
  done < "$PYOUT"; rm -f "$PYOUT"

  # Node.js (trae su propio bundle de raíces de Mozilla)
  if have node; then
    r=$(node -e '
      require("https").get(process.argv[1],{timeout:10000},()=>{console.log("VULN");process.exit()})
      .on("error",e=>{console.log(/CERT|ISSUER|SELF_SIGNED|UNABLE_TO|signature/i.test(e.code+e.message)?"OK "+e.code:"UNK "+e.code);process.exit()})
      .on("timeout",function(){console.log("UNK timeout");process.exit()})' "$URL" 2>&1)
    case $r in VULN*) bad "node $(node -v) confía en la cadena";; OK*) ok "node $(node -v) rechaza (${r#OK })";; *) unk "node: $r";; esac
  fi
done

# 3) Versiones (almacenes embebidos)
echo "-- Versiones de runtimes"
if have go; then
  gv=$(go env GOVERSION 2>/dev/null)
  echo "  go: $gv  (necesitas >= go1.27.3 / go1.26.10 y RECOMPILAR los binarios)"
fi
if have python3; then
  cv=$(python3 -c 'import certifi;print(certifi.__version__)' 2>/dev/null)
  if [ -n "$cv" ]; then
    if [ "$(printf '%s\n2026.10.19\n' "$cv" | sort -V | head -1)" = "2026.10.19" ]; then ok "certifi $cv"
    else bad "certifi $cv < 2026.10.19 (pip install -U 'certifi>=2026.10.19')"; fi
  fi
fi
if have keytool; then
  if keytool -list -cacerts -storepass changeit -v 2>/dev/null | tr -d : | grep -qi "$ROOT_FP"; then
    bad "el cacerts de Java contiene emSign ECC Root CA - G3"
  else ok "el cacerts de Java no contiene la raíz G3"; fi
fi

# Resumen
echo "== Resumen: OK=$OK  VULNERABLE=$VULN  NO_CONCLUYENTE=$INCONCL"
[ $VULN -gt 0 ] && exit 1
[ $INCONCL -gt 0 ] && exit 2
exit 0
