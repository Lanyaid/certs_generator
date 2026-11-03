#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.cnf"
ENV_DIR="$SCRIPT_DIR/environments"
CA_DIR="$ROOT_DIR/CA"
CERTS_DIR="$ROOT_DIR/certs"

if ! command -v openssl >/dev/null 2>&1; then
    echo "Erreur : openssl n'est pas installé ou absent du PATH." >&2
    exit 1
fi

if [[ ! -f "$CONFIG_FILE" || ! -f "$CA_DIR/ca.key" || ! -f "$CA_DIR/ca.crt" ]]; then
    echo "Erreur : configuration globale ou CA introuvable." >&2
    exit 1
fi

if [[ ! -d "$ENV_DIR" ]] || ! compgen -G "$ENV_DIR/*.certconf" > /dev/null; then
    echo "Erreur : aucun fichier *.certconf trouvé dans $ENV_DIR." >&2
    exit 1
fi

# shellcheck disable=SC1090
source "$CONFIG_FILE"

ask_value() {
    local var_name="$1"
    local label="$2"
    local current="${!var_name-}"
    local answer

    while true; do
        printf '%s [%s]\n' "$label" "$current"
        printf 'Réponds OK pour confirmer ou saisis une nouvelle valeur : '
        IFS= read -r answer

        if [[ "${answer,,}" == "ok" ]]; then
            printf -v "$var_name" '%s' "$current"
            return
        elif [[ -n "$answer" ]]; then
            current="$answer"
        else
            echo "Réponse vide : tape OK ou saisis une valeur."
        fi
    done
}

echo "========================================"
echo " Renouvellement de certificat d'environ."
echo "========================================"
echo

echo "Sélectionne l'environnement à renouveler :"
select ENV_FILE in "$ENV_DIR"/*.certconf; do
    if [[ -n "$ENV_FILE" ]]; then
        break
    else
        echo "Sélection invalide, réessaie."
    fi
done

# shellcheck disable=SC1090
source "$ENV_FILE"

CERT_DAYS="${CERT_DAYS:-825}"
SAN_DNS="${SAN_DNS:-}"
SAN_IP="${SAN_IP:-}"

TARGET_DIR="$CERTS_DIR/$CERT_NAME"
KEY_PATH="$TARGET_DIR/$CERT_NAME.key"
CRT_PATH="$TARGET_DIR/$CERT_NAME.crt"
FULLCHAIN_PATH="$TARGET_DIR/$CERT_NAME-fullchain.crt"

echo
echo "Configuration chargée depuis : $(basename "$ENV_FILE")"
if [[ -f "$CRT_PATH" ]]; then
    echo "Certificat actuel :"
    openssl x509 -in "$CRT_PATH" -noout -dates
fi
echo

ask_value CERT_DAYS "Nouvelle durée de validité (jours)"

echo
echo "--------------------------------------------------"
echo "          RECAPITULATIF DU RENOUVELLEMENT         "
echo "--------------------------------------------------"
printf '  Nom / Dossier      : certs/%s/\n' "$CERT_NAME"
printf '  Common Name (CN)   : %s\n' "$COMMON_NAME"
printf '  Validité           : %s jours\n' "$CERT_DAYS"
echo

while true; do
    printf 'Tape OK pour valider et renouveler le certificat : '
    read -r confirmation
    if [[ "${confirmation,,}" == "ok" ]]; then
        break
    else
        echo "Renouvellement annulé."
        exit 0
    fi
done

mkdir -p "$TARGET_DIR"
chmod 700 "$TARGET_DIR"

if [[ ! -f "$KEY_PATH" ]]; then
    echo "Clé privée introuvable, génération d'une nouvelle clé..."
    openssl genpkey -algorithm RSA -pkeyopt "rsa_keygen_bits:$KEY_SIZE" -out "$KEY_PATH"
fi
chmod 600 "$KEY_PATH"

TMP_CONF="$(mktemp)"
ALT_NAMES_BLOCK=""
counter=1

if [[ -n "$SAN_DNS" ]]; then
    IFS=',' read -ra DNS_ARR <<< "$SAN_DNS"
    for d in "${DNS_ARR[@]}"; do
        d_trimmed="$(echo "$d" | xargs)"
        [[ -n "$d_trimmed" ]] && ALT_NAMES_BLOCK+="DNS.$counter = $d_trimmed"$'\n'
        ((counter++))
    done
fi

if [[ -n "$SAN_IP" ]]; then
    IFS=',' read -ra IP_ARR <<< "$SAN_IP"
    for ip in "${IP_ARR[@]}"; do
        ip_trimmed="$(echo "$ip" | xargs)"
        [[ -n "$ip_trimmed" ]] && ALT_NAMES_BLOCK+="IP.$counter = $ip_trimmed"$'\n'
        ((counter++))
    done
fi

cat > "$TMP_CONF" <<EOF
[ req ]
default_bits = $KEY_SIZE
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[ req_distinguished_name ]
C = $COUNTRY
ST = $STATE
L = $LOCALITY
O = $ORGANIZATION
OU = $ORGANIZATIONAL_UNIT
CN = $COMMON_NAME

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
$([[ -n "$ALT_NAMES_BLOCK" ]] && echo "subjectAltName = @alt_names")

[ alt_names ]
$ALT_NAMES_BLOCK
EOF

CSR_PATH="$(mktemp)"
trap 'rm -f "$TMP_CONF" "$CSR_PATH"' EXIT

echo "Génération de la CSR..."
openssl req -new -key "$KEY_PATH" -out "$CSR_PATH" -config "$TMP_CONF" -"$DIGEST"

# Sauvegarde des anciens fichiers s'ils existent
if [[ -f "$CRT_PATH" ]]; then
    cp "$CRT_PATH" "$CRT_PATH.bak"
fi
if [[ -f "$FULLCHAIN_PATH" ]]; then
    cp "$FULLCHAIN_PATH" "$FULLCHAIN_PATH.bak"
fi

echo "Signature du nouveau certificat par la CA..."
openssl x509 -req \
    -in "$CSR_PATH" \
    -CA "$CA_DIR/ca.crt" \
    -CAkey "$CA_DIR/ca.key" \
    -CAcreateserial \
    -out "$CRT_PATH" \
    -days "$CERT_DAYS" \
    -"$DIGEST" \
    -extfile "$TMP_CONF" \
    -extensions v3_req

# Régénération du bundle / fullchain
cat "$CRT_PATH" "$CA_DIR/ca.crt" > "$FULLCHAIN_PATH"

chmod 644 "$CRT_PATH"
chmod 644 "$FULLCHAIN_PATH"

echo
echo "Certificat renouvelé avec succès dans : $TARGET_DIR/"
echo "  - Ancien certificat sauvegardé en : $(basename "$CRT_PATH").bak (le cas échéant)"
echo "  - Nouveau certificat : $(basename "$CRT_PATH")"
echo "  - Fullchain mis à jour : $(basename "$FULLCHAIN_PATH")"
echo
openssl x509 -in "$CRT_PATH" -noout -subject -dates
