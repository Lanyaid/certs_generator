#!/usr/bin/env bash
set -Eeuo pipefail

# Répertoires calculés à partir de l'emplacement du script.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$ROOT_DIR/configs/config.cnf"
ENV_DIR="$ROOT_DIR/configs"
CA_DIR="$ROOT_DIR/CA"
CERTS_DIR="$ROOT_DIR/certs"

if ! command -v openssl >/dev/null 2>&1; then
    echo "Erreur : openssl n'est pas installé ou absent du PATH." >&2
    exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Erreur : fichier de configuration introuvable : $CONFIG_FILE" >&2
    exit 1
fi

if [[ ! -f "$CA_DIR/ca.key" || ! -f "$CA_DIR/ca.crt" ]]; then
    echo "Erreur : la CA est introuvable dans $CA_DIR. Exécute d'abord create-ca.sh." >&2
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
echo " Génération de certificat d'environnement"
echo "========================================"
echo

echo "4. Sélectionne l'environnement à générer :"
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

echo
echo "Configuration chargée depuis : $(basename "$ENV_FILE")"
echo

ask_value CERT_NAME "Nom du certificat (dossier cible)"
ask_value COMMON_NAME "Common Name (CN)"
ask_value SAN_DNS "Noms DNS alternatifs (SAN DNS, séparés par virgule)"
ask_value SAN_IP "Adresses IP alternatives (SAN IP, séparées par virgule)"
ask_value CERT_DAYS "Durée de validité (jours)"

echo
echo "--------------------------------------------------"
echo "            RECAPITULATIF DU CERTIFICAT           "
echo "--------------------------------------------------"
printf '  Nom / Dossier      : certs/%s/\n' "$CERT_NAME"
printf '  Common Name (CN)   : %s\n' "$COMMON_NAME"
printf '  DNS SANs           : %s\n' "${SAN_DNS:-Aucun}"
printf '  IP SANs            : %s\n' "${SAN_IP:-Aucune}"
printf '  Validité           : %s jours\n' "$CERT_DAYS"
printf '  Clé                : %s %s bits, non chiffrée\n' "$KEY_TYPE" "$KEY_SIZE"
printf '  Signature          : %s\n' "$DIGEST"
echo

while true; do
    printf 'Tape OK pour valider et générer le certificat : '
    read -r confirmation
    if [[ "${confirmation,,}" == "ok" ]]; then
        break
    else
        echo "Génération annulée par l'utilisateur."
        exit 0
    fi
done

TARGET_DIR="$CERTS_DIR/$CERT_NAME"
KEY_PATH="$TARGET_DIR/$CERT_NAME.key"
CRT_PATH="$TARGET_DIR/$CERT_NAME.crt"
FULLCHAIN_PATH="$TARGET_DIR/$CERT_NAME-fullchain.crt"

if [[ -e "$KEY_PATH" || -e "$CRT_PATH" ]]; then
    echo
    echo "Erreur : un certificat ou une clé existe déjà dans $TARGET_DIR."
    echo "Aucun fichier n'a été écrasé. Supprime ou déplace l'existant si tu souhaites régénérer."
    exit 1
fi

if [[ "$KEY_TYPE" != "RSA" ]]; then
    echo "Erreur : ce script prend actuellement en charge uniquement RSA." >&2
    exit 1
fi

if ! [[ "$KEY_SIZE" =~ ^[0-9]+$ ]] || ! [[ "$CERT_DAYS" =~ ^[0-9]+$ ]] || (( CERT_DAYS < 1 )); then
    echo "Erreur : taille de clé ou durée de validité invalide." >&2
    exit 1
fi

mkdir -p "$TARGET_DIR"
chmod 700 "$TARGET_DIR"

TMP_CONF="$(mktemp)"
trap 'rm -f "$TMP_CONF"' EXIT

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

echo
echo "Génération de la clé privée RSA..."
openssl genpkey \
    -algorithm RSA \
    -pkeyopt "rsa_keygen_bits:$KEY_SIZE" \
    -out "$KEY_PATH"

chmod 600 "$KEY_PATH"

echo "Génération de la CSR..."
CSR_PATH="$(mktemp)"
trap 'rm -f "$TMP_CONF" "$CSR_PATH"' EXIT

openssl req -new \
    -key "$KEY_PATH" \
    -out "$CSR_PATH" \
    -config "$TMP_CONF" \
    -"$DIGEST"

echo "Signature du certificat par la CA..."
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

# --- Génération du Bundle / Fullchain ---
# Concaténation : Certificat du service d'abord, puis certificat de la CA
cat "$CRT_PATH" "$CA_DIR/ca.crt" > "$FULLCHAIN_PATH"

chmod 644 "$CRT_PATH"
chmod 644 "$FULLCHAIN_PATH"

echo
echo "Certificat et fullchain générés avec succès dans : $TARGET_DIR/"
echo "  - Clé privée : $(basename "$KEY_PATH") (permissions 600)"
echo "  - Certificat : $(basename "$CRT_PATH") (permissions 644)"
echo "  - Fullchain  : $(basename "$FULLCHAIN_PATH") (permissions 644)"
echo
echo "Vérification du certificat généré :"
openssl x509 -in "$CRT_PATH" -noout -subject -issuer -dates -ext subjectAltName
