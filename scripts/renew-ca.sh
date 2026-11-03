#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.cnf"
CA_DIR="$ROOT_DIR/CA"

if ! command -v openssl >/dev/null 2>&1; then
    echo "Erreur : openssl n'est pas installé ou absent du PATH." >&2
    exit 1
fi

if [[ ! -f "$CONFIG_FILE" || ! -f "$CA_DIR/ca.key" ]]; then
    echo "Erreur : configuration ou clé privée de la CA introuvable." >&2
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
echo " Renouvellement du certificat de la CA  "
echo "========================================"
echo

ask_value CA_DAYS "Nouvelle durée de validité de la CA (jours)"

echo
echo "État actuel du certificat CA :"
openssl x509 -in "$CA_DIR/ca.crt" -noout -subject -dates
echo

while true; do
    printf 'Tape OK pour valider et renouveler le certificat CA : '
    read -r confirmation
    if [[ "${confirmation,,}" == "ok" ]]; then
        break
    else
        echo "Renouvellement annulé."
        exit 0
    fi
done

TMP_CONF="$(mktemp)"
trap 'rm -f "$TMP_CONF"' EXIT

cat > "$TMP_CONF" <<EOF
[ req ]
prompt = no
distinguished_name = subject
x509_extensions = v3_ca
default_md = $DIGEST

[ subject ]
C = $COUNTRY
ST = $STATE
L = $LOCALITY
O = $ORGANIZATION
OU = $ORGANIZATIONAL_UNIT
CN = $COMMON_NAME

[ v3_ca ]
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

# Sauvegarde de l'ancien certificat par sécurité
cp "$CA_DIR/ca.crt" "$CA_DIR/ca.crt.bak"

echo "Génération du nouveau certificat racine (avec la même clé)..."
openssl req -new -x509 \
    -key "$CA_DIR/ca.key" \
    -out "$CA_DIR/ca.crt" \
    -days "$CA_DAYS" \
    -"$DIGEST" \
    -config "$TMP_CONF"

chmod 644 "$CA_DIR/ca.crt"

echo
echo "CA renouvelée avec succès !"
echo "Ancien certificat sauvegardé en : $CA_DIR/ca.crt.bak"
echo "Nouveau certificat : $CA_DIR/ca.crt"
echo
openssl x509 -in "$CA_DIR/ca.crt" -noout -subject -dates
