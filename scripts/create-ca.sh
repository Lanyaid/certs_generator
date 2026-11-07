#!/usr/bin/env bash
set -Eeuo pipefail

# Répertoires calculés à partir de l'emplacement du script.
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$ROOT_DIR/configs/config.cnf"
CA_DIR="$ROOT_DIR/CA"

if ! command -v openssl >/dev/null 2>&1; then
    echo "Erreur : openssl n'est pas installé ou absent du PATH." >&2
    exit 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "Erreur : fichier de configuration introuvable : $CONFIG_FILE" >&2
    exit 1
fi

# Le fichier de configuration est un fichier shell local, éditable par l'administrateur.
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
echo " Création de l'autorité de certification"
echo "========================================"
echo
echo "Fichier de configuration : $CONFIG_FILE"
echo

ask_value CA_NAME "Nom de la CA"
ask_value COUNTRY "Country (C)"
ask_value STATE "State / Province (ST)"
ask_value LOCALITY "Locality (L)"
ask_value ORGANIZATION "Organization (O)"
ask_value ORGANIZATIONAL_UNIT "Organizational Unit (OU)"
ask_value COMMON_NAME "Common Name (CN)"
ask_value CA_DAYS "Durée de validité de la CA (jours)"
ask_value KEY_TYPE "Type de clé"
ask_value KEY_SIZE "Taille de clé (bits)"
ask_value DIGEST "Algorithme de signature"

echo
echo "Récapitulatif :"
printf '  CA                 : %s\n' "$CA_NAME"
printf '  Subject            : C=%s, ST=%s, L=%s, O=%s, OU=%s, CN=%s\n' \
    "$COUNTRY" "$STATE" "$LOCALITY" "$ORGANIZATION" "$ORGANIZATIONAL_UNIT" "$COMMON_NAME"
printf '  Validité           : %s jours\n' "$CA_DAYS"
printf '  Clé                : %s %s bits, non chiffrée\n' "$KEY_TYPE" "$KEY_SIZE"
printf '  Signature          : %s\n' "$DIGEST"
echo

if [[ -e "$CA_DIR/ca.key" || -e "$CA_DIR/ca.crt" ]]; then
    echo "Erreur : une clé ou un certificat existe déjà dans $CA_DIR."
    echo "Aucun fichier n'a été écrasé. Sauvegarde ou déplace l'existant avant de recommencer."
    exit 1
fi

if [[ "$KEY_TYPE" != "RSA" ]]; then
    echo "Erreur : ce script de création de CA est actuellement prévu pour RSA." >&2
    exit 1
fi

if ! [[ "$KEY_SIZE" =~ ^[0-9]+$ ]] || ! [[ "$CA_DAYS" =~ ^[0-9]+$ ]] || (( CA_DAYS < 1 )); then
    echo "Erreur : taille de clé ou durée de validité invalide." >&2
    exit 1
fi

mkdir -p "$CA_DIR"
chmod 700 "$CA_DIR"

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

echo "Génération de la clé privée RSA..."
openssl genpkey \
    -algorithm RSA \
    -pkeyopt "rsa_keygen_bits:$KEY_SIZE" \
    -out "$CA_DIR/ca.key"

chmod 600 "$CA_DIR/ca.key"

echo "Génération du certificat racine..."
openssl req -new -x509 \
    -key "$CA_DIR/ca.key" \
    -out "$CA_DIR/ca.crt" \
    -days "$CA_DAYS" \
    -"$DIGEST" \
    -config "$TMP_CONF"

chmod 644 "$CA_DIR/ca.crt"

echo
echo "CA créée avec succès."
echo "Clé privée : $CA_DIR/ca.key (permissions 600)"
echo "Certificat : $CA_DIR/ca.crt (permissions 644)"
echo
echo "Vérification du certificat :"
openssl x509 -in "$CA_DIR/ca.crt" -noout -subject -issuer -dates
echo
echo "Empreinte SHA-256 :"
openssl x509 -in "$CA_DIR/ca.crt" -noout -fingerprint -sha256
echo
echo "IMPORTANT : sauvegarde la clé privée ca.key dans un emplacement sûr."
echo "Ne la distribue jamais aux machines clientes ; seul ca.crt doit être installé."
