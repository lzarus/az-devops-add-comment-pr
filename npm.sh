#!/bin/bash

# Lire les fichiers JSON des packages et des vulnérabilités
package_list=$(cat package.json)
audit_results=$(cat audit.json)

# Initialiser les tableaux pour chaque niveau de sévérité
declare -A vulnerabilities
vulnerabilities[high]=""
vulnerabilities[moderate]=""
vulnerabilities[low]=""
vulnerabilities[info]=""

# Parcourir les vulnérabilités du JSON
while IFS= read -r vulnerability; do
  name=$(echo "$vulnerability" | jq -r '.Name')
  severity=$(echo "$vulnerability" | jq -r '.Value.severity')
  version=$(echo "$vulnerability" | jq -r '.Value.range // "N/A"')
  fix_name=$(echo "$vulnerability" | jq -r '.Value.fixAvailable.name // "N/A"')
  fix_version=$(echo "$vulnerability" | jq -r '.Value.fixAvailable.version // "N/A"')
  fix_major=$(echo "$vulnerability" | jq -r '.Value.fixAvailable.isSemVerMajor // "N/A"')

  # Trier selon le niveau de sévérité
  case "$severity" in
    high)
      vulnerabilities[high]+="Package: $name, Version: $version, Fix: $fix_name - $fix_version (Major: $fix_major)\n"
      ;;
    moderate)
      vulnerabilities[moderate]+="Package: $name, Version: $version, Fix: $fix_name - $fix_version (Major: $fix_major)\n"
      ;;
    low)
      vulnerabilities[low]+="Package: $name, Version: $version, Fix: $fix_name - $fix_version (Major: $fix_major)\n"
      ;;
    info)
      vulnerabilities[info]+="Package: $name, Version: $version, Fix: $fix_name - $fix_version (Major: $fix_major)\n"
      ;;
  esac
done < <(echo "$audit_results" | jq -c '.vulnerabilities | to_entries[]')

# Construire le commentaire en Markdown
comment_content="# Résumé de l'audit NPM 📊\n"

# Ajouter les sections pour chaque niveau de sévérité
for severity in high moderate low info; do
  severity_label=""
  case "$severity" in
    high) severity_label="🔴 Vulnérabilités Hautes" ;;
    moderate) severity_label="🟠 Vulnérabilités Modérées" ;;
    low) severity_label="🟢 Vulnérabilités Basses" ;;
    info) severity_label="🔵 Vulnérabilités d'Information" ;;
  esac

  count=$(echo -e "${vulnerabilities[$severity]}" | grep -c "Package" || echo 0)
  comment_content+="## $severity_label (Total: $count)\n"

  if [[ "$count" -gt 0 ]]; then
    comment_content+="${vulnerabilities[$severity]}\n"
  else
    comment_content+="Aucune vulnérabilité $severity trouvée.\n"
  fi
done

# Liste des packages NPM installés
comment_content+="\n## 📦 Liste des packages NPM installés\n"
dependencies=$(echo "$package_list" | jq -r '.dependencies | to_entries[] | "- \(.key) @ \(.value.version)"')
if [[ -n "$dependencies" ]]; then
  comment_content+="$dependencies\n"
else
  comment_content+="Aucun package NPM trouvé dans la liste des dépendances.\n"
fi

# Envoi du commentaire via l'API Azure DevOps
repository_id="$BUILD_REPOSITORY_NAME"
pr_id="$SYSTEM_PULLREQUEST_PULLREQUESTID"
api_url="${SYSTEM_TEAMFOUNDATIONCOLLECTIONURI}${SYSTEM_TEAMPROJECT}/_apis/git/repositories/$repository_id/pullRequests/$pr_id/threads?api-version=7.2-preview.1"

if [[ -z "$pr_id" ]]; then
  echo "Aucun ID de PR disponible. Sortie sans ajouter de commentaire."
  exit 0
fi

body=$(jq -n \
  --arg content "$comment_content" \
  '{"comments": [{"parentCommentId": 0, "content": $content, "commentType": "text"}], "status": "active"}')

response=$(curl -s -X POST \
  -H "Authorization: Bearer $SYSTEM_ACCESSTOKEN" \
  -H "Content-Type: application/json" \
  -d "$body" \
  "$api_url")

if [[ $? -eq 0 ]]; then
  echo "Commentaire ajouté avec succès."
else
  echo "Erreur lors de l'ajout du commentaire : $response"
fi
