# Protocole Tesla BLE — spécification d'implémentation

Toutes les valeurs de ce document ont été **vérifiées dans le code source officiel**
[`teslamotors/vehicle-command`](https://github.com/teslamotors/vehicle-command) (récupéré
le 2026-10-03). Les fichiers `.proto` de référence sont copiés dans ce dossier.

Correspondance code Go → notre implémentation :

| Concept | Source Go | Notre fichier |
|---|---|---|
| Échange ECDH, dérivation de clé | `internal/authentication/native.go` | `core/src/tk_session.c` |
| Sérialisation des métadonnées | `internal/authentication/metadata.go` | `core/src/tk_metadata.c` |
| Signature des commandes | `internal/authentication/signer.go`, `peer.go` | `core/src/tk_session.c` |
| Transport BLE (framing) | `pkg/connector/ble/ble.go` | `core/src/tk_frame.c` |
| Commandes VCSEC | `pkg/vehicle/vcsec.go`, `security.go` | `core/src/tk_vcsec.c` |

---

## 1. Transport BLE

### Découverte

Le véhicule émet un advertisement dont le **nom local** est dérivé du VIN :

```
local_name = "S" + hex(SHA1(vin_ascii)[0..8]) + "C"
```

soit 18 caractères ASCII : `S` + 16 chiffres hexadécimaux **minuscules** + `C`.
(Go : `fmt.Sprintf("S%02xC", digest[:8])` sur `sha1.Sum([]byte(vin))`.)

### GATT

| Rôle | UUID |
|---|---|
| Service | `00000211-b2d1-43f0-9b88-960cebf8b91e` |
| Écriture vers le véhicule (TX) | `00000212-b2d1-43f0-9b88-960cebf8b91e` |
| Notifications du véhicule (RX) | `00000213-b2d1-43f0-9b88-960cebf8b91e` |

On s'abonne à RX en **indications** (Go : `Subscribe(rxChar, true, ...)`, le `true`
signifiant indication plutôt que notification).

### Framing

Chaque `RoutableMessage` sérialisé est précédé d'un préfixe de longueur de
**2 octets big-endian**, puis le tout est découpé en blocs de `MTU - 3` octets
écrits séquentiellement sur la caractéristique TX.

```
[len_hi][len_lo][ ... protobuf RoutableMessage ... ]
```

En réception, on concatène les notifications dans un tampon et on extrait les
messages complets. Deux règles importantes :

- **Timeout de réassemblage de 1 s** : si plus d'une seconde s'écoule entre deux
  fragments, le tampon est vidé (le message est considéré perdu).
- Taille maximale d'un message : 1024 octets (`maxBLEMessageSize`). Au-delà,
  le tampon est vidé.

MTU : on demande le maximum ; en cas d'échec on retombe sur `23 - 3 = 20` octets
par bloc. C'est le cas des ESP32 classiques et des nRF en BLE 4.2 par défaut.

---

## 2. Cryptographie

### Primitives requises de la plateforme

- ECDH sur **NIST P-256** (secp256r1), clés statiques
- SHA-1 (uniquement comme KDF, pas pour sa résistance aux collisions)
- SHA-256, HMAC-SHA256
- AES-128-GCM
- RNG cryptographique

### Dérivation de la clé de session

```
shared = coordonnée X de (cle_privee_locale * cle_publique_vehicule)
         // 32 octets, big-endian, complété de zéros à gauche
key    = SHA1(shared)[0..16]        // 16 octets → AES-128
```

Le commentaire du code Tesla justifie SHA-1 ici : il ne sert qu'à projeter un
point de courbe pseudo-aléatoire en une chaîne de bits pseudo-aléatoire, la
résistance aux collisions n'est pas requise.

### Sous-clés

```
subkey(label) = HMAC-SHA256(key, label)      // 32 octets
```

Deux labels, en ASCII, **sans octet nul terminal** :

| Label | Usage |
|---|---|
| `session info` | authentification du message de session reçu du véhicule |
| `authenticated command` | signature HMAC des commandes (non utilisé en BLE, voir §5) |

### Format des clés publiques

Point non compressé : `0x04 || X(32) || Y(32)` = **65 octets**.

---

## 3. Sérialisation des métadonnées

Les métadonnées authentifiées sont encodées en TLV, **par ordre croissant de tag** :

```
pour chaque champ :  [tag:1][longueur:1][valeur:longueur]
terminateur       :  [0xFF]
puis              :  le message (éventuellement vide)
```

Un champ dont la valeur est absente est **omis** (il ne contribue pas au
hachage). Une valeur de plus de 255 octets est une erreur. Les entiers 32 bits
sont encodés en **big-endian sur 4 octets**.

Tags (`Signatures.Tag`) :

| Tag | Valeur |
|---|---|
| `TAG_SIGNATURE_TYPE` | 0 |
| `TAG_DOMAIN` | 1 |
| `TAG_PERSONALIZATION` | 2 |
| `TAG_EPOCH` | 3 |
| `TAG_EXPIRES_AT` | 4 |
| `TAG_COUNTER` | 5 |
| `TAG_CHALLENGE` | 6 |
| `TAG_FLAGS` | 7 |
| `TAG_REQUEST_HASH` | 8 |
| `TAG_FAULT` | 9 |
| `TAG_END` | 255 |

`PERSONALIZATION` vaut toujours le **VIN en ASCII** (17 octets), appelé
`verifierName` dans le code Go.

---

## 4. Poignée de main (handshake)

### 4.1 Requête

On envoie un `RoutableMessage` non authentifié :

```
to_destination.domain            = DOMAIN_VEHICLE_SECURITY (2)
from_destination.routing_address = 16 octets aléatoires
uuid                             = 16 octets aléatoires
session_info_request.public_key  = notre clé publique (65 octets)
```

Pour le domaine VCSEC, l'adresse de routage source est **aléatoire à chaque
message** (le code Go ne réutilise l'adresse stable que pour l'infotainment).

Note : le champ `session_info_request.challenge` existe dans le `.proto` mais le
client officiel **ne le remplit pas**. Le défi effectif est l'`uuid` du message,
que le véhicule renvoie dans `request_uuid`.

### 4.2 Réponse

Le véhicule répond avec :

- `session_info` : un `Signatures.SessionInfo` sérialisé (champ 15, octets opaques)
- `signature_data.session_info_tag.tag` : HMAC-SHA256 de 32 octets
- `request_uuid` : l'`uuid` que nous avions envoyé

`SessionInfo` contient `counter`, `publicKey` (clé publique du véhicule),
`epoch` (16 octets), `clock_time` et `status`.

Si `status == SESSION_INFO_STATUS_KEY_NOT_ON_WHITELIST` (1), notre clé n'est pas
appairée : il faut passer par l'enrôlement (§7).

### 4.3 Vérification du tag

Le tag doit être vérifié **avant** d'accepter la session, sinon un attaquant
pourrait imposer des valeurs de compteur ou d'epoch :

```
ctx  = HMAC-SHA256 initialisé avec la clé subkey("session info")
ctx <- TLV(TAG_SIGNATURE_TYPE, [6])        // SIGNATURE_TYPE_HMAC
ctx <- TLV(TAG_PERSONALIZATION, vin)
ctx <- TLV(TAG_CHALLENGE, request_uuid)
ctx <- 0xFF
ctx <- session_info_bytes                  // les octets exacts reçus
tag_attendu = ctx.final()
```

Comparaison en temps constant avec le tag reçu.

> **Important** : le HMAC porte sur les **octets reçus tels quels**. Il ne faut
> jamais ré-encoder le protobuf avant de vérifier — l'encodage pourrait différer
> et le tag ne correspondrait plus.

### 4.4 État de session à conserver

```
session_key   16 octets
epoch         16 octets
counter       uint32          — initialisé à SessionInfo.counter
clock_offset  int64           — vehicle_clock_time - uptime_local_s à la réception
vehicle_pub   65 octets
```

La latence est contrôlée : le client officiel rejette une session info reçue plus
de **4 secondes** après l'envoi de la requête (`maxLatency`).

---

## 5. Signature des commandes

En BLE, la méthode d'authentification préférée est **AES-GCM**
(`PreferredAuthMethod()` → `AuthMethodGCM`), donc le payload est **chiffré**, pas
seulement signé. Le mode HMAC existe pour le proxy HTTP, qui doit pouvoir lire
les commandes en clair ; nous ne l'implémentons pas.

### Construction

```
counter += 1                                       // pré-incrément ; erreur au débordement de 0xFFFFFFFF
expires_at = uptime_local_s + clock_offset + ttl   // ttl = 5 s par défaut
```

Métadonnées (SHA-256) :

```
TLV(TAG_SIGNATURE_TYPE,  [5])           // SIGNATURE_TYPE_AES_GCM_PERSONALIZED
TLV(TAG_DOMAIN,          [2])           // domaine de destination du message
TLV(TAG_PERSONALIZATION, vin)
TLV(TAG_EPOCH,           epoch)
TLV(TAG_EXPIRES_AT,      u32be)
TLV(TAG_COUNTER,         u32be)
TLV(TAG_FLAGS,           u32be)         // UNIQUEMENT si flags != 0 (compatibilité ascendante)
0xFF
(message vide)
→ aad = SHA256(...)                     // 32 octets
```

Chiffrement :

```
nonce = 12 octets aléatoires
ciphertext, tag = AES-128-GCM-Encrypt(key, nonce, aad, plaintext)
```

Le message émis contient :

```
to_destination.domain                     = 2
from_destination.routing_address          = 16 octets aléatoires
uuid                                      = 16 octets aléatoires
protobuf_message_as_bytes                 = ciphertext
signature_data.signer_identity.public_key = notre clé publique (65 octets)
signature_data.AES_GCM_Personalized_data  = { epoch, nonce, counter, expires_at, tag }
```

`expires_at` est un `fixed32` protobuf (little-endian sur le fil) mais big-endian
dans les métadonnées. C'est le piège principal de cette partie.

### Bornes à respecter

`expires_at` doit être dans `[0, 2^30]` secondes. Le véhicule rejette une
expiration trop lointaine (`MESSAGEFAULT_ERROR_TIME_TO_LIVE_TOO_LONG`).

---

## 6. Déchiffrement des réponses

L'identifiant de requête lie la réponse à la commande :

```
request_id = [0x05] || gcm_tag(16)          // 17 octets, pour AES_GCM_PERSONALIZED
```

Métadonnées de réponse (SHA-256) :

```
TLV(TAG_SIGNATURE_TYPE,  [9])           // SIGNATURE_TYPE_AES_GCM_RESPONSE
TLV(TAG_DOMAIN,          [from_domain])
TLV(TAG_PERSONALIZATION, vin)
TLV(TAG_COUNTER,         u32be)         // compteur porté par la réponse
TLV(TAG_FLAGS,           u32be)         // TOUJOURS ajouté ici, même à 0 — diffère de §5 !
TLV(TAG_REQUEST_HASH,    request_id)
TLV(TAG_FAULT,           u32be)         // signedMessageStatus.signed_message_fault
0xFF
→ aad = SHA256(...)
```

Puis `AES-128-GCM-Decrypt(key, nonce, aad, ciphertext, tag)`.

Le compteur de réponse doit être vérifié contre une fenêtre anti-rejeu glissante
de 32 bits (`windowSize = 32`).

Toutes les réponses ne sont pas chiffrées : un message d'erreur protocolaire
arrive en clair avec `signedMessageStatus` renseigné et, souvent, une nouvelle
`session_info` permettant la resynchronisation (§9).

---

## 7. Enrôlement de la clé

L'ajout d'une clé n'est **pas** un `RoutableMessage` : c'est un
`VCSEC.ToVCSECMessage` envoyé brut sur la caractéristique TX.

```
ToVCSECMessage.signed_message = {
  protobuf_message_as_bytes = UnsignedMessage {
      whitelist_operation = {
        add_key_to_whitelist_and_add_permissions = {
          key.public_key_raw = notre clé publique (65 octets)
          key_role           = ROLE_DRIVER (3)   // ou ROLE_OWNER (2)
        }
        metadata_for_key.key_form_factor = KEY_FORM_FACTOR_ANDROID_DEVICE (7)
      }
  }
  signature_type = SIGNATURE_TYPE_PRESENT_KEY (2)
}
```

Le conducteur doit ensuite **poser une carte NFC Tesla sur la console centrale**
puis confirmer sur l'écran. L'envoi réussi ne garantit pas l'approbation : il
faut sonder la whitelist, ou refaire un handshake, pour savoir si la clé est
devenue active.

`ROLE_OWNER` permet d'ajouter et de retirer d'autres clés ; `ROLE_DRIVER` suffit
pour ouvrir et conduire. On utilise `ROLE_DRIVER` par défaut, par principe de
moindre privilège.

---

## 8. Commandes utiles

Payload = `VCSEC.UnsignedMessage`, chiffré selon §5, envoyé au domaine 2.

| Action | Encodage |
|---|---|
| Déverrouiller | `rke_action = RKE_ACTION_UNLOCK (0)` |
| Verrouiller | `rke_action = RKE_ACTION_LOCK (1)` |
| **Autoriser la conduite** | `rke_action = RKE_ACTION_REMOTE_DRIVE (20)` |
| Réveiller | `rke_action = RKE_ACTION_WAKE_VEHICLE (30)` |
| Coffre / frunk | `closure_move_request.rear_trunk` / `.front_trunk = CLOSURE_MOVE_TYPE_MOVE (1)` |
| État du véhicule | `information_request.information_request_type = GET_STATUS (0)` — non authentifié |

`RKE_ACTION_REMOTE_DRIVE` est l'équivalent fonctionnel du « démarrage » par clé
téléphone : il autorise le départ sans clé physique présente. La voiture démarre
ensuite normalement (frein, puis sélecteur).

### Séquence « ouvrir et démarrer »

```
scan → connexion → handshake → vérification du tag
     → UNLOCK → attente de la réponse
     → REMOTE_DRIVE → attente de la réponse
```

---

## 9. Reprise de session et resynchronisation

Le véhicule peut répondre par une erreur accompagnée d'une nouvelle session info :

| Faute | Action |
|---|---|
| `ERROR_INVALID_SIGNATURE` (5) | mettre à jour la session, réessayer |
| `ERROR_INVALID_TOKEN_OR_COUNTER` (6) | idem |
| `ERROR_REPEATED_COUNTER` (26) | idem |
| `ERROR_INCORRECT_EPOCH` (15) | idem |
| `ERROR_TIME_EXPIRED` (17) | resynchroniser l'horloge, réessayer |
| `ERROR_UNKNOWN_KEY_ID` (3) | la clé n'est pas appairée → enrôlement |
| `ERROR_INACTIVE_KEY` (4) | clé désactivée côté véhicule |
| `ERROR_KEYCHAIN_IS_FULL` (14) | supprimer une clé depuis l'écran du véhicule |
| `ERROR_BUSY` (1), `ERROR_TIMEOUT` (2), `ERROR_INTERNAL` (11) | réessayer plus tard |

Règle de mise à jour (`UpdateSessionInfo` en Go) : on n'accepte la nouvelle info
que si l'epoch a changé **ou** si son `clock_time` est supérieur ou égal au
dernier connu ; le compteur ne peut que croître.

Mettre la session en cache (clé de session, epoch, compteur, offset d'horloge)
évite un aller-retour de handshake au réveil — précieux sur batterie.

---

## 10. Ce que ce protocole ne couvre pas

L'**entrée passive** (la portière se déverrouille quand on s'approche, sans
action) n'est pas réalisable avec ce protocole seul. Dans ce mode, c'est le
véhicule qui scanne et interroge le téléphone, avec une couche de mesure de
proximité (RSSI/timing) qui ne fait pas partie du code publié par Tesla. Un
firmware basé sur ce document agit en **client** : il se connecte au véhicule et
envoie des commandes authentifiées. Le déclenchement vient donc d'un bouton, ou
de la détection de l'advertisement du véhicule par notre propre firmware.
