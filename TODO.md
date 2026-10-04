# Reste à faire

État au 4 octobre 2026. **Le firmware a ouvert et autorisé la conduite d'un
vrai véhicule** depuis le Heltec WiFi LoRa 32 V3 (ESP32-S3).

---

## 1. Essai dans la voiture — fait le 4 octobre 2026

Résultat : scan (RSSI −40 dBm dans l'habitacle), connexion, MTU 247,
découverte GATT, appairage par carte NFC (≈ 6 s entre `pair` et
l'acceptation), session authentifiée, `unlock` et `drive` acceptés, `lock`
refusé proprement portière ouverte. Après redémarrage la clé est relue de
la NVS et reconnue. Un cycle complet scan → commande acceptée prend ≈ 1,8 s.

Ce que l'essai a révélé et corrigé :

| Constat sur véhicule | Correction |
|---|---|
| Le nom BLE est dans la **réponse de scan**, pas dans l'advertisement | Scan actif ; la connectabilité est mémorisée depuis l'advertisement (`tk_ble_nimble.c`) |
| Le VIN configuré avait une faute de frappe | VIN corrigé ; le HAL signale désormais toute autre Tesla en vue |
| `ble_gattc_disc_svc_by_uuid` ne trouve pas le service `0211` | Énumération de tous les services |
| Clé inconnue : session info `KEY_NOT_ON_WHITELIST` **sans tag** | Le cœur la reconnaît au lieu de l'ignorer |
| L'enrôlement n'est pas acquitté par le véhicule | `pair` enchaîne connexion → demande, puis redemande une session toutes les 2 s (60 s max) |
| Débordement de pile de la tâche hôte NimBLE (4 Ko) pendant l'ECDH | `CONFIG_BT_NIMBLE_HOST_TASK_STACK_SIZE=8192` |
| VCSEC répond **en clair**, rattaché par `request_uuid` ; payload vide = succès | Nouveau chemin de réception, `TK_ERR_CLOSURES_OPEN` |

Le journal brut de la séance est dans `essai-vehicule.log` (non versionné).

Pour revoir les trames : passer le niveau de log à `DEBUG`, le HAL dumpe
alors chaque bloc TX/RX en hexadécimal.

---

## 2. Suites directes de l'essai

- [ ] **Sortir la crypto de la tâche hôte NimBLE.** Agrandir la pile règle
      le plantage, mais le cœur tourne toujours dans le rappel GAP. Mieux :
      poster les blocs reçus dans une file et les traiter dans la tâche
      principale.
- [ ] Les réponses VCSEC en clair ne sont pas authentifiées (comme dans le
      client officiel). Envisager `FLAG_ENCRYPT_RESPONSE` pour que
      « accepté » soit une affirmation signée du véhicule.
- [ ] `trunk` (ouvre puis referme), `frunk` et `chargeport` essayés avec
      succès. Le port de charge ne libère le câble qu'avec le type MOVE :
      OPEN est accepté mais ne déverrouille pas le loquet. Reste : le
      bouton (appui court / long) et `lock` portes fermées.
- [ ] Reporter sur le HAL nRF la mémorisation de connectabilité et vérifier
      la découverte de service (le scan actif y est déjà reporté, non
      compilé).
- [ ] Commande `scan` de diagnostic, qui s'arrête après le handshake.

---

## 3. Non vérifié à ce jour

- [ ] **HAL nRF (`hal/nrf/`) : jamais compilé.** Le nRF Connect SDK n'est
      pas installé. Tout le fichier `tk_ble_zephyr.c` est du code neuf ;
      la machine de découverte GATT de Zephyr y est la partie la plus
      susceptible de devoir être reprise.
- [ ] **Chemin mbedTLS 2.x : jamais compilé.** Les adaptations sont en
      place (`MBEDTLS_VERSION_MAJOR < 3`) mais seul le 3.x a été éprouvé.
      Ne concerne que les ESP-IDF 4.x, donc pas notre configuration
      actuelle (ESP-IDF 5.3.2 via PlatformIO).
- [ ] Environnements PlatformIO `heltec_wifi_kit_32` et `esp32c3` : builds
      lancés mais interrompus. Le `esp32c3` est en **RISC-V** : c'est le
      test de portabilité d'architecture qui reste à passer.

---

## 4. Améliorations identifiées

- [ ] **Cache de session en NVS.** `tk_session` sait déjà exporter son état
      (clé, epoch, compteur, offset d'horloge). Le persister éviterait un
      aller-retour de handshake au réveil — intéressant sur batterie.
- [ ] **Déclenchement automatique à portée.** Le firmware voit déjà
      l'advertisement du véhicule et son RSSI. Déverrouiller au-delà d'un
      seuil serait le plus proche de la clé téléphone, mais attention aux
      ouvertures involontaires : prévoir une hystérésis et un délai de
      garde.
- [ ] **Écran OLED du Heltec** : afficher l'état et le RSSI. Il reste
      largement la place (RAM 8 %, flash 535 Ko sur 1 Mo de partition).
- [ ] Commandes supplémentaires du domaine VCSEC déjà encodables :
      coffre avant, trappe de recharge.
- [ ] Domaine `DOMAIN_INFOTAINMENT` (climatisation, recharge) : demanderait
      d'ajouter `car_server.proto`, soit ~50 Ko de définitions. Volontairement
      laissé de côté : inutile pour ouvrir et démarrer.

---

## 5. Sécurité, avant tout usage quotidien

- [ ] **Chiffrer le flash** (`CONFIG_SECURE_FLASH_ENC_ENABLED`). Aujourd'hui
      la clé privée P-256 est en clair en NVS : qui tient la carte peut
      l'extraire et démarrer la voiture.
- [ ] Garder `TK_ROLE_DRIVER` (c'est le défaut) et non `ROLE_OWNER` : la
      clé peut ouvrir et conduire, mais pas gérer les autres clés.
- [x] Savoir révoquer : clé supprimée depuis l'écran le 4 octobre 2026, la
      voiture répond alors « clé non appairée » ; réappairage réussi dans
      la foulée.
- [x] Le VIN n'est plus dans le dépôt : il vit dans `secrets/tk_secrets.h`
      (ignoré par git), seul `tk_secrets.example.h` est versionné. Les
      Kconfig et les tests n'utilisent que des VIN fictifs.

---

## 6. Ce qui est acquis

- Cœur protocolaire : 844 vérifications, 0 échec, dont les **vecteurs de
  test officiels de Tesla** (ECDH P-256, dérivation de clé publique,
  somme de contrôle des métadonnées) et les vecteurs HMAC de la RFC 4231.
- Compile sans aucun avertissement avec `-Wall -Wextra -Wpedantic
  -Wconversion -Wsign-conversion -Wcast-qual` ; l'analyseur statique de
  clang ne signale rien.
- Module crypto mbedTLS (celui de la cible) validé contre les mêmes
  vecteurs et en interopérabilité bit à bit avec OpenSSL.
- ESP32 et ESP32-S3 : compilation et lien sans avertissement, symboles
  vérifiés dans l'ELF.
- Sur véhicule : appairage, session, ouvrir, verrouiller, autoriser la
  conduite (voir section 1).
- Sur matériel : démarrage, console, génération de la clé P-256 par la
  puce, persistance NVS dans les deux sens, et nom BLE calculé par le
  firmware identique à la référence OpenSSL.
