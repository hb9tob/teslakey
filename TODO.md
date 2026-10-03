# Reste à faire

État au 3 octobre 2026. Le cœur protocolaire est testé et le firmware tourne
sur un Heltec WiFi LoRa 32 V3 (ESP32-S3), mais **le BLE n'a jamais vu le
véhicule**. C'est l'objet de la prochaine séance.

---

## 1. Essai dans la voiture — la prochaine étape

### À emporter

- la carte Heltec V3 flashée, sur COM9
- un PC portable avec un câble USB (la console série est le seul moyen de
  lancer l'appairage aujourd'hui)
- **la carte-clé NFC Tesla** : sans elle, aucun appairage n'est possible
- de quoi couper le Bluetooth des téléphones présents (voir pièges)

### Procédure

1. Réveiller le véhicule (ouvrir une portière suffit) et s'installer
   dedans. L'appairage exige d'être à l'intérieur.
2. Ouvrir la console série :
   `pio device monitor -p COM9 -b 115200` depuis `apps/esp32/`
3. Vérifier au démarrage la ligne
   `nom BLE recherche : S57bfc47617573c4eC`.
   C'est la valeur attendue pour le VIN `5YJ3E1EA7JF000000`.
4. Taper `unlock` : cela déclenche scan → connexion → handshake. Attendu à
   ce stade, puisque la clé n'est pas encore appairée :
   `cle non appairee` et l'invitation à taper `pair`.
   C'est **le premier vrai test du BLE** : s'il arrive jusque-là, le scan,
   la découverte GATT et le transport fonctionnent.
5. Taper `pair`, puis **poser la carte NFC sur la console centrale** et
   confirmer sur l'écran du véhicule. Sans traîner : l'approbation expire.
6. Taper `unlock` à nouveau. Les portières doivent se déverrouiller.
7. `drive` : déverrouille puis autorise la conduite. **À l'arrêt, dans un
   endroit sûr.** Vérifier qu'on peut enclencher une position sans la carte
   NFC sur le lecteur.
8. Couper l'alimentation, rebrancher : la clé doit être relue depuis la NVS
   (`cle existante rechargee`) et `unlock` doit marcher sans réappairer.

### Ce qu'il faut noter pendant l'essai

Le journal est la seule trace : **copier tout le log de la console**, même
en cas de succès. En particulier :

- le RSSI et le temps mis pour trouver le véhicule
- le MTU négocié (`MTU negocie : N`) — s'il reste à 23, c'est normal
- tout message `decouverte GATT : ...` : c'est là que le HAL NimBLE est le
  plus susceptible de se tromper (handles, CCCD)
- le délai entre `pair` et l'acceptation

### Pièges connus

| Symptôme | Cause probable |
|---|---|
| Le véhicule n'est jamais trouvé | Véhicule endormi, ou VIN erroné. Vérifier le nom BLE annoncé au démarrage avec un scanner BLE sur téléphone (nRF Connect). |
| `vehicule non connectable (trop de liens)` | La Tesla limite le nombre de connexions BLE. Couper le Bluetooth des téléphones appairés. |
| `delai depasse en attendant la carte NFC` | L'approbation a expiré. Relancer `pair` et poser la carte immédiatement. |
| `decouverte GATT : CCCD de RX introuvable` | Bug dans `tk_ble_nimble.c` : la plage de recherche du descripteur. |
| `commande expiree` à répétition | Horloge : vérifier `clock_offset_s` et la resynchronisation. |
| `trousseau du vehicule plein` | Supprimer une clé depuis l'écran du véhicule (limite ~19). |

---

## 2. À faire avant l'essai (recommandé)

- [ ] **Ajouter une commande `scan` à la console.** Aujourd'hui, pour tester
      le BLE il faut taper `unlock`, qui met une action en file. Sans risque
      tant que la clé n'est pas appairée, mais il manque une commande qui
      s'arrête après le handshake sans rien envoyer au véhicule. Utile pour
      diagnostiquer sans agir sur la voiture.
- [ ] Augmenter le niveau de log à `DEBUG` pour l'essai
      (`CONFIG_LOG_DEFAULT_LEVEL_DEBUG=y` dans `sdkconfig.defaults`) :
      les traces de réassemblage et d'aiguillage des messages seront
      précieuses en cas d'échec.

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
- [ ] Savoir révoquer : la clé se supprime depuis l'écran du véhicule.
      À tester une fois, pour ne pas le découvrir en urgence.
- [ ] **Le VIN est en clair** dans `apps/esp32/main/Kconfig.projbuild`,
      `apps/nrf52840/Kconfig` et `tests/test_main.c`. Nécessaire au
      fonctionnement, mais à remplacer par un VIN d'exemple si ce dépôt
      devient public.

---

## 6. Ce qui est acquis

- Cœur protocolaire : 798 vérifications, 0 échec, dont les **vecteurs de
  test officiels de Tesla** (ECDH P-256, dérivation de clé publique,
  somme de contrôle des métadonnées) et les vecteurs HMAC de la RFC 4231.
- Compile sans aucun avertissement avec `-Wall -Wextra -Wpedantic
  -Wconversion -Wsign-conversion -Wcast-qual` ; l'analyseur statique de
  clang ne signale rien.
- Module crypto mbedTLS (celui de la cible) validé contre les mêmes
  vecteurs et en interopérabilité bit à bit avec OpenSSL.
- ESP32 et ESP32-S3 : compilation et lien sans avertissement, symboles
  vérifiés dans l'ELF.
- Sur matériel : démarrage, console, génération de la clé P-256 par la
  puce, persistance NVS dans les deux sens, et nom BLE calculé par le
  firmware identique à la référence OpenSSL.
