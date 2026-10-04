# teslakey

Firmware pour ouvrir et démarrer une Tesla depuis un microcontrôleur, à la
manière de la clé téléphone, basé sur le protocole publié par Tesla
([`teslamotors/vehicle-command`](https://github.com/teslamotors/vehicle-command)).

Écrit pour être **portable** : le cœur est en C99 pur, sans allocation
dynamique, sans dépendance plateforme. Les cibles actuelles sont l'ESP32
(ESP-IDF) et le nRF52840 (Zephyr / nRF Connect SDK), avec le même code
protocolaire.

---

## État de la validation — à lire avant de flasher

Soyons précis sur ce qui est vérifié et ce qui ne l'est pas.

| Partie | État |
|---|---|
| Cœur protocolaire (`core/`) | **844 vérifications automatisées, 0 échec.** Compile sans aucun avertissement avec `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wcast-qual` ; l'analyseur statique de clang ne signale rien. |
| Conformité crypto | Validée contre les **vecteurs de test officiels de Tesla** (ECDH P-256 avec secret à octet de tête nul, dérivation de clé publique, somme de contrôle des métadonnées) et les vecteurs HMAC de la RFC 4231. |
| Crypto embarquée (`hal/common/`) | **Compilée et testée.** Le module mbedTLS, celui qui tournera réellement sur ESP32 et nRF, passe les mêmes vecteurs Tesla que la référence OpenSSL, s'accorde bit à bit avec elle (AES-GCM et ECDH croisés), et fait tourner toute la machine à états. Validé sur mbedTLS 3.6, la série qu'embarquent ESP-IDF v5 et le nRF Connect SDK. |
| Bout en bout | 9 scénarios contre un véhicule simulé, rejoués sur les **deux** backends crypto : handshake, enchaînement ouvrir → conduire, tag falsifié, clé non appairée puis appairage, resynchronisation, réponse rejouée, déconnexion, échéances, persistance de la clé. |
| HAL ESP32 (`hal/esp32/`) | **Compile et se lie, sans un seul avertissement**, sur ESP-IDF 5.3.2 via PlatformIO, pour ESP32 classique (`esp32dev`) comme pour ESP32-S3 (`heltec_wifi_lora_32_V3`). Vérifié au-delà du simple « build OK » : `libteslakey.a` fait 503 Ko et tous les symboles du cœur comme du HAL sont présents dans l'ELF. Empreinte : **RAM 9,8 %** / Flash 524 Ko sur ESP32, **RAM 8,2 %** / Flash 535 Ko sur S3. |
| Exécution sur matériel | **Testé sur un Heltec WiFi LoRa 32 V3 (ESP32-S3)** : flashé après effacement complet, démarre, console série opérationnelle. Validé en vrai : génération de la clé P-256 par mbedTLS sur la puce, écriture puis relecture en NVS, repli sur le VIN de configuration, et **nom BLE calculé par le firmware identique à la référence OpenSSL**. |
| HAL nRF (`hal/nrf/`) | **Écrit mais jamais compilé** — le nRF Connect SDK n'est pas installé sur cette machine. |
| Compatibilité ESP-IDF 4.x | Les adaptations sont en place (API NimBLE et mbedTLS 2.x), mais **seul le chemin mbedTLS 3.x a été compilé**. Concerne PlatformIO : voir la section ESP32. |
| Sur un vrai véhicule | **Essayé le 4 octobre 2026** avec le Heltec V3 : scan, connexion, appairage par carte NFC, session authentifiée, `unlock`, `lock`, `drive` acceptés. La clé survit à un redémarrage. Voir `TODO.md` pour ce que l'essai a corrigé. |

Autrement dit : la partie difficile et piégeuse — la cryptographie et le
format exact des messages — est testée, conforme aux vecteurs de Tesla, et
l'a été jusque dans l'implémentation mbedTLS qui tournera sur la cible. Ce
qui reste non vérifié, c'est la plomberie : pilotes BLE, stockage flash,
horloge. Attendez-vous à y corriger des noms de symboles à la première
compilation, selon la version de votre SDK.

Commencez par `make -C tests test` : si les vérifications passent sur votre
machine, le protocole est bon et il ne reste que le portage. Puis
`make -C tests mbedtls` pour valider en plus la crypto de la cible (il faut
mbedTLS 3.x installé).

---

## Ce que ça fait, et ce que ça ne fait pas

**Ça fait :**

- s'enrôler comme clé auprès du véhicule (clé P-256, approbation par carte NFC)
- ouvrir une session authentifiée en BLE (ECDH P-256 → AES-128-GCM)
- déverrouiller, verrouiller, ouvrir le coffre ou le coffre avant
- **autoriser la conduite** (`RKE_ACTION_REMOTE_DRIVE`), c'est-à-dire
  l'équivalent fonctionnel du « démarrage » par clé téléphone : la voiture
  part ensuite normalement, frein puis sélecteur

**Ça ne fait pas : l'entrée passive.** La portière ne se déverrouille pas
toute seule quand vous approchez. Dans ce mode, c'est le véhicule qui
scanne et interroge le téléphone, avec une couche de mesure de proximité
qui ne fait pas partie du code publié par Tesla. Ce firmware agit en
**client** : il se connecte au véhicule et envoie des commandes signées.
Le déclenchement vient donc d'un bouton — ou, si vous le souhaitez, de la
détection de l'advertisement du véhicule par le firmware lui-même.

---

## Architecture

```
core/                 C99 pur, portable, zéro dépendance plateforme
  include/teslakey/   API publique
  src/
    tk_pb.c           codec protobuf minimal, décodage en zéro-copie
    tk_digest.c       HMAC-SHA256 au-dessus du SHA-256 du HAL
    tk_meta.c         sérialisation TLV des métadonnées authentifiées
    tk_session.c      ECDH, dérivation, signature, anti-rejeu
    tk_frame.c        framing BLE (préfixe de longueur, réassemblage)
    tk_msg.c          RoutableMessage
    tk_vcsec.c        commandes VCSEC et enrôlement
    tk_client.c       machine à états non bloquante

hal/
  common/             crypto mbedTLS — partagé ESP32 et nRF
  esp32/              NimBLE, NVS, esp_timer
  nrf/                Bluetooth Zephyr, settings, k_uptime

apps/esp32/           application ESP-IDF (bouton + console série)
apps/nrf52840/        application Zephyr (bouton seul)
tests/                HAL hôte sur OpenSSL + suite de tests
docs/PROTOCOL.md      la spécification, vérifiée ligne à ligne
```

Trois décisions de conception méritent une explication.

**Pas de nanopb.** Les messages nécessaires sont peu nombreux et simples.
Un codec protobuf maison de ~300 lignes évite un générateur de code, toute
dépendance externe et tout `malloc` — et surtout il permet le décodage en
zéro-copie. C'est indispensable : le HMAC de la session info porte sur les
octets **reçus tels quels**, et ré-encoder le protobuf avant de vérifier
produirait un tag différent.

**HMAC-SHA256 dans le cœur, pas dans le HAL.** Il est construit au-dessus
du seul SHA-256 en flux. Cela réduit la surface à implémenter pour une
nouvelle plateforme, évite les contextes HMAC à allocation dynamique de
mbedTLS et de PSA, et garantit un résultat identique bit à bit sur toutes
les cibles.

**Machine à états non bloquante.** Pas de thread, pas d'allocation. C'est
ce qui permet au même code de tourner dans une tâche FreeRTOS et dans la
boucle d'un thread Zephyr.

---

## Compiler et tester le cœur

```sh
cd tests
make test
```

Il faut un compilateur C99 et OpenSSL 3 (`libcrypto`). Sur Windows avec
MSYS2 : `mingw32-make CC=gcc` depuis un shell MINGW64.

`make strict` recompile le cœur avec un jeu d'avertissements élargi et doit
rester silencieux.

---

## ESP32 (WROOM, Heltec WiFi Kit 32, WiFi LoRa 32, C3, S3)

Le dossier `apps/esp32/` sert **aux deux chaînes d'outils**, sans
duplication de code : c'est un projet ESP-IDF standard, et PlatformIO
réutilise la même arborescence.

### IDE Espressif, ou `idf.py` en ligne de commande

C'est la cible de référence : ESP-IDF **v5.x**, en CMake natif. Fonctionne
avec l'extension *Espressif IDF* de VS Code, le plugin Eclipse, ou
directement :

```sh
cd apps/esp32
idf.py set-target esp32          # ou esp32c3, esp32s3
idf.py menuconfig                # teslakey → VIN, GPIO du bouton
idf.py build flash monitor
```

### PlatformIO

```sh
cd apps/esp32
pio run -e esp32dev -t upload -t monitor
```

Environnements prédéfinis : `esp32dev`, `heltec_wifi_kit_32`,
`heltec_wifi_lora_32_V2`, `heltec_wifi_lora_32_V3`, `esp32c3`.

Un avertissement s'impose. Le paquet `espressif32` officiel de PlatformIO
est resté longtemps sur **ESP-IDF 4.4**, où les API NimBLE et mbedTLS
diffèrent de la v5. Le code contient les adaptations nécessaires
(`hal/common/tk_crypto_mbedtls.c` et `hal/esp32/tk_ble_nimble.c` testent la
version), **mais le chemin 4.x n'a pas pu être compilé ici** : seul
mbedTLS 3.x l'a été. Vérifiez ce que vous avez :

```sh
pio run -e esp32dev -v 2>&1 | grep -i "esp-idf\|framework-espidf"
```

Si c'est une 4.x et que ça coince, passez au fork communautaire
[pioarduino](https://github.com/pioarduino/platform-espressif32/releases),
qui suit les ESP-IDF 5.x — la ligne `platform` à remplacer est commentée
dans `platformio.ini`.

### À propos de la place en flash

Le pourcentage affiché par PlatformIO compare l'application à la **flash
totale** de la carte, ce qui est trompeur. Ce qui compte, c'est la
partition : la table par défaut réserve 1 Mo à `factory`, et le firmware en
occupe environ 535 Ko, soit la moitié. La marge est confortable, mais si
vous ajoutez beaucoup de code (OTA, écran, LoRa), prévoyez une table de
partition personnalisée.

### À propos du MTU

L'ESP32 classique est en BLE 4.2 : le MTU reste généralement à 23, donc les
messages partent en blocs de 20 octets. C'est le cas normal, pas une
dégradation — le framing est écrit pour ça et c'est le cas testé.

### Première mise en service

Le VIN ne se versionne pas. Copiez `secrets/tk_secrets.example.h` en
`secrets/tk_secrets.h` (ignoré par git) et mettez-y le vôtre : il est
compilé dans le firmware. Sans ce fichier, la compilation utilise un VIN
fictif, à remplacer par la commande `vin` de la console.

Il ne reste alors qu'une commande à taper dans le moniteur série :

```
pair
```

Puis **posez votre carte NFC Tesla sur la console centrale** et confirmez à
l'écran. Le véhicule doit être réveillé et vous à l'intérieur.

Au démarrage, le firmware affiche le nom BLE qu'il recherche, dérivé du
VIN. Si le véhicule n'est jamais trouvé alors qu'une ligne `autre Tesla en
vue : S…C` apparaît, le VIN saisi est faux. La commande `vin <17
caractères>` change de véhicule et rend le choix persistant en mémoire.

Ensuite le bouton suffit : appui court pour ouvrir, appui long pour ouvrir
et autoriser la conduite. Autres commandes : `unlock`, `lock`, `drive`,
`trunk`, `frunk`, `chargeport`, `status`, `help`.

---

## nRF52840

```sh
cd apps/nrf52840
west build -b nrf52840dk/nrf52840
west flash
```

Le VIN est fourni à la compilation (`secrets/tk_secrets.h`, à défaut
`CONFIG_TESLAKEY_VIN` dans `Kconfig`),
la carte n'ayant pas forcément de console. Pour cibler un autre véhicule :

```sh
west build -b nrf52840dk/nrf52840 -- -DCONFIG_TESLAKEY_VIN='"<17 caractères>"'
```

Le bouton `sw0` de l'arbre matériel : appui court pour ouvrir, appui long
pour ouvrir et conduire, appui de plus de 3 s pour demander l'appairage.

Sur nRF52840, `nrf_security` adosse mbedTLS à CryptoCell (CC310) : P-256 et
AES-GCM passent par le matériel sans rien changer au code. Sur nRF52832,
dépourvu de CryptoCell, P-256 tourne en logiciel et la marge RAM est
étroite — surveillez `CONFIG_BT_RX_STACK_SIZE` et `CONFIG_MAIN_STACK_SIZE`.

---

## Porter sur une autre plateforme

Un seul fichier à lire : `core/include/teslakey/tk_hal.h`. Il faut fournir

- **crypto** : RNG, SHA-1 en une passe, SHA-256 en flux, AES-128-GCM,
  et trois opérations P-256 (génération, clé publique depuis le scalaire,
  ECDH rendant la coordonnée X sur 32 octets complétée à gauche)
- **BLE** : rôle central, scan par nom local, connexion, écriture sans
  réponse, MTU
- **stockage** : trois paires clé/valeur
- **horloge** : millisecondes monotones depuis le démarrage

Si mbedTLS est disponible, `hal/common/tk_crypto_mbedtls.c` couvre déjà
toute la partie crypto : il ne reste que `tk_platform_rng()` à écrire.

`tests/hal_host.c` est une implémentation de référence complète sur
OpenSSL, utile comme modèle.

Deux pièges à connaître :

- **L'ECDH doit valider le point distant** (appartenance à la courbe, rejet
  du point à l'infini). Sans ce contrôle, un point choisi par un attaquant
  ouvre une attaque par courbe invalide. Les deux implémentations fournies
  le font ; un test le vérifie.
- **La réentrance.** Le cœur n'est pas réentrant et les piles BLE remontent
  leurs événements depuis leur propre thread. Les deux HAL fournissent un
  mutex (`tk_hal_esp32_lock()`, `tk_hal_nrf_lock()`) ; il faut en entourer
  les appels à `tk_client_tick()` et aux fonctions de commande.

---

## Sécurité

La clé privée P-256 est stockée en clair dans la mémoire non volatile
(NVS sur ESP32, `settings` sur nRF). **Quiconque a la carte en main peut
l'extraire et ouvrir puis démarrer la voiture.** C'est une clé de voiture :
traitez-la comme telle.

Pour faire mieux :

- chiffrer le flash (`CONFIG_SECURE_FLASH_ENC_ENABLED` sur ESP32, TF-M sur
  nRF5340)
- enrôler la clé avec `TK_ROLE_DRIVER` plutôt que `TK_ROLE_OWNER` — c'est
  le défaut ici : la clé peut ouvrir et conduire, mais pas ajouter ou
  retirer d'autres clés
- garder `ROLE_OWNER` pour votre téléphone, et révoquer la clé depuis
  l'écran du véhicule si vous perdez la carte

Le protocole lui-même est solide : chaque commande est chiffrée et
authentifiée, avec un compteur anti-rejeu et une expiration de 5 secondes.
Une commande capturée en l'air ne peut pas être rejouée.

---

## Dépannage

| Symptôme | Piste |
|---|---|
| Le véhicule n'est jamais trouvé | Le nom BLE dépend du VIN : vérifiez-le caractère par caractère. `status` affiche le nom recherché. Le véhicule doit être réveillé. |
| « cle non appairée » | Normal au premier démarrage ou après effacement du flash. Lancez `pair`. |
| « vehicule non connectable » | La Tesla accepte un nombre limité de connexions BLE simultanées. Éloignez les téléphones appairés, ou coupez leur Bluetooth. |
| « trousseau du vehicule plein » | Supprimez une clé depuis l'écran du véhicule (limite d'environ 19). |
| « delai depasse en attendant la carte NFC » | L'approbation a expiré : relancez `pair` et posez la carte sans attendre. |
| « commande expiree » | Désynchronisation d'horloge. Le client se resynchronise seul ; si cela persiste, c'est un problème d'horloge monotone dans le HAL. |

---

## Licence et responsabilité

teslakey est un logiciel libre sous **GNU GPL version 3 ou ultérieure**
(`LICENSE`). Vous pouvez l'utiliser, le modifier et le redistribuer, à
condition que toute version redistribuée, modifiée ou non, reste sous la
même licence et que son code source soit fourni. Il est distribué sans
aucune garantie.

Les fichiers `docs/*.proto` sont des copies non modifiées de
[`teslamotors/vehicle-command`](https://github.com/teslamotors/vehicle-command),
publié par Tesla sous licence Apache 2.0 (`docs/LICENSE-Apache-2.0.txt`) ;
ils restent sous cette licence. Le détail est dans `NOTICE`. Ce projet
n'est ni affilié à Tesla, ni approuvé par elle.

Ce code pilote un véhicule. Il n'a été essayé que sur une seule voiture.
Faites vos premiers essais à l'arrêt, dans un endroit sûr, et ne comptez pas
dessus comme unique moyen d'accès avant de l'avoir éprouvé : gardez votre
carte NFC sur vous.
