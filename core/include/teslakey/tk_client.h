/*
 * teslakey — API publique
 *
 * Machine a etats NON BLOQUANTE, sans thread, sans allocation dynamique.
 * C'est ce qui permet de la faire tourner aussi bien dans une tache
 * FreeRTOS (ESP-IDF) que dans la boucle systeme de Zephyr (nRF).
 *
 * Boucle d'integration typique :
 *
 *     tk_client_init(&c, &hal, &cb, NULL);
 *     tk_client_set_vin(&c, "5YJ3E1EA7JF000000");
 *     tk_client_load_or_create_key(&c);
 *     tk_client_start(&c);                  // scan -> connexion -> handshake
 *     for (;;) {
 *         tk_client_tick(&c);               // echeances, ~100 ms suffisent
 *         attendre_evenement();
 *     }
 *
 * Le HAL BLE remonte les evenements par tk_client_on_*(). Ces fonctions
 * peuvent etre appelees depuis le contexte de la pile BLE : elles ne
 * bloquent pas, mais elles ne sont pas reentrantes. Si la pile BLE tourne
 * dans une autre tache que tk_client_tick(), serialiser les appels
 * (mutex, ou file d'evenements vers la tache applicative).
 */
#ifndef TESLAKEY_TK_CLIENT_H
#define TESLAKEY_TK_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "teslakey/tk_config.h"
#include "teslakey/tk_err.h"
#include "teslakey/tk_hal.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Taille du tampon d'emission. Le plus gros message est une commande
 * signee : en-tete (~45) + texte chiffre + SignatureData (~160). */
#define TK_TX_BUF_LEN       512

/* Profondeur de la file de commandes (ex. UNLOCK puis REMOTE_DRIVE). */
#define TK_CMD_QUEUE_LEN    4

/* Echeances de la machine a etats. */
#define TK_SCAN_TIMEOUT_MS      15000
#define TK_CONNECT_TIMEOUT_MS   10000
#define TK_HANDSHAKE_TIMEOUT_MS  5000
#define TK_COMMAND_TIMEOUT_MS    5000

typedef enum {
    TK_STATE_IDLE = 0,
    TK_STATE_SCANNING,
    TK_STATE_CONNECTING,
    TK_STATE_HANDSHAKE,     /* requete de session envoyee */
    TK_STATE_READY,         /* session authentifiee, pret a commander */
    TK_STATE_COMMAND,       /* commande emise, en attente de reponse */
    TK_STATE_ENROLLING,     /* demande d'ajout de cle envoyee */
} tk_state;

/* Actions de haut niveau exposees a l'application. */
typedef enum {
    TK_ACTION_UNLOCK = 0,
    TK_ACTION_LOCK,
    TK_ACTION_REMOTE_DRIVE,
    TK_ACTION_WAKE,
    TK_ACTION_OPEN_TRUNK,
    TK_ACTION_OPEN_FRUNK,
} tk_action;

typedef struct {
    /* Changement d'etat. Peut etre NULL. */
    void (*on_state)(void *user, tk_state state);

    /* La session est etablie : les commandes peuvent partir. */
    void (*on_ready)(void *user);

    /* Fin d'une action : err == TK_OK si le vehicule l'a acceptee. */
    void (*on_action_done)(void *user, tk_action action, int err);

    /* Notre cle n'est pas (ou plus) appairee. L'application doit appeler
     * tk_client_enroll() puis demander a l'utilisateur de poser sa carte
     * NFC sur la console centrale. */
    void (*on_not_whitelisted)(void *user);

    /* Erreur non rattrapable du cycle courant. La machine retourne a
     * TK_STATE_IDLE ; a l'application de decider de reessayer. */
    void (*on_error)(void *user, int err);
} tk_client_cb;

/* Etat interne. Opaque en pratique : ne pas toucher aux champs. */
typedef struct tk_client tk_client;

#include "teslakey/tk_client_impl.h"

/* ------------------------------------------------------------------ */
/* Cycle de vie                                                        */
/* ------------------------------------------------------------------ */

/* hal est copie dans le client : la structure appelante peut etre
 * temporaire, mais les pointeurs ctx qu'elle contient doivent survivre. */
int tk_client_init(tk_client *c, const tk_hal *hal,
                   const tk_client_cb *cb, void *user);

/* vin : 17 caracteres ASCII. Persiste dans le stockage. */
int tk_client_set_vin(tk_client *c, const char *vin);

/* Charge la cle privee depuis le stockage, ou en genere une et l'ecrit.
 * Retourne 1 si une nouvelle cle a ete creee (il faudra donc s'enroler),
 * 0 si une cle existante a ete rechargee, ou une erreur negative. */
int tk_client_load_or_create_key(tk_client *c);

/* Clef publique au format non compresse (65 octets). */
const uint8_t *tk_client_public_key(const tk_client *c);

/* Nom local BLE attendu du vehicule (§1). out doit faire au moins
 * TK_LOCAL_NAME_LEN + 1 octets ; le resultat est termine par un nul. */
int tk_client_local_name(const tk_client *c, char *out, size_t out_len);

/* ------------------------------------------------------------------ */
/* Pilotage                                                            */
/* ------------------------------------------------------------------ */

/* Lance le cycle : scan, connexion, handshake. */
int tk_client_start(tk_client *c);

/* Interrompt tout et revient a TK_STATE_IDLE. */
void tk_client_stop(tk_client *c);

/* Met une action en file. Si la session est prete, elle part aussitot ;
 * sinon elle attend la fin du handshake. */
int tk_client_queue(tk_client *c, tk_action action);

/* Raccourci "ouvrir et demarrer" : UNLOCK puis REMOTE_DRIVE (§8). */
int tk_client_unlock_and_drive(tk_client *c);

/* Demande d'enrolement (§7). A appeler apres on_not_whitelisted().
 * role : TK_ROLE_DRIVER (defaut conseille) ou TK_ROLE_OWNER. */
int tk_client_enroll(tk_client *c, uint32_t role);

/* A appeler regulierement (100 ms suffisent) pour les echeances. */
void tk_client_tick(tk_client *c);

tk_state tk_client_state(const tk_client *c);

/* ------------------------------------------------------------------ */
/* Evenements remontes par le HAL BLE                                  */
/* ------------------------------------------------------------------ */

/* name n'a pas besoin d'etre termine par un nul : name_len l'indique. */
void tk_client_on_scan_result(tk_client *c, const tk_ble_peer *peer,
                              const char *name, size_t name_len);
void tk_client_on_connected(tk_client *c);
void tk_client_on_disconnected(tk_client *c);
void tk_client_on_ble_data(tk_client *c, const uint8_t *data, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* TESLAKEY_TK_CLIENT_H */
