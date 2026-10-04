/*
 * teslakey — sommeil profond, reveil par bouton et LED d'etat (ESP32)
 */
#ifndef TESLAKEY_APP_POWER_H
#define TESLAKEY_APP_POWER_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Lecture des gestes, commune au stub de reveil et a la tache qui lit les
 * boutons une fois la carte eveillee. */
#define POWER_LONG_PRESS_MS   800
#define POWER_DEBOUNCE_MS     30
#define POWER_MULTI_GAP_MS    400   /* attente d'un appui suivant */

typedef enum {
    POWER_LED_OFF = 0,
    POWER_LED_BUSY,      /* scintillement rapide : cycle en cours */
    POWER_LED_PAIRING,   /* clignotement lent : carte NFC attendue */
    POWER_LED_OK,        /* fixe 1,5 s puis eteinte : accepte */
    POWER_LED_FAIL,      /* trois eclats puis eteinte : echec */
} power_led;

/* A appeler en tout debut de app_main() : rend aux boutons leur role de
 * GPIO ordinaire apres un reveil, et prepare la LED. buttons liste les
 * broches des boutons, actives a l'etat bas ; une valeur negative designe
 * un bouton absent. Le tableau doit rester valide. */
void power_init(const int *buttons, size_t count);

/* Vrai si ce demarrage est un reveil du sommeil profond par un bouton. */
int power_woke_by_button(void);

/* Geste lu par le stub de reveil, avant meme le redemarrage du firmware :
 * aucun appui d'un double ou triple ne peut ainsi tomber pendant le
 * demarrage. Retourne 1 et remplit clicks (1 a 3) et is_long si le stub a
 * tourne a ce reveil, 0 sinon (demarrage a froid, ou cible sans stub :
 * c'est alors a l'application de lire le geste). */
int power_wake_gesture(int *clicks, int *is_long);

void power_led_set(power_led pattern);

/* Vrai tant qu'un motif de resultat (OK, FAIL) n'est pas fini. */
int power_led_playing(void);

/* Eteint la carte et entre en sommeil profond jusqu'au prochain appui. Ne
 * revient que si aucun bouton ne peut reveiller la puce : dormir serait
 * alors sans retour.
 * timer_s non nul ajoute un reveil par minuterie, pour le banc : la carte
 * redemarre alors comme a froid, sans geste. */
void power_sleep(uint32_t timer_s);

#ifdef __cplusplus
}
#endif

#endif /* TESLAKEY_APP_POWER_H */
