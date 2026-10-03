/*
 * teslakey — libelles des codes d'erreur
 */
#include "teslakey/tk_err.h"

const char *tk_strerror(int err)
{
    switch (err) {
    case TK_OK:                   return "ok";
    case TK_ERR_INVAL:            return "argument invalide";
    case TK_ERR_NOMEM:            return "tampon trop petit";
    case TK_ERR_STATE:            return "etat invalide";
    case TK_ERR_CRYPTO:           return "echec d'une operation cryptographique";
    case TK_ERR_DECODE:           return "protobuf malforme";
    case TK_ERR_TRUNCATED:        return "message incomplet";
    case TK_ERR_TIMEOUT:          return "delai depasse";
    case TK_ERR_TRANSPORT:        return "echec du transport BLE";
    case TK_ERR_NOT_FOUND:        return "vehicule non trouve";
    case TK_ERR_STORAGE:          return "echec du stockage persistant";
    case TK_ERR_BAD_TAG:          return "authentification invalide";
    case TK_ERR_BAD_PUBKEY:       return "cle publique invalide";
    case TK_ERR_COUNTER_OVERFLOW: return "debordement du compteur anti-rejeu";
    case TK_ERR_REPLAY:           return "reponse rejouee";
    case TK_ERR_STALE_SESSION:    return "session info recue trop tard";
    case TK_ERR_NO_SESSION:       return "aucune session etablie";
    case TK_ERR_VEHICLE_FAULT:    return "commande refusee par le vehicule";
    case TK_ERR_NOT_WHITELISTED:  return "cle non appairee";
    case TK_ERR_NEEDS_RESYNC:     return "resynchronisation necessaire";
    case TK_ERR_BUSY:             return "vehicule occupe";
    default:                      return "erreur inconnue";
    }
}

/* UniversalMessage.MessageFault_E */
const char *tk_strfault(int fault)
{
    switch (fault) {
    case 0:  return "aucune";
    case 1:  return "sous-systeme occupe";
    case 2:  return "sous-systeme muet";
    case 3:  return "cle inconnue du vehicule";
    case 4:  return "cle desactivee";
    case 5:  return "signature invalide";
    case 6:  return "compteur anti-rejeu deja utilise";
    case 7:  return "privileges insuffisants";
    case 8:  return "domaine invalide";
    case 9:  return "commande inconnue";
    case 10: return "echec de decodage";
    case 11: return "erreur interne du vehicule";
    case 12: return "VIN incorrect";
    case 13: return "parametre invalide";
    case 14: return "trousseau du vehicule plein";
    case 15: return "epoch incorrecte";
    case 16: return "longueur d'IV incorrecte";
    case 17: return "commande expiree";
    case 18: return "vehicule sans VIN provisionne";
    case 19: return "echec du hachage des metadonnees";
    case 20: return "duree de vie trop longue";
    case 21: return "acces mobile desactive par le proprietaire";
    case 22: return "acces service distant desactive";
    case 23: return "identifiants de compte Tesla requis";
    case 24: return "requete superieure au MTU";
    case 25: return "reponse superieure au MTU";
    case 26: return "compteur repete";
    case 27: return "handle de cle invalide";
    case 28: return "chiffrement de la reponse exige";
    default: return "faute inconnue";
    }
}

/* VCSEC.WhitelistOperation_information_E — codes utiles a l'enrolement. */
const char *tk_strwhitelist(int code)
{
    switch (code) {
    case 0:  return "aucune";
    case 1:  return "erreur non documentee";
    case 3:  return "emplacements de cle pleins";
    case 4:  return "liste de cles pleine";
    case 5:  return "pas le droit d'ajouter une cle";
    case 6:  return "cle publique invalide";
    case 13: return "cle deja presente dans la liste";
    case 14: return "ajout autorise seulement sur le lecteur NFC";
    case 19: return "ajout d'une cle sans role";
    case 23: return "echec du demarrage de l'authentification locale";
    case 24: return "refuse sur l'ecran du vehicule";
    case 25: return "delai depasse en attendant la carte NFC";
    case 26: return "delai depasse en attendant la confirmation ecran";
    case 27: return "refuse : mode voiturier actif";
    case 28: return "annule";
    default: return "code de liste blanche inconnu";
    }
}
