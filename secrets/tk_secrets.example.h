/*
 * teslakey — secrets de compilation (EXEMPLE)
 *
 * Copier ce fichier en "tk_secrets.h" dans ce meme dossier, puis y mettre
 * le vrai VIN. tk_secrets.h est ignore par git : il ne doit jamais etre
 * pousse. Sans lui, la compilation retombe sur le VIN d'exemple de
 * Kconfig, a remplacer ensuite par la commande 'vin' de la console.
 *
 * Le VIN ci-dessous est fictif.
 */
#ifndef TK_SECRETS_H
#define TK_SECRETS_H

/* VIN du vehicule : exactement 17 caracteres. */
#define TK_SECRET_VIN "5YJ3E1EA7JF000000"

#endif /* TK_SECRETS_H */
