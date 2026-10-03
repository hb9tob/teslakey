/*
 * teslakey — tests du coeur
 *
 * Les vecteurs marques [TESLA] proviennent des tests unitaires du depot
 * officiel teslamotors/vehicle-command : ce sont les seuls qui prouvent la
 * CONFORMITE au protocole. Les autres verifient la coherence interne.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "teslakey/tk_client.h"
#include "teslakey/tk_err.h"
#include "teslakey/tk_frame.h"
#include "teslakey/tk_session.h"

#include "hal_host.h"
#include "tk_digest.h"
#include "tk_meta.h"
#include "tk_msg.h"
#include "tk_pb.h"
#include "tk_vcsec.h"

/* ------------------------------------------------------------------ */
/* Mini cadre de test                                                  */
/* ------------------------------------------------------------------ */

static int g_fail;
static int g_checks;
static const char *g_test;

#define CHECK(cond)                                                       \
    do {                                                                  \
        g_checks++;                                                       \
        if (!(cond)) {                                                    \
            printf("  ECHEC %s:%d  %s\n", __FILE__, __LINE__, #cond);     \
            g_fail++;                                                     \
        }                                                                 \
    } while (0)

#define CHECK_MEM(a, b, n)                                                \
    do {                                                                  \
        g_checks++;                                                       \
        if (memcmp((a), (b), (n)) != 0) {                                  \
            printf("  ECHEC %s:%d  %s != %s\n",                           \
                   __FILE__, __LINE__, #a, #b);                           \
            dump("    obtenu ", (const uint8_t *)(a), (n));               \
            dump("    attendu", (const uint8_t *)(b), (n));               \
            g_fail++;                                                     \
        }                                                                 \
    } while (0)

static void dump(const char *label, const uint8_t *p, size_t n)
{
    size_t i;

    printf("%s: ", label);
    for (i = 0; i < n; i++) {
        printf("%02x", p[i]);
    }
    printf("\n");
}

static void begin(const char *name)
{
    g_test = name;
    printf("== %s\n", name);
}

/* ------------------------------------------------------------------ */
/* [TESLA] Serialisation des metadonnees — metadata_test.go/TestCheckSum */
/* ------------------------------------------------------------------ */

static void test_metadata_checksum(tk_crypto_if *cr)
{
    /* Vecteur exact du depot officiel. Note : la personnalisation vaut
     * "testVIN" (7 octets) et non un VIN de 17 caracteres. */
    static const uint8_t epoch[16] = {
        0xaa, 0xda, 0x92, 0x8a, 0x4f, 0x21, 0x5f, 0x55,
        0xf9, 0xe6, 0xe4, 0x5e, 0x66, 0xb6, 0x52, 0x1e
    };
    static const uint8_t expected[TK_SHA256_LEN] = {
        0xab, 0xab, 0x04, 0xd8, 0x04, 0x49, 0x98, 0x13,
        0x38, 0x2e, 0xfd, 0x74, 0xa0, 0x67, 0x91, 0xce,
        0x2d, 0xe7, 0x77, 0x43, 0x96, 0x03, 0x24, 0x6d,
        0xfb, 0xaa, 0x83, 0x92, 0xca, 0x05, 0x86, 0x8e
    };
    uint8_t out[TK_SHA256_LEN];
    tk_meta m;

    begin("[TESLA] metadonnees : somme de controle SHA-256");

    CHECK(tk_meta_init_sha256(&m, cr) == TK_OK);
    CHECK(tk_meta_add_u8(&m, TK_TAG_SIGNATURE_TYPE, 0x05) == TK_OK);
    CHECK(tk_meta_add_u8(&m, TK_TAG_DOMAIN, 0x02) == TK_OK);
    CHECK(tk_meta_add(&m, TK_TAG_PERSONALIZATION,
                      (const uint8_t *)"testVIN", 7) == TK_OK);
    CHECK(tk_meta_add(&m, TK_TAG_EPOCH, epoch, sizeof(epoch)) == TK_OK);
    CHECK(tk_meta_add_u32(&m, TK_TAG_EXPIRES_AT, 0x00000e74) == TK_OK);
    CHECK(tk_meta_add_u32(&m, TK_TAG_COUNTER, 0x0000053a) == TK_OK);
    CHECK(tk_meta_checksum(&m, NULL, 0, out) == TK_OK);
    CHECK_MEM(out, expected, sizeof(expected));
}

/* Comportements imposes par metadata.go : ordre croissant, longueur max,
 * valeur absente omise. */
static void test_metadata_rules(tk_crypto_if *cr)
{
    uint8_t out[TK_SHA256_LEN];
    uint8_t out2[TK_SHA256_LEN];
    uint8_t big[256];
    tk_meta m;

    begin("metadonnees : regles d'ajout");

    /* Tag en ordre decroissant : refuse. */
    CHECK(tk_meta_init_sha256(&m, cr) == TK_OK);
    CHECK(tk_meta_add(&m, TK_TAG_PERSONALIZATION,
                      (const uint8_t *)"x", 1) == TK_OK);
    CHECK(tk_meta_add(&m, TK_TAG_DOMAIN, (const uint8_t *)"y", 1)
          == TK_ERR_STATE);
    (void)tk_meta_checksum(&m, NULL, 0, out);

    /* Valeur de plus de 255 octets : refusee. */
    memset(big, 0, sizeof(big));
    CHECK(tk_meta_init_sha256(&m, cr) == TK_OK);
    CHECK(tk_meta_add(&m, TK_TAG_DOMAIN, big, sizeof(big)) == TK_ERR_INVAL);
    (void)tk_meta_checksum(&m, NULL, 0, out);

    /* Un champ NULL est omis : le hachage doit etre celui d'une sequence
     * sans ce champ du tout. */
    CHECK(tk_meta_init_sha256(&m, cr) == TK_OK);
    CHECK(tk_meta_add_u8(&m, TK_TAG_SIGNATURE_TYPE, 0x05) == TK_OK);
    CHECK(tk_meta_add(&m, TK_TAG_DOMAIN, NULL, 0) == TK_OK);
    CHECK(tk_meta_checksum(&m, NULL, 0, out) == TK_OK);

    CHECK(tk_meta_init_sha256(&m, cr) == TK_OK);
    CHECK(tk_meta_add_u8(&m, TK_TAG_SIGNATURE_TYPE, 0x05) == TK_OK);
    CHECK(tk_meta_checksum(&m, NULL, 0, out2) == TK_OK);
    CHECK_MEM(out, out2, sizeof(out));
}

/* ------------------------------------------------------------------ */
/* [TESLA] ECDH et derivation de cle — ecdh_test.go/TestSharedKey       */
/* ------------------------------------------------------------------ */

static void test_shared_key(tk_crypto_if *cr)
{
    /* Valeurs choisies par Tesla pour que le secret partage commence par
     * un octet nul : elles verifient le completement a gauche. */
    static const uint8_t priv[TK_PRIVKEY_LEN] = {
        0x52, 0x60, 0xf8, 0xd6, 0x11, 0x38, 0x75, 0xd8,
        0x6f, 0x8e, 0xe8, 0xfe, 0xa3, 0x40, 0xdf, 0x1f,
        0xfb, 0x40, 0xc6, 0x58, 0xb5, 0x45, 0x5e, 0x8c,
        0x33, 0xd7, 0x97, 0xc5, 0x3a, 0x41, 0xaf, 0xd3
    };
    static const uint8_t peer_pub[TK_PUBKEY_LEN] = {
        0x04, 0x07, 0xfb, 0x60, 0xb6, 0x5b, 0x94, 0xe0,
        0xde, 0x4a, 0x95, 0x4c, 0x53, 0xbe, 0x10, 0x00,
        0x3d, 0x9e, 0x69, 0x91, 0x8d, 0xed, 0xfd, 0xa5,
        0xf4, 0xe9, 0xef, 0xb9, 0xeb, 0xd8, 0xc5, 0xbd,
        0x67, 0x2a, 0x53, 0x99, 0x1c, 0x40, 0x68, 0x86,
        0x5d, 0x5f, 0xb4, 0x4f, 0x97, 0xf6, 0xce, 0xcf,
        0x83, 0x98, 0xf2, 0x61, 0xdd, 0x1d, 0x7b, 0xc6,
        0x9b, 0xe6, 0x76, 0xaf, 0xdc, 0x8f, 0xfa, 0xcb,
        0xcc
    };
    static const uint8_t expected_shared[TK_PRIVKEY_LEN] = {
        0x00, 0x72, 0xd5, 0xb8, 0x15, 0x20, 0x7a, 0x04,
        0xf0, 0xc7, 0x95, 0xfb, 0xa0, 0xba, 0x9e, 0x8a,
        0xdd, 0x3f, 0x1f, 0x57, 0x14, 0x8c, 0x51, 0xff,
        0xac, 0xe2, 0x2c, 0xa1, 0x5e, 0x6f, 0xd8, 0x45
    };
    uint8_t shared[TK_PRIVKEY_LEN];
    uint8_t digest[TK_SHA1_LEN];
    uint8_t bad[TK_PUBKEY_LEN];

    begin("[TESLA] ECDH P-256 et derivation de la cle de session");

    CHECK(cr->p256_ecdh(cr->ctx, priv, peer_pub, shared) == 0);
    CHECK_MEM(shared, expected_shared, sizeof(expected_shared));

    /* key = SHA1(shared)[0..16] */
    CHECK(cr->sha1(cr->ctx, expected_shared, sizeof(expected_shared),
                   digest) == 0);
    {
        uint8_t key_from_ecdh[TK_SHA1_LEN];
        CHECK(cr->sha1(cr->ctx, shared, sizeof(shared), key_from_ecdh) == 0);
        CHECK_MEM(key_from_ecdh, digest, TK_SESSION_KEY_LEN);
    }

    /* Point hors courbe : doit etre refuse. */
    memcpy(bad, peer_pub, sizeof(bad));
    bad[1] ^= 1;
    CHECK(cr->p256_ecdh(cr->ctx, priv, bad, shared) != 0);

    /* Point a l'infini encode : doit etre refuse. */
    memset(bad, 0, sizeof(bad));
    bad[0] = 0x04;
    CHECK(cr->p256_ecdh(cr->ctx, priv, bad, shared) != 0);

    /* Cle privee nulle : doit etre refusee. */
    {
        uint8_t zero[TK_PRIVKEY_LEN];
        memset(zero, 0, sizeof(zero));
        CHECK(cr->p256_ecdh(cr->ctx, zero, peer_pub, shared) != 0);
    }
}

/* [TESLA] native_test.go/TestLocalPublicBytes */
static void test_public_from_private(tk_crypto_if *cr)
{
    static const uint8_t priv[TK_PRIVKEY_LEN] = {
        0x3e, 0x20, 0xd8, 0xf0, 0xb0, 0xca, 0xdd, 0xd0,
        0x97, 0x0a, 0xb3, 0x63, 0x42, 0xc5, 0xdc, 0x3f,
        0x0a, 0x3d, 0x56, 0x77, 0x88, 0x3c, 0xb2, 0x60,
        0xed, 0x6c, 0xeb, 0x3a, 0xed, 0x93, 0x20, 0xc4
    };
    static const uint8_t expected_pub[TK_PUBKEY_LEN] = {
        0x04, 0xc4, 0xff, 0x45, 0xb9, 0x68, 0xe8, 0x74,
        0x69, 0xaf, 0x64, 0x8e, 0xd3, 0x4c, 0x34, 0xa9,
        0x34, 0xd7, 0x4a, 0x1d, 0x76, 0xf2, 0x72, 0xd1,
        0x53, 0xfc, 0x81, 0x11, 0x4d, 0xdf, 0xec, 0xc1,
        0x78, 0xf6, 0x88, 0xe6, 0x2b, 0xec, 0x19, 0xc9,
        0xb1, 0x44, 0xe9, 0x41, 0x53, 0x61, 0xfa, 0x4f,
        0xec, 0xab, 0x5d, 0xed, 0x43, 0x36, 0x33, 0x6b,
        0x97, 0x51, 0xc9, 0xa7, 0x8f, 0xfa, 0x27, 0x0f,
        0xae
    };
    uint8_t pub[TK_PUBKEY_LEN];

    begin("[TESLA] cle publique P-256 derivee du scalaire prive");

    CHECK(cr->p256_public(cr->ctx, priv, pub) == 0);
    CHECK_MEM(pub, expected_pub, sizeof(expected_pub));
}

/* ------------------------------------------------------------------ */
/* HMAC-SHA256 — RFC 4231                                              */
/* ------------------------------------------------------------------ */

static void test_hmac_rfc4231(tk_crypto_if *cr)
{
    /* Cas de test 2 de la RFC 4231. Valide notre HMAC construit au-dessus
     * du SHA-256 du HAL. */
    static const uint8_t expected[TK_SHA256_LEN] = {
        0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e,
        0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xc7,
        0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83,
        0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec, 0x38, 0x43
    };
    uint8_t out[TK_SHA256_LEN];

    begin("HMAC-SHA256 (RFC 4231, cas 2)");

    CHECK(tk_hmac_sha256(cr, (const uint8_t *)"Jefe", 4,
                         (const uint8_t *)"what do ya want for nothing?", 28,
                         out) == TK_OK);
    CHECK_MEM(out, expected, sizeof(expected));

    /* Cas 3 : cle de 20 octets 0xaa, donnees = 50 x 0xdd. */
    {
        static const uint8_t exp3[TK_SHA256_LEN] = {
            0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46,
            0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81, 0xa7,
            0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22,
            0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5, 0x65, 0xfe
        };
        uint8_t key[20];
        uint8_t data[50];

        memset(key, 0xaa, sizeof(key));
        memset(data, 0xdd, sizeof(data));
        CHECK(tk_hmac_sha256(cr, key, sizeof(key), data, sizeof(data), out)
              == TK_OK);
        CHECK_MEM(out, exp3, sizeof(exp3));
    }

    /* Cas 6 : cle de 131 octets, plus longue que le bloc HMAC (64) : elle
     * doit d'abord etre hachee (RFC 2104). */
    {
        static const uint8_t exp6[TK_SHA256_LEN] = {
            0x60, 0xe4, 0x31, 0x59, 0x1e, 0xe0, 0xb6, 0x7f,
            0x0d, 0x8a, 0x26, 0xaa, 0xcb, 0xf5, 0xb7, 0x7f,
            0x8e, 0x0b, 0xc6, 0x21, 0x37, 0x28, 0xc5, 0x14,
            0x05, 0x46, 0x04, 0x0f, 0x0e, 0xe3, 0x7f, 0x54
        };
        uint8_t key[131];

        memset(key, 0xaa, sizeof(key));
        CHECK(tk_hmac_sha256(cr, key, sizeof(key),
                             (const uint8_t *)
                             "Test Using Larger Than Block-Size Key - "
                             "Hash Key First", 54, out) == TK_OK);
        CHECK_MEM(out, exp6, sizeof(exp6));
    }
}

/* ------------------------------------------------------------------ */
/* Codec protobuf                                                      */
/* ------------------------------------------------------------------ */

static void test_protobuf(void)
{
    uint8_t   buf[512];
    tk_pb_enc e;
    tk_pb_dec d;
    uint32_t  field;
    uint8_t   wire;
    int       len;

    begin("protobuf : encodage, varints, sous-messages");

    /* Encodage attendu, verifie a la main :
     *   champ 1 varint 300  -> 0x08 0xac 0x02
     *   champ 2 bytes "hi"  -> 0x12 0x02 'h' 'i'
     *   champ 3 fixed32 1   -> 0x1d 0x01 0x00 0x00 0x00  (little-endian) */
    {
        static const uint8_t expected[] = {
            0x08, 0xac, 0x02,
            0x12, 0x02, 'h', 'i',
            0x1d, 0x01, 0x00, 0x00, 0x00
        };
        tk_pb_enc_init(&e, buf, sizeof(buf));
        CHECK(tk_pb_varint(&e, 1, 300) == TK_OK);
        CHECK(tk_pb_bytes(&e, 2, (const uint8_t *)"hi", 2) == TK_OK);
        CHECK(tk_pb_fixed32(&e, 3, 1) == TK_OK);
        len = tk_pb_enc_finish(&e);
        CHECK(len == (int)sizeof(expected));
        CHECK_MEM(buf, expected, sizeof(expected));
    }

    /* Un champ varint a zero est omis par tk_pb_varint_opt (proto3). */
    tk_pb_enc_init(&e, buf, sizeof(buf));
    CHECK(tk_pb_varint_opt(&e, 52, 0) == TK_OK);
    CHECK(tk_pb_enc_finish(&e) == 0);

    /* Sous-message dont le corps depasse 127 octets : la longueur passe a
     * deux octets de varint et le corps doit etre decale correctement. */
    {
        uint8_t payload[200];
        size_t  m;

        memset(payload, 0x5a, sizeof(payload));
        tk_pb_enc_init(&e, buf, sizeof(buf));
        m = tk_pb_sub_begin(&e, 6);
        CHECK(tk_pb_bytes(&e, 1, payload, sizeof(payload)) == TK_OK);
        CHECK(tk_pb_sub_end(&e, m) == TK_OK);
        len = tk_pb_enc_finish(&e);
        CHECK(len > 0);

        /* Relecture : champ 6, longueur 203 (tag+len+200). */
        tk_pb_dec_init(&d, buf, (size_t)len);
        CHECK(tk_pb_dec_next(&d, &field, &wire) == 1);
        CHECK(field == 6);
        CHECK(wire == TK_WIRE_BYTES);
        {
            const uint8_t *sub;
            size_t         sub_len;
            CHECK(tk_pb_dec_bytes(&d, &sub, &sub_len) == TK_OK);
            CHECK(sub_len == 203);
            /* Et le contenu imbrique est intact. */
            tk_pb_dec_init(&d, sub, sub_len);
            CHECK(tk_pb_dec_next(&d, &field, &wire) == 1);
            CHECK(field == 1);
            CHECK(tk_pb_dec_bytes(&d, &sub, &sub_len) == TK_OK);
            CHECK(sub_len == sizeof(payload));
            CHECK_MEM(sub, payload, sizeof(payload));
        }
    }

    /* Tampon trop petit : erreur collante, pas de debordement. */
    {
        uint8_t tiny[4];
        tk_pb_enc_init(&e, tiny, sizeof(tiny));
        (void)tk_pb_bytes(&e, 1, (const uint8_t *)"abcdefgh", 8);
        CHECK(tk_pb_enc_finish(&e) == TK_ERR_NOMEM);
    }

    /* Message tronque : detecte, pas de lecture hors limites. */
    {
        static const uint8_t truncated[] = { 0x12, 0x08, 'a', 'b' };
        const uint8_t       *p;
        size_t               n;

        tk_pb_dec_init(&d, truncated, sizeof(truncated));
        CHECK(tk_pb_dec_next(&d, &field, &wire) == 1);
        CHECK(tk_pb_dec_bytes(&d, &p, &n) == TK_ERR_TRUNCATED);
    }

    /* Champ de numero 0 : invalide. */
    {
        static const uint8_t bad[] = { 0x00, 0x01 };
        tk_pb_dec_init(&d, bad, sizeof(bad));
        CHECK(tk_pb_dec_next(&d, &field, &wire) == TK_ERR_DECODE);
    }
}

/* ------------------------------------------------------------------ */
/* Encodage VCSEC                                                      */
/* ------------------------------------------------------------------ */

static void test_vcsec_encoding(void)
{
    uint8_t buf[256];
    int     len;

    begin("VCSEC : encodage des commandes");

    /* RKE_ACTION_UNLOCK vaut 0. Le champ DOIT etre emis explicitement,
     * sinon le oneof reste vide et le vehicule ne voit aucune commande.
     * Encodage attendu : champ 2, varint 0 -> 0x10 0x00 */
    len = tk_vcsec_encode_rke(buf, sizeof(buf), TK_RKE_UNLOCK);
    CHECK(len == 2);
    CHECK(buf[0] == 0x10);
    CHECK(buf[1] == 0x00);

    /* REMOTE_DRIVE = 20 -> 0x10 0x14 */
    len = tk_vcsec_encode_rke(buf, sizeof(buf), TK_RKE_REMOTE_DRIVE);
    CHECK(len == 2);
    CHECK(buf[0] == 0x10);
    CHECK(buf[1] == 0x14);

    /* GET_STATUS = 0 dans un sous-message : le sous-message doit exister.
     * UnsignedMessage.InformationRequest = 1 { type = 1 : varint 0 }
     *   -> 0x0a 0x02 0x08 0x00 */
    len = tk_vcsec_encode_info_request(buf, sizeof(buf), 0);
    CHECK(len == 4);
    {
        static const uint8_t expected[] = { 0x0a, 0x02, 0x08, 0x00 };
        CHECK_MEM(buf, expected, sizeof(expected));
    }

    /* Enrolement : doit contenir la cle publique et le type PRESENT_KEY. */
    {
        uint8_t pub[TK_PUBKEY_LEN];
        memset(pub, 0xa5, sizeof(pub));
        pub[0] = 0x04;
        len = tk_vcsec_encode_add_key(buf, sizeof(buf), pub,
                                      TK_ROLE_DRIVER,
                                      TK_FORM_FACTOR_ANDROID_DEVICE);
        CHECK(len > TK_PUBKEY_LEN);
        /* La cle publique apparait telle quelle dans le message. */
        {
            int found = 0;
            int i;
            for (i = 0; i + TK_PUBKEY_LEN <= len; i++) {
                if (memcmp(buf + i, pub, TK_PUBKEY_LEN) == 0) {
                    found = 1;
                    break;
                }
            }
            CHECK(found);
        }
    }

    /* Tampon insuffisant : erreur, pas de debordement. */
    {
        uint8_t tiny[3];
        uint8_t pub[TK_PUBKEY_LEN];
        memset(pub, 0x04, sizeof(pub));
        CHECK(tk_vcsec_encode_add_key(tiny, sizeof(tiny), pub,
                                      TK_ROLE_DRIVER, 7) < 0);
    }
}

/* ------------------------------------------------------------------ */
/* Framing BLE                                                         */
/* ------------------------------------------------------------------ */

static uint8_t  g_rx_msg[TK_MAX_MESSAGE_LEN];
static size_t   g_rx_len;
static int      g_rx_count;

static void frame_cb(void *user, const uint8_t *msg, size_t len)
{
    (void)user;
    g_rx_count++;
    g_rx_len = len;
    if (len <= sizeof(g_rx_msg)) {
        memcpy(g_rx_msg, msg, len);
    }
}

static uint8_t g_tx_buf[4096];
static size_t  g_tx_len;
static size_t  g_tx_blocks;
static size_t  g_tx_max_block;

static int frame_write(void *user, const uint8_t *data, size_t len)
{
    (void)user;
    if (g_tx_len + len > sizeof(g_tx_buf)) {
        return TK_ERR_NOMEM;
    }
    memcpy(g_tx_buf + g_tx_len, data, len);
    g_tx_len += len;
    g_tx_blocks++;
    if (len > g_tx_max_block) {
        g_tx_max_block = len;
    }
    return TK_OK;
}

static void test_framing(void)
{
    tk_frame_rx r;
    uint8_t     msg[300];
    size_t      i;

    begin("framing BLE : decoupage et reassemblage");

    for (i = 0; i < sizeof(msg); i++) {
        msg[i] = (uint8_t)(i & 0xFF);
    }

    /* Emission avec un MTU de 23 (bloc utile de 20 octets). */
    g_tx_len = 0; g_tx_blocks = 0; g_tx_max_block = 0;
    CHECK(tk_frame_send(msg, sizeof(msg), 20, frame_write, NULL) == TK_OK);
    CHECK(g_tx_len == sizeof(msg) + 2);
    CHECK(g_tx_max_block == 20);
    /* Prefixe de longueur big-endian. */
    CHECK(g_tx_buf[0] == (uint8_t)(sizeof(msg) >> 8));
    CHECK(g_tx_buf[1] == (uint8_t)(sizeof(msg) & 0xFF));
    CHECK_MEM(g_tx_buf + 2, msg, sizeof(msg));

    /* Reassemblage du flux emis, injecte octet par octet : le cas le plus
     * defavorable pour la detection des frontieres. */
    tk_frame_rx_init(&r, frame_cb, NULL);
    g_rx_count = 0;
    for (i = 0; i < g_tx_len; i++) {
        CHECK(tk_frame_rx_feed(&r, g_tx_buf + i, 1, 1000) == TK_OK);
    }
    CHECK(g_rx_count == 1);
    CHECK(g_rx_len == sizeof(msg));
    CHECK_MEM(g_rx_msg, msg, sizeof(msg));

    /* Deux messages dans la meme rafale doivent etre remis tous les deux. */
    {
        uint8_t stream[2 * (2 + 4)];
        static const uint8_t a[4] = { 1, 2, 3, 4 };
        static const uint8_t b[4] = { 5, 6, 7, 8 };

        stream[0] = 0; stream[1] = 4; memcpy(stream + 2, a, 4);
        stream[6] = 0; stream[7] = 4; memcpy(stream + 8, b, 4);

        tk_frame_rx_init(&r, frame_cb, NULL);
        g_rx_count = 0;
        CHECK(tk_frame_rx_feed(&r, stream, sizeof(stream), 1000) == TK_OK);
        CHECK(g_rx_count == 2);
        CHECK_MEM(g_rx_msg, b, 4);   /* le dernier remis */
    }

    /* Un silence superieur au delai de reassemblage purge le tampon :
     * le fragment orphelin ne doit pas se recoller au suivant. */
    {
        uint8_t partial[3] = { 0, 4, 0xFF };
        uint8_t complete[6] = { 0, 4, 1, 2, 3, 4 };

        tk_frame_rx_init(&r, frame_cb, NULL);
        g_rx_count = 0;
        CHECK(tk_frame_rx_feed(&r, partial, sizeof(partial), 1000) == TK_OK);
        CHECK(g_rx_count == 0);
        /* 1001 ms plus tard : le tampon est purge. */
        CHECK(tk_frame_rx_feed(&r, complete, sizeof(complete),
                               1000 + TK_RX_REASSEMBLY_MS + 1) == TK_OK);
        CHECK(g_rx_count == 1);
        CHECK(g_rx_len == 4);
    }

    /* Longueur annoncee superieure a la limite : rejet et purge. */
    {
        uint8_t bogus[2] = { 0xFF, 0xFF };

        tk_frame_rx_init(&r, frame_cb, NULL);
        g_rx_count = 0;
        CHECK(tk_frame_rx_feed(&r, bogus, sizeof(bogus), 1000)
              == TK_ERR_DECODE);
        CHECK(g_rx_count == 0);
    }

    /* Message vide : accepte, remis avec une longueur de zero. */
    {
        uint8_t empty[2] = { 0, 0 };

        tk_frame_rx_init(&r, frame_cb, NULL);
        g_rx_count = 0;
        CHECK(tk_frame_rx_feed(&r, empty, sizeof(empty), 1000) == TK_OK);
        CHECK(g_rx_count == 1);
        CHECK(g_rx_len == 0);
    }
}

/* ------------------------------------------------------------------ */
/* Fenetre anti-rejeu                                                  */
/* ------------------------------------------------------------------ */

static void test_replay_window(void)
{
    tk_replay_window w;

    begin("fenetre anti-rejeu");

    memset(&w, 0, sizeof(w));
    CHECK(tk_replay_update(&w, 100) == 1);   /* premiere valeur : acceptee */
    CHECK(tk_replay_update(&w, 100) == 0);   /* rejouee */
    CHECK(tk_replay_update(&w, 101) == 1);
    CHECK(tk_replay_update(&w, 105) == 1);
    CHECK(tk_replay_update(&w, 103) == 1);   /* desordre dans la fenetre */
    CHECK(tk_replay_update(&w, 103) == 0);   /* rejouee */
    CHECK(tk_replay_update(&w, 101) == 0);   /* rejouee */
    CHECK(tk_replay_update(&w, 105) == 0);   /* egale au maximum courant */

    /* Au-dela de la fenetre de 32, on ne peut plus trancher : refus. */
    CHECK(tk_replay_update(&w, 105 - 33) == 0);
    CHECK(tk_replay_update(&w, 105 - 32) == 1);

    /* Saut enorme : la fenetre est entierement renouvelee, sans
     * comportement indefini sur le decalage. */
    memset(&w, 0, sizeof(w));
    CHECK(tk_replay_update(&w, 1) == 1);
    CHECK(tk_replay_update(&w, 1000000) == 1);
    CHECK(tk_replay_update(&w, 1000000) == 0);
    CHECK(tk_replay_update(&w, 1) == 0);
    CHECK(tk_replay_update(&w, 999999) == 1);

    /* Decalage de exactement 64 puis de 65. */
    memset(&w, 0, sizeof(w));
    CHECK(tk_replay_update(&w, 0) == 1);
    CHECK(tk_replay_update(&w, 64) == 1);
    CHECK(tk_replay_update(&w, 64 + 65) == 1);
}

/* ------------------------------------------------------------------ */
/* Nom local BLE                                                       */
/* ------------------------------------------------------------------ */

static void test_local_name(tk_crypto_if *cr)
{
    /* Valeurs de reference calculees independamment, hors de ce code :
     *   printf '<vin>' | openssl dgst -sha1
     * puis "S" + les 16 premiers chiffres hexadecimaux + "C".
     *
     * Le second cas est le vehicule reellement cible ; il verifie aussi
     * qu'un changement de VIN recalcule bien le nom. A remplacer par un
     * VIN d'exemple si ce depot doit etre publie. */
    static const struct {
        const char *vin;
        const char *expected;
    } cases[] = {
        { "5YJ3E1EA7JF000000", "S57bfc47617573c4eC" },
        { "5YJSA1E26HF000001", "Sb3f019d29bb66cacC" },
    };

    tk_client    c;
    tk_hal       hal;
    char         name[TK_LOCAL_NAME_LEN + 1];
    size_t       i;

    begin("nom local BLE derive du VIN");

    memset(&hal, 0, sizeof(hal));
    hal.crypto = *cr;
    hal_host_time(&hal.time);
    hal_host_store(&hal.store);
    /* Un transport factice suffit : tk_client_init valide seulement que
     * les pointeurs existent. */
    hal.ble.scan_start = (int (*)(void *, const char *, uint32_t))(void *)1;
    hal.ble.connect    = (int (*)(void *, const tk_ble_peer *))(void *)1;
    hal.ble.write      = (int (*)(void *, const uint8_t *, size_t))(void *)1;
    hal.ble.mtu        = (size_t (*)(void *))(void *)1;

    CHECK(tk_client_init(&c, &hal, NULL, NULL) == TK_OK);

    for (i = 0; i < sizeof(cases) / sizeof(cases[0]); i++) {
        CHECK(tk_client_set_vin(&c, cases[i].vin) == TK_OK);
        CHECK(tk_client_local_name(&c, name, sizeof(name)) == TK_OK);
        CHECK(strlen(name) == TK_LOCAL_NAME_LEN);
        CHECK(strcmp(name, cases[i].expected) == 0);
        if (strcmp(name, cases[i].expected) != 0) {
            printf("    %s\n      obtenu  : %s\n      attendu : %s\n",
                   cases[i].vin, name, cases[i].expected);
        }
    }

    /* VIN de longueur incorrecte : refuse. */
    CHECK(tk_client_set_vin(&c, "TROPCOURT") == TK_ERR_INVAL);
    CHECK(tk_client_set_vin(&c, "5YJ3E1EA7JF0000000") == TK_ERR_INVAL);
}

/* ------------------------------------------------------------------ */
/* Aller-retour RoutableMessage                                        */
/* ------------------------------------------------------------------ */

static void test_routable_roundtrip(void)
{
    uint8_t    buf[TK_TX_BUF_LEN];
    uint8_t    pub[TK_PUBKEY_LEN];
    uint8_t    epoch[TK_EPOCH_LEN];
    uint8_t    addr[TK_ROUTING_ADDR_LEN];
    uint8_t    uuid[TK_UUID_LEN];
    uint8_t    ct[8];
    tk_gcm_sig sig;
    tk_msg_rx  rx;
    int        len;

    begin("RoutableMessage : encodage puis relecture");

    memset(pub, 0x11, sizeof(pub));   pub[0] = 0x04;
    memset(epoch, 0x22, sizeof(epoch));
    memset(addr, 0x33, sizeof(addr));
    memset(uuid, 0x44, sizeof(uuid));
    memset(ct, 0x55, sizeof(ct));
    memset(&sig, 0, sizeof(sig));
    memset(sig.nonce, 0x66, sizeof(sig.nonce));
    memset(sig.tag, 0x77, sizeof(sig.tag));
    sig.counter    = 0x0000053a;
    sig.expires_at = 0x00000e74;

    /* Requete de session. */
    len = tk_msg_encode_session_request(buf, sizeof(buf),
                                        TK_DOMAIN_VEHICLE_SECURITY,
                                        addr, uuid, pub);
    CHECK(len > 0);
    CHECK(tk_msg_decode(buf, (size_t)len, &rx) == TK_OK);
    CHECK(rx.has_to_domain);
    CHECK(rx.to_domain == TK_DOMAIN_VEHICLE_SECURITY);
    CHECK(rx.session_info == NULL);

    /* Commande signee. */
    len = tk_msg_encode_signed(buf, sizeof(buf), TK_DOMAIN_VEHICLE_SECURITY,
                               addr, uuid, pub, epoch, &sig,
                               ct, sizeof(ct), 0);
    CHECK(len > 0);
    CHECK(len < TK_TX_BUF_LEN);
    CHECK(tk_msg_decode(buf, (size_t)len, &rx) == TK_OK);
    CHECK(rx.has_to_domain);
    CHECK(rx.to_domain == TK_DOMAIN_VEHICLE_SECURITY);
    CHECK(rx.payload_len == sizeof(ct));
    CHECK_MEM(rx.payload, ct, sizeof(ct));
    CHECK(rx.flags == 0);

    /* Un tampon trop court doit produire une erreur, jamais un
     * depassement. */
    {
        uint8_t small[32];
        CHECK(tk_msg_encode_signed(small, sizeof(small),
                                   TK_DOMAIN_VEHICLE_SECURITY,
                                   addr, uuid, pub, epoch, &sig,
                                   ct, sizeof(ct), 0) == TK_ERR_NOMEM);
    }
}

/* ------------------------------------------------------------------ */

int tk_run_loopback_tests(tk_crypto_if *cr, int *checks, int *fails);

#ifdef TK_TEST_MBEDTLS
#include "tk_crypto_mbedtls.h"
int tk_test_gcm_interop(tk_crypto_if *a, tk_crypto_if *b,
                        int *checks, int *fails);
#endif

int main(void)
{
    tk_crypto_if cr;
    int          lb_checks = 0;
    int          lb_fails  = 0;

    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    hal_host_crypto(&cr);
    hal_host_store_reset();

    printf("teslakey — tests du coeur\n\n");

    test_metadata_checksum(&cr);
    test_metadata_rules(&cr);
    test_shared_key(&cr);
    test_public_from_private(&cr);
    test_hmac_rfc4231(&cr);
    test_protobuf();
    test_vcsec_encoding();
    test_framing();
    test_replay_window();
    test_local_name(&cr);
    test_routable_roundtrip();

    (void)tk_run_loopback_tests(&cr, &lb_checks, &lb_fails);
    g_checks += lb_checks;
    g_fail   += lb_fails;

#ifdef TK_TEST_MBEDTLS
    /* Le module crypto partage par les cibles ESP32 et nRF doit passer
     * exactement les memes vecteurs officiels que la reference OpenSSL,
     * et s'accorder bit a bit avec elle. */
    {
        tk_crypto_if mb;
        int          ic = 0;
        int          if_ = 0;

        printf("\n-- backend mbedTLS (partage ESP32 / nRF) --\n");
        tk_crypto_mbedtls(&mb);

        test_metadata_checksum(&mb);
        test_shared_key(&mb);
        test_public_from_private(&mb);
        test_hmac_rfc4231(&mb);

        begin("mbedTLS : interoperabilite AES-GCM et ECDH avec OpenSSL");
        (void)tk_test_gcm_interop(&cr, &mb, &ic, &if_);
        g_checks += ic;
        g_fail   += if_;

        /* Et toute la machine a etats doit tourner sur ce backend. */
        printf("\n-- boucle complete sur backend mbedTLS --\n");
        ic = 0; if_ = 0;
        (void)tk_run_loopback_tests(&mb, &ic, &if_);
        g_checks += ic;
        g_fail   += if_;
    }
#endif

    printf("\n%d verifications, %d echec(s)\n", g_checks, g_fail);
    if (g_test == NULL) {
        return 1;
    }
    return g_fail == 0 ? 0 : 1;
}
