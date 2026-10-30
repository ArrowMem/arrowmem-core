/* arrowmem-core C surface. Written by hand from src/ffi.rs; the test
 * tests/c_header.rs fails if a function or a constant here drifts from it.
 *
 * Every call returns AM_OK (0) or a negative code. Pointers are checked
 * before anything is read; output goes only into buffers you own; on
 * AM_TOO_SMALL, *out_len holds the size needed and nothing else is written.
 * Handles are tickets, not pointers: a stale or freed one is AM_BAD_ARG. */
#ifndef ARROWMEM_H
#define ARROWMEM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define AM_OK 0
#define AM_INTERNAL (-1)     /* a caught panic; the handle is now poisoned */
#define AM_BUSY (-2)         /* another call on this handle is running */
#define AM_BAD_ARG (-3)      /* null pointer, bad length, or overlapping buffers */
#define AM_TOO_SMALL (-4)    /* output buffer too small; *out_len holds the need */
#define AM_NO_KEY (-5)       /* no sealing key loaded */
#define AM_BAD_FRAGMENT (-6) /* a radio fragment that is not well formed; drop it */
#define AM_ERROR_BASE (-100) /* crate errors: -100 minus the variant position */

#define AM_OBJECT_SIZE 1114 /* every sealed object, exactly */
#define AM_MAX_BODY 885     /* largest body am_seal takes, kind byte included */

/* First body byte, chosen by the sender. */
#define AM_KIND_MESSAGE 0x01
#define AM_KIND_INVITE 0x02
#define AM_KIND_INTRO 0x03
#define AM_KIND_REQUEST 0x04

typedef uint64_t AmId;
typedef uint64_t AmReasm;

/* Hardware signing: sign msg, write the signature to sig_out, set *sig_len,
 * set *format to 0 for raw r||s or 1 for DER. Return 0 on success. Never
 * convert the hardware's signature by hand; report its format. */
typedef int32_t (*AmSignCb)(void *ctx, const uint8_t *msg, size_t msg_len, uint8_t *sig_out, size_t sig_cap, size_t *sig_len, uint8_t *format);

int32_t am_new(AmId *out);
int32_t am_free(AmId id);
int32_t am_set_seal_key(AmId id, const uint8_t *sk32, const uint8_t *pk65);
int32_t am_load(AmId id, const uint8_t *p, size_t len);
/* Output is PLAINTEXT: encrypt it at rest, then wipe the buffer. */
int32_t am_save(AmId id, uint8_t *out, size_t cap, size_t *out_len);
/* Call am_save and store it durably BEFORE sending the object. */
int32_t am_seal(AmId id, const uint8_t *recipient65, const uint8_t *body, size_t body_len, const uint8_t *signer_pub33, AmSignCb cb, void *ctx, uint64_t *counter_out, uint8_t *out, size_t cap, size_t *out_len);
/* *kind: 1 message, 2 new contact, 3 request waiting. On any error, drop the
 * object silently and never reply. */
int32_t am_admit(AmId id, const uint8_t *obj, size_t obj_len, uint8_t *kind, uint8_t *from33, uint64_t *counter, uint8_t *out, size_t cap, size_t *out_len);
int32_t am_accept(AmId id, const uint8_t *key33);
int32_t am_decline(AmId id, const uint8_t *key33);
int32_t am_block(AmId id, const uint8_t *key33);
int32_t am_remove(AmId id, const uint8_t *key33);
int32_t am_was_removed(AmId id, const uint8_t *key33, uint8_t *out);
/* 16 secret bytes for the QR code. */
int32_t am_new_invite(AmId id, uint8_t *out16);

/* Radio links with small messages (BLE: mtu = ATT MTU less 3). */
int32_t am_fragment_count(size_t mtu, size_t *count_out);
int32_t am_fragment(const uint8_t *object, size_t object_len, size_t mtu, uint16_t frag_id, size_t index, uint8_t *out, size_t cap, size_t *out_len);
/* A fresh random frag_id per object. */
int32_t am_fragment_id(uint16_t *out);
/* One reassembler per radio link. */
int32_t am_reasm_new(AmReasm *out);
int32_t am_reasm_free(AmReasm id);
/* cap >= AM_OBJECT_SIZE always; *out_len 0 means not whole yet. */
int32_t am_reasm_push(AmReasm id, const uint8_t *frag, size_t frag_len, uint8_t *out, size_t cap, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif
