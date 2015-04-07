/* ====================================================================
 * Copyright (c) 2001-2014 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 */

#include <openssl/opensslconf.h>
#ifndef OPENSSL_NO_CHACHA_POLY
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/chacha20poly1305.h>
#include "evp_locl.h"
#include <openssl/rand.h>

typedef struct
	{
	uint8_t key[32];
	/* uint8_t salt[4] */;
	uint8_t nonce[8];
	poly1305_state poly_state;
	size_t aad_l;
	size_t ct_l;
	int valid;
#ifdef CHAPOLY_x86_64_ASM
	void (*poly1305_init_ptr)(poly1305_state *, const uint8_t *);
	void (*poly1305_update_ptr)(poly1305_state *, const uint8_t *, size_t);
	void (*poly1305_finish_ptr)(poly1305_state *, uint8_t *);
	#define poly_init aead_ctx->poly1305_init_ptr
	#define poly_update poly1305_update_wrapper
	#define poly_finish poly1305_finish_wrapper
	#define FILL_BUFFER ((size_t)128)
	uint8_t poly_buffer[FILL_BUFFER];
	uint8_t chacha_buffer[FILL_BUFFER];
	uint8_t poly_buffer_used;
	uint8_t chacha_used;
#else
	#define poly_init CRYPTO_poly1305_init
	#define poly_update(c,i,l) CRYPTO_poly1305_update(&c->poly_state,i,l)
	#define poly_finish(c,m) CRYPTO_poly1305_finish(&c->poly_state,m)
#endif
	} EVP_CHACHA20_POLY1305_CTX;

#ifdef CHAPOLY_x86_64_ASM
static void poly1305_update_wrapper(EVP_CHACHA20_POLY1305_CTX *ctx, const uint8_t *in, size_t in_len)
	{
	int todo;
	/* Attempt to fill as many bytes as possible before calling the update function */
	if(in_len < FILL_BUFFER || ctx->poly_buffer_used)
		{
		todo = FILL_BUFFER - ctx->poly_buffer_used;
		todo = in_len < todo? in_len : todo;
		memcpy(ctx->poly_buffer + ctx->poly_buffer_used, in, todo);
		ctx->poly_buffer_used += todo;
		in += todo;
		in_len -= todo;
		if(ctx->poly_buffer_used == FILL_BUFFER)
			{
			ctx->poly1305_update_ptr(&ctx->poly_state, ctx->poly_buffer, FILL_BUFFER);
			ctx->poly_buffer_used = 0;
			}
		}
	if(in_len >= FILL_BUFFER)
		{
		ctx->poly1305_update_ptr(&ctx->poly_state, in, in_len&(-FILL_BUFFER));
		in += in_len&(-FILL_BUFFER);
		in_len &= (FILL_BUFFER-1);
		}
	if(in_len)
		{
		memcpy(ctx->poly_buffer, in, in_len);
		ctx->poly_buffer_used = in_len;
		}
	}

static void poly1305_finish_wrapper(EVP_CHACHA20_POLY1305_CTX *ctx, uint8_t mac[16])
	{
	if(ctx->poly_buffer_used)
		{
                if(ctx->poly_buffer_used % 16)
			{
			memset(ctx->poly_buffer + ctx->poly_buffer_used, 0, 16 - (ctx->poly_buffer_used%16));
			}
		ctx->poly1305_update_ptr(&ctx->poly_state, ctx->poly_buffer, ctx->poly_buffer_used);
		}
	ctx->poly1305_finish_ptr(&ctx->poly_state, mac);
	memset(ctx->poly_buffer, 0 ,FILL_BUFFER);
	}
#endif

static int EVP_chacha20_poly1305_init(EVP_CIPHER_CTX *ctx, const unsigned char *key, const unsigned char *iv, int enc)
	{
	EVP_CHACHA20_POLY1305_CTX *aead_ctx = ctx->cipher_data;
	/* simply copy the chacha key and iv*/
	memcpy(aead_ctx->key, key, 32);
	/* memcpy(aead_ctx->salt, iv, 4); */
	aead_ctx->valid = 0;
	return 1;
	}
	
static int EVP_chacha20_poly1305_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t inl)
	{
	EVP_CHACHA20_POLY1305_CTX *aead_ctx = ctx->cipher_data;
	uint8_t poly_block[16];
	uint64_t cl;
	if(!aead_ctx->valid)
		return 0;
	/* Fix for MAC */
	inl -= 16;
	/* Encryption */
	if(ctx->encrypt)
		{
#ifdef FILL_BUFFER
		/* we can use the buffer we already accumulated during the parallel computation in init */
		if(inl<=FILL_BUFFER-64)
			{
			int i;
			for(i=0; i<inl; i++)
				out[i] = in[i] ^ aead_ctx->chacha_buffer[i+64];
			}
		else
#endif
		CRYPTO_chacha_20(out, in, inl, aead_ctx->key, aead_ctx->nonce, 1);
		poly_update(aead_ctx, out, inl);
		aead_ctx->ct_l += inl;
		cl = aead_ctx->ct_l;
		poly_update(aead_ctx, (uint8_t*)&cl, sizeof(cl));
		poly_finish(aead_ctx, &out[inl]);
		aead_ctx->valid = 0;
		return inl+16;
		}
	/* Decryption */
	else
		{
		/* Fix to accommodate for the MAC */
		poly_update(aead_ctx, in, inl);
#ifdef FILL_BUFFER
		/* we can use the buffer we already accumulated during the parallel computation in init */
		if(inl<=FILL_BUFFER-64)
			{
			int i;
			for(i=0; i<inl; i++)
				out[i] = in[i] ^ aead_ctx->chacha_buffer[i+64];
			}
		else
#endif
		CRYPTO_chacha_20(out, in, inl, aead_ctx->key, aead_ctx->nonce, 1);
		aead_ctx->ct_l += inl;
		cl = aead_ctx->ct_l;
		poly_update(aead_ctx, (uint8_t*)&cl, sizeof(cl));
		poly_finish(aead_ctx, poly_block);
	
                uint64_t cmp = ((uint64_t*)poly_block)[0] ^ ((uint64_t*)(in + inl))[0];
                cmp |= ((uint64_t*)poly_block)[1] ^ ((uint64_t*)(in + inl))[1];

		/*if (memcmp(poly_block, in + inl, POLY1305_MAC_LEN)) */
		if (cmp)
			{
			OPENSSL_cleanse(out, inl);
			aead_ctx->valid = 0;
			return -1;
			}
		aead_ctx->valid = 0;
		return inl;
		}
	return 0;
	}
	
static int EVP_chacha20_poly1305_cleanup(EVP_CIPHER_CTX *ctx)
	{
	return 1;
	}

static int EVP_chacha20_poly1305_ctrl(EVP_CIPHER_CTX *ctx, int type, int arg, void *ptr)
	{
	EVP_CHACHA20_POLY1305_CTX *aead_ctx = ctx->cipher_data;
#ifndef FILL_BUFFER
	uint8_t poly1305_key[32];
#endif
	uint8_t aad[13 + 8];
        uint64_t thirteen = 13;
	
	switch(type)
		{
		case EVP_CTRL_AEAD_TLS1_AAD:
			if(arg!=13) 
				return 0;
			/* Initialize poly keys */
#ifndef FILL_BUFFER
			memset(poly1305_key, 0, sizeof(poly1305_key));
#else
			memset(aead_ctx->chacha_buffer, 0, FILL_BUFFER);
#endif
			/* Salt is the IV (not in draft) */
			/* memcpy(aead_ctx->nonce, aead_ctx->salt, 4); */
			/* Take sequence number from AAD */
			/* memcpy(&aead_ctx->nonce[4], ptr, 8); */
			memcpy(aead_ctx->nonce, ptr, 8);

#ifdef CHAPOLY_x86_64_ASM
			aead_ctx->poly_buffer_used = 0;
			if((OPENSSL_ia32cap_loc()[1] >> 5) & 1) /* AVX2 */
				{
				aead_ctx->poly1305_init_ptr = poly1305_init_avx2;
				aead_ctx->poly1305_update_ptr = poly1305_update_avx2;
				aead_ctx->poly1305_finish_ptr = poly1305_finish_avx2;	
				}
			else if ((OPENSSL_ia32cap_loc()[0] >> 60) & 1) /* AVX */
				{
				aead_ctx->poly1305_init_ptr = poly1305_init_avx;
				aead_ctx->poly1305_update_ptr = poly1305_update_avx;
				aead_ctx->poly1305_finish_ptr = poly1305_finish_avx;	
				}
			else						/*C*/
				{
				aead_ctx->poly1305_init_ptr = CRYPTO_poly1305_init;
				aead_ctx->poly1305_update_ptr = CRYPTO_poly1305_update;
				aead_ctx->poly1305_finish_ptr = CRYPTO_poly1305_finish;
				}

#endif
#ifndef FILL_BUFFER
			CRYPTO_chacha_20(poly1305_key, poly1305_key, sizeof(poly1305_key), aead_ctx->key, aead_ctx->nonce, 0);
			poly_init(&aead_ctx->poly_state, poly1305_key);
#else
			CRYPTO_chacha_20(aead_ctx->chacha_buffer, aead_ctx->chacha_buffer, FILL_BUFFER, aead_ctx->key, aead_ctx->nonce, 0);
			poly_init(&aead_ctx->poly_state, aead_ctx->chacha_buffer);
			aead_ctx->chacha_used = 64;	/* We keep 64 byte for future use, to accelerate for very short messages */
#endif
			aead_ctx->aad_l = 0;
			aead_ctx->ct_l = 0;
			/* Absorb AAD */
			memcpy(aad, ptr, arg);
                        memcpy(&aad[arg], &thirteen, sizeof(thirteen));
			/* If decrypting fix length for tag */
			if (!ctx->encrypt)
				{
				unsigned int len=aad[arg-2]<<8|aad[arg-1];
				len -= POLY1305_MAC_LEN;
				aad[arg-2] = len>>8;
				aad[arg-1] = len & 0xff;
				}
			poly_update(aead_ctx, aad, arg + sizeof(thirteen));
			/* aead_ctx->aad_l += arg; */
			aead_ctx->valid = 1;
			return POLY1305_MAC_LEN;
			break;
		default:
			return 0;
			break;
		}
	return 0;
	}
	
#define CUSTOM_FLAGS	(\
		  EVP_CIPH_CUSTOM_IV | EVP_CIPH_FLAG_CUSTOM_CIPHER \
		| EVP_CIPH_ALWAYS_CALL_INIT  \
		| EVP_CIPH_CUSTOM_COPY)
		
static const EVP_CIPHER chacha20_poly1305 = {
	0,	/* nid ??? */
	1,	/* block size, sorta */
	32,	/* key len */
	0,	/* iv len */
	CUSTOM_FLAGS|EVP_CIPH_FLAG_AEAD_CIPHER,	/* flags */
	EVP_chacha20_poly1305_init,
	EVP_chacha20_poly1305_cipher,
	EVP_chacha20_poly1305_cleanup,
	sizeof(EVP_CHACHA20_POLY1305_CTX), /* ctx size */
	NULL, NULL, 
	EVP_chacha20_poly1305_ctrl,
	NULL
	};
	
const EVP_CIPHER *EVP_chacha20_poly1305(void)
{ return &chacha20_poly1305; }

#endif
