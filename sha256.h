https://github.com/simonratner/Arduino-SHA-256.git 


/*-
  * Copyright 2005 Colin Percival
  * Copyright 2013 Christian Mehlis & René Kijewski
  * Copyright 2016 Martin Landsmann <martin.landsmann@haw-hamburg.de>
  * Copyright 2016 OTA keys S.A.
  * All rights reserved.
  *
  * Redistribution and use in source and binary forms, with or without
  * modification, are permitted provided that the following conditions
  * are met:
  * 1. Redistributions of source code must retain the above copyright
  *    notice, this list of conditions and the following disclaimer.
  * 2. Redistributions in binary form must reproduce the above copyright
  *    notice, this list of conditions and the following disclaimer in the
  *    documentation and/or other materials provided with the distribution.
  *
  * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
  * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
  * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
  * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
  * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
  * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
  * SUCH DAMAGE.
  *
  * $FreeBSD: src/lib/libmd/sha256.h,v 1.1.2.1 2005/06/24 13:32:25 cperciva Exp $
  */
  
 #ifndef HASHES_SHA256_H
 #define HASHES_SHA256_H
  
 #include <inttypes.h>
 #include <stddef.h>
  
 #include "hashes/sha2xx_common.h"
  
 #ifdef __cplusplus
 extern "C" {
 #endif
  
 #define SHA256_DIGEST_LENGTH 32
  
 #define SHA256_INTERNAL_BLOCK_SIZE (64)
  
 typedef sha2xx_context_t sha256_context_t;
  
 typedef struct {
     sha256_context_t c_in;
     sha256_context_t c_out;
 } hmac_context_t;
  
 typedef struct {
     size_t index;
     unsigned char element[SHA256_DIGEST_LENGTH];
 } sha256_chain_idx_elm_t;
  
 void sha256_init(sha256_context_t *ctx);
  
 static inline void sha256_update(sha256_context_t *ctx, const void *data, size_t len)
 {
     sha2xx_update(ctx, data, len);
 }
  
 static inline void sha256_final(sha256_context_t *ctx, void *digest)
 {
     sha2xx_final(ctx, digest, SHA256_DIGEST_LENGTH);
 }
  
 void *sha256(const void *data, size_t len, void *digest);
  
 void hmac_sha256_init(hmac_context_t *ctx, const void *key, size_t key_length);
  
 void hmac_sha256_update(hmac_context_t *ctx, const void *data, size_t len);
  
 void hmac_sha256_final(hmac_context_t *ctx, void *digest);
  
 const void *hmac_sha256(const void *key, size_t key_length,
                         const void *data, size_t len, void *digest);
  
 void *sha256_chain(const void *seed, size_t seed_length,
                    size_t elements, void *tail_element);
  
 void *sha256_chain_with_waypoints(const void *seed, size_t seed_length,
                                   size_t elements, void *tail_element,
                                   sha256_chain_idx_elm_t *waypoints,
                                   size_t *waypoints_length);
  
 int sha256_chain_verify_element(void *element,
                                 size_t element_index,
                                 void *tail_element,
                                 size_t chain_length);
  
 #ifdef __cplusplus
 }
 #endif
  
 #endif /* HASHES_SHA256_H */
