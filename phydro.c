#include "phydro.h"

#include "ext/standard/info.h"

#if PHP_MAJOR_VERSION < 7
# error Phydro requires PHP version 7 or later
#endif

#if SIZEOF_LONG < 5
# warn Phydro uses unsigned 32bit integers, but this PHP only supports signed 32bit, some positive values may appear negative
#endif

static zend_bool validate(zend_string *str, const char *label, size_t len) {
	if (ZSTR_LEN(str) == len) { return 1; }
	php_error(E_RECOVERABLE_ERROR, "%s must be precisely %ld bytes", label, len);
	return 0;
}

/*************************************************************************/
/* Random */

/* {{{ proto int phydro_random_u32() */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(random_u32_arginfo, IS_LONG, 1)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_random_u32) {
	zend_parse_parameters_none();
	RETURN_LONG((zend_long)hydro_random_u32());
}
/* }}} */

/* {{{ proto int phydro_random_uniform(int $upper_bound) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(random_uniform_arginfo, ZEND_RETURN_VALUE, 1, IS_LONG, 1)
	ZEND_ARG_TYPE_INFO(0, upper_bound, IS_LONG, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_random_uniform) {
	zend_long upper_bound;
	uint32_t ub;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "l", &upper_bound) == FAILURE) { return; }
	ub = (uint32_t)upper_bound;

	if (((zend_long)ub) != upper_bound) {
		php_error(E_RECOVERABLE_ERROR, "Upper bound %ld overflows libhydrogen's uint32_t limit", upper_bound);
		return;
	}

	if (ub < 2) {
		php_error(E_RECOVERABLE_ERROR, "Invalid upper bound %ld, this will always result in zero", upper_bound);
		return;
	}

	RETURN_LONG((zend_long)hydro_random_uniform((uint32_t)upper_bound));
} /* }}} */

/* {{{ proto string phydro_random_buf(int $len[, ?string $seed = null]) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(random_buf_arginfo, ZEND_RETURN_VALUE, 1, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO(0, length, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, seed, IS_STRING, 1)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_random_buf) {
	zend_long len;
	zend_string *seed = NULL, *ret;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "l|S!", &len, &seed) == FAILURE) { return; }

	if ((len < 0) || (len > 0x7FFFFFFF)) {
		php_error(E_RECOVERABLE_ERROR, "Invalid buffer length: %ld", len);
		return;
	}
	ret = zend_string_alloc(len, 0);

	if (seed) {
		if (ZSTR_LEN(seed) != hydro_random_SEEDBYTES) {
			zend_string_release(ret);
			php_error(E_RECOVERABLE_ERROR, "Seed must be precisely %d bytes long", hydro_random_SEEDBYTES);
			return;
		}
		hydro_random_buf_deterministic(ZSTR_VAL(ret), len, ZSTR_VAL(seed));
	} else {
		hydro_random_buf(ZSTR_VAL(ret), len);
	}
	ZSTR_VAL(ret)[len] = 0;
	ZSTR_LEN(ret) = len;
	RETURN_NEW_STR(ret);
} /* }}} */

/* {{{ proto void phydro_random_ratchet() */
static PHP_FUNCTION(phydro_random_ratchet) {
	zend_parse_parameters_none();
	hydro_random_ratchet();
} /* }}} */

/* {{{ proto void phydro_random_reseed() */
static PHP_FUNCTION(phydro_random_reseed) {
	zend_parse_parameters_none();
	hydro_random_reseed();
} /* }}} */

/*************************************************************************/
/* Hash */

/* {{{ proto string phydro_hash_keygen() */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO(hash_keygen_arginfo, IS_STRING, 1)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_hash_keygen) {
	uint8_t hash[hydro_hash_KEYBYTES];
	zend_parse_parameters_none();
	hydro_hash_keygen(hash);
	RETURN_STRINGL(hash, sizeof(hash));
} /* }}} */

/* {{{ proto PhydroHash phydro_hash_init(string $context, string $key) */
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(hash_init_arginfo, ZEND_RETURN_VALUE, 2, PhydroHash, 1)
	ZEND_ARG_TYPE_INFO(0, context, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_hash_init) {
	zend_string *context, *key;
	zend_object *ret;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "SS", &context, &key) == FAILURE) { return; }
	if (!validate(context, "Context", hydro_hash_CONTEXTBYTES) ||
		!validate(key, "Key", hydro_hash_KEYBYTES)) {
		return;
	}
	ret = phydro_hash_init(context, key);
	if (!ret) {
		php_error(E_RECOVERABLE_ERROR, "Failure initializing hash context");
		return;
	}
	RETURN_OBJ(ret);
} /* }}} */

/* {{{ proto bool phydro_hash_update(PhydroHash $hash, string $data) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(hash_update_arginfo, ZEND_RETURN_VALUE, 2, _IS_BOOL, 1)
	ZEND_ARG_OBJ_INFO(0, hash, PhydroHash, 0)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_hash_update) {
	zval *hash;
	zend_string *data;
	hydro_hash_state* state;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "OS", &hash, phydro_hash_ce, &data) == FAILURE) { return; }
	state = phydro_hash_get_state(Z_OBJ_P(hash));
	if (!state) {
		php_error(E_RECOVERABLE_ERROR, "Error getting state from PhydroHash object");
		RETURN_FALSE;
	}
	if (hydro_hash_update(state, ZSTR_VAL(data), ZSTR_LEN(data))) {
		php_error(E_RECOVERABLE_ERROR, "Failure updating hash");
		RETURN_FALSE;
	}
	RETURN_TRUE;
} /* }}} */

/* {{{ proto string phydro_hash_final(PhydroHash $hash, int $len) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(hash_final_arginfo, ZEND_RETURN_VALUE, 2, IS_STRING, 1)
	ZEND_ARG_OBJ_INFO(0, hash, PhydroHash, 0)
	ZEND_ARG_TYPE_INFO(0, len, IS_LONG, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_hash_final) {
	zval *hash;
	zend_long len;
	hydro_hash_state* state;
	zend_string *ret;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "Ol", &hash, phydro_hash_ce, &len) == FAILURE) { return; }
	state = phydro_hash_get_state(Z_OBJ_P(hash));
	if (!state) {
		php_error(E_RECOVERABLE_ERROR, "Error getting state from PhydroHash object");
		return;
	}
	if ((len < hydro_hash_BYTES_MIN) || (len > hydro_hash_BYTES_MAX)) {
		php_error(E_RECOVERABLE_ERROR, "Invalid output length: %ld", len);
		return;
	}
	ret = zend_string_alloc(len, 0);
	if (hydro_hash_final(state, ZSTR_VAL(ret), len)) {
		php_error(E_RECOVERABLE_ERROR, "Failure updating hash");
		return;
	}
	RETURN_NEW_STR(ret);
} /* }}} */

/* {{{ proto string phydro_hash_hash(string $data, int $len, string $context, string $key) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(hash_hash_arginfo, ZEND_RETURN_VALUE, 4, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, len, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, context, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_hash_hash) {
	zend_string *data, *context, *key, *ret;
	zend_long len;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "SlSS", &data, &len, &context, &key) == FAILURE) { return; }

	if ((len < hydro_hash_BYTES_MIN) || (len > hydro_hash_BYTES_MAX)) {
		php_error(E_RECOVERABLE_ERROR, "Invalid output length: %ld", len);
		return;
	}
	if (!validate(context, "Context", hydro_hash_CONTEXTBYTES) ||
		!validate(key, "Key", hydro_hash_KEYBYTES)) {
		return;
	}

	ret = zend_string_alloc(len, 0);
	if (hydro_hash_hash(ZSTR_VAL(ret), len, ZSTR_VAL(data), ZSTR_LEN(data), ZSTR_VAL(context), ZSTR_VAL(key))) {
		php_error(E_RECOVERABLE_ERROR, "Failure hashing input");
		return;
	}
	ZSTR_VAL(ret)[len] = 0;
	ZSTR_LEN(ret) = len;
	RETURN_NEW_STR(ret);
} /* }}} */

/*************************************************************************/
/* Secretbox */

/* {{{ proto string phydro_secretbox_keygen() */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(box_keygen_arginfo, ZEND_RETURN_VALUE, 0, IS_STRING, 1)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_secretbox_keygen) {
	uint8_t key[hydro_secretbox_KEYBYTES];
	zend_parse_parameters_none();
	hydro_secretbox_keygen(key);
	RETURN_STRINGL(key, sizeof(key));
} /* }}} */

/* {{{ proto string phydro_secretbox_encrypt(string $message, int $id, string $context, string $key) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(box_encrypt_arginfo, ZEND_RETURN_VALUE, 4, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO(0, message, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, id, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, context, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_secretbox_encrypt) {
	zend_string *message, *context, *key, *ret;
	zend_long id;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "SlSS", &message, &id, &context, &key) == FAILURE) { return; }
	if (!validate(context, "Context", hydro_secretbox_CONTEXTBYTES) ||
		!validate(key, "Key", hydro_secretbox_KEYBYTES)) {
		return;
	}

	ret = zend_string_alloc(ZSTR_LEN(message) + hydro_secretbox_HEADERBYTES, 0);
	if (hydro_secretbox_encrypt(ZSTR_VAL(ret), ZSTR_VAL(message), ZSTR_LEN(message), (uint64_t)id, ZSTR_VAL(context), ZSTR_VAL(key))) {
		zend_string_release(ret);
		php_error(E_RECOVERABLE_ERROR, "Error encrypting payload");
		return;
	}
	ZSTR_VAL(ret)[ZSTR_LEN(message) + hydro_secretbox_HEADERBYTES] = 0;
	ZSTR_LEN(ret) = ZSTR_LEN(message) + hydro_secretbox_HEADERBYTES;
	RETURN_NEW_STR(ret);
} /* }}} */

/* {{{ proto string phydro_secretbox_decrypt(string $ciphertext, int $id, string $context, string $key) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(box_decrypt_arginfo, ZEND_RETURN_VALUE, 4, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO(0, ciphertext, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, id, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, context, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_secretbox_decrypt) {
	zend_string *ciphertext, *context, *key, *ret;
	zend_long id, ret_len;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "SlSS", &ciphertext, &id, &context, &key) == FAILURE) { return; }
	if (!validate(context, "Context", hydro_secretbox_CONTEXTBYTES) ||
		!validate(key, "Key", hydro_secretbox_KEYBYTES)) {
		return;
	}

	ret_len = ZSTR_LEN(ciphertext) - hydro_secretbox_HEADERBYTES;
	ret = zend_string_alloc(ret_len, 0);
	if (hydro_secretbox_decrypt(ZSTR_VAL(ret), ZSTR_VAL(ciphertext), ZSTR_LEN(ciphertext), (uint64_t)id, ZSTR_VAL(context), ZSTR_VAL(key))) {
		zend_string_release(ret);
		php_error(E_RECOVERABLE_ERROR, "Error decrypting payload");
		return;
	}
	ZSTR_VAL(ret)[ret_len] = 0;
	ZSTR_LEN(ret) = ret_len;
	RETURN_NEW_STR(ret);
} /* }}} */

/* {{{ proto string phydro_secretbox_probe_create(string $ciphertext, string $context, string $key) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(box_probe_create_arginfo, ZEND_RETURN_VALUE, 3, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO(0, ciphertext, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, context, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_secretbox_probe_create) {
	zend_string *ciphertext, *context, *key, *ret;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "SSS", &ciphertext, &context, &key) == FAILURE) { return; }
	if (!validate(context, "Context", hydro_secretbox_CONTEXTBYTES) ||
		!validate(key, "Key", hydro_secretbox_KEYBYTES)) {
		return;
	}
	ret = zend_string_alloc(hydro_secretbox_PROBEBYTES, 0);
	hydro_secretbox_probe_create(ZSTR_VAL(ret), ZSTR_VAL(ciphertext), ZSTR_LEN(ciphertext), ZSTR_VAL(context), ZSTR_VAL(key));
	ZSTR_VAL(ret)[hydro_secretbox_PROBEBYTES] = 0;
	ZSTR_LEN(ret) = hydro_secretbox_PROBEBYTES;
	RETURN_NEW_STR(ret);
} /* }}} */

/* {{{ proto bool phydro_secretbox_probe_verify(string $probe, string $ciphertext, string $context, string $key) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(box_probe_verify_arginfo, ZEND_RETURN_VALUE, 4, _IS_BOOL, 1)
	ZEND_ARG_TYPE_INFO(0, probe, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, ciphertext, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, context, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_secretbox_probe_verify) {
	zend_string *probe, *ciphertext, *context, *key;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "SSSS", &probe, &ciphertext, &context, &key) == FAILURE) { return; }
	if (!validate(context, "Context", hydro_secretbox_CONTEXTBYTES) ||
		!validate(key, "Key", hydro_secretbox_KEYBYTES)) {
		return;
	}
	if (ZSTR_LEN(probe) != hydro_secretbox_PROBEBYTES) {
		php_error(E_RECOVERABLE_ERROR, "Invalid probe length, must be exactly %d bytes", hydro_secretbox_PROBEBYTES);
		return;
	}
	RETURN_BOOL(0 == hydro_secretbox_probe_verify(ZSTR_VAL(probe),
	                                              ZSTR_VAL(ciphertext), ZSTR_LEN(ciphertext),
                                                  ZSTR_VAL(context), ZSTR_VAL(key)));
} /* }}} */

/*************************************************************************/
/* KDF */

/* {{{ proto string phydro_kdf_keygen() */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(kdf_keygen_arginfo, ZEND_RETURN_VALUE, 0, IS_STRING, 1)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_kdf_keygen) {
	zend_string *ret = zend_string_alloc(hydro_kdf_KEYBYTES, 0);
	zend_parse_parameters_none();
	hydro_kdf_keygen(ZSTR_VAL(ret));
	ZSTR_VAL(ret)[hydro_kdf_KEYBYTES] = 0;
	ZSTR_LEN(ret) = hydro_kdf_KEYBYTES;
	RETURN_NEW_STR(ret);
} /* }}} */

/* {{{ proto string phydro_kdf_derive_from_key(int $len, int $id, string $context, string $key) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(kdf_derive_from_key_arginfo, ZEND_RETURN_VALUE, 4, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO(0, length, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, id, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, context, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, key, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_kdf_derive_from_key) {
	zend_long len, id;
	zend_string *context, *key, *ret;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "llSS", &len, &id, &context, &key) == FAILURE) { return; }

	if ((len < hydro_kdf_BYTES_MIN) || (len > hydro_kdf_BYTES_MAX)) {
		php_error(E_RECOVERABLE_ERROR, "Invalid length specified %ld, must be between %d and %d", len, hydro_kdf_BYTES_MIN, hydro_kdf_BYTES_MAX);
		return;
	}
	if (ZSTR_LEN(context) != hydro_kdf_CONTEXTBYTES) {
		php_error(E_RECOVERABLE_ERROR, "Context must be precisely %d bytes", hydro_kdf_CONTEXTBYTES);
		return;
	}
	if (ZSTR_LEN(key) != hydro_kdf_KEYBYTES) {
		php_error(E_RECOVERABLE_ERROR, "Key must be precisely %d bytes", hydro_kdf_KEYBYTES);
		return;
	}
	ret = zend_string_alloc(len, 0);
	if (hydro_kdf_derive_from_key(ZSTR_VAL(ret), len, (uint64_t)id, ZSTR_VAL(context), ZSTR_VAL(key))) {
		zend_string_release(ret);
		php_error(E_RECOVERABLE_ERROR, "Failed deriving subkey");
		return;
	}
	ZSTR_VAL(ret)[len] = 0;
	ZSTR_LEN(ret) = len;
	RETURN_NEW_STR(ret);
} /* }}} */

/*************************************************************************/
/* Signing */

/* {{{ proto array phydro_sign_keygen([?string $seed = null])
 * Return array:
 * 'pubkey' => $pk
 * 'seckey' => $sk
 */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(sign_keygen_arginfo, ZEND_RETURN_VALUE, 0, IS_ARRAY, 1)
	ZEND_ARG_TYPE_INFO(0, seed, IS_STRING, 1)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_sign_keygen) {
	zend_string *seed = NULL;
	hydro_sign_keypair kp;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "|S!", &seed) == FAILURE) { return; }
	if (seed) {
		if (!validate(seed, "Seed", hydro_sign_SEEDBYTES)) { return; }
		hydro_sign_keygen_deterministic(&kp, ZSTR_VAL(seed));
	} else {
		hydro_sign_keygen(&kp);
	}
	array_init(return_value);
	add_assoc_stringl(return_value, "pubkey", kp.pk, sizeof(kp.pk));
	add_assoc_stringl(return_value, "seckey", kp.sk, sizeof(kp.sk));
	hydro_memzero(&kp, sizeof(kp));
} /* }}} */

/* {{{ proto PhydroSignState phydro_sign_init(string $context) */
ZEND_BEGIN_ARG_WITH_RETURN_OBJ_INFO_EX(sign_init_arginfo, ZEND_RETURN_VALUE, 1, PhydroSignState, 1)
	ZEND_ARG_TYPE_INFO(0, context, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_sign_init) {
	zend_string *context;
	zend_object *ret;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "S", &context) == FAILURE) { return; }
	if (!validate(context, "Context", hydro_hash_CONTEXTBYTES)) { return; }
	ret = phydro_sign_init(context);
	if (!ret) {
		php_error(E_RECOVERABLE_ERROR, "Failure initializing signing context");
		return;
	}
	RETURN_OBJ(ret);
} /* }}} */

/* {{{ proto bool phydro_sign_update(PhydroSignState $sign, string $data) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(sign_update_arginfo, ZEND_RETURN_VALUE, 2, _IS_BOOL, 1)
	ZEND_ARG_OBJ_INFO(0, sign, PhydroSignState, 0)
	ZEND_ARG_TYPE_INFO(0, data, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_sign_update) {
	zval *sign;
	zend_string *data;
	hydro_sign_state* state;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "OS", &sign, phydro_sign_ce, &data) == FAILURE) { return; }
	state = phydro_sign_get_state(Z_OBJ_P(sign));
	if (!state) {
		php_error(E_RECOVERABLE_ERROR, "Error getting state from PhydroSignState object");
		RETURN_FALSE;
	}
	if (hydro_sign_update(state, ZSTR_VAL(data), ZSTR_LEN(data))) {
		php_error(E_RECOVERABLE_ERROR, "Failure updating signature");
		RETURN_FALSE;
	}
	RETURN_TRUE;
} /* }}} */

/* {{{ proto string phydro_sign_final_create(PhydroSignState $sign, string $seckey) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(sign_final_create_arginfo, ZEND_RETURN_VALUE, 2, IS_STRING, 1)
	ZEND_ARG_OBJ_INFO(0, sign, PhydroSignState, 0)
	ZEND_ARG_TYPE_INFO(0, seckey, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_sign_final_create) {
	zval *sign;
	hydro_sign_state* state;
	zend_string *ret, *seckey;
	uint8_t csig[hydro_sign_BYTES];

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "OS", &sign, phydro_sign_ce, &seckey) == FAILURE) { return; }
	if (!validate(seckey, "Secret key", hydro_sign_SECRETKEYBYTES)) { return; }
	state = phydro_sign_get_state(Z_OBJ_P(sign));
	if (!state) {
		php_error(E_RECOVERABLE_ERROR, "Error getting state from PhydroSignState object");
		return;
	}
	if (hydro_sign_final_create(state, csig, ZSTR_VAL(seckey))) {
		php_error(E_RECOVERABLE_ERROR, "Error signing message");
		return;
	}
	RETVAL_STRINGL(csig, sizeof(csig));
	hydro_memzero(csig, sizeof(csig));
} /* }}} */

/* {{{ proto bool phydro_sign_final_verify(PhydroSignState $sign, string $signature, string $pubkey) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(sign_final_verify_arginfo, ZEND_RETURN_VALUE, 3, _IS_BOOL, 1)
	ZEND_ARG_OBJ_INFO(0, sign, PhydroSignState, 0)
	ZEND_ARG_TYPE_INFO(0, signature, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, pubkey, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_sign_final_verify) {
	zval *sign;
	hydro_sign_state* state;
	zend_string *sig, *pubkey;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "OSS", &sign, phydro_sign_ce, &sig, &pubkey) == FAILURE) { return; }
	if (!validate(sig, "Signature", hydro_sign_BYTES) ||
		!validate(pubkey, "Public key", hydro_sign_PUBLICKEYBYTES)) {
		return;
	}
	state = phydro_sign_get_state(Z_OBJ_P(sign));
	if (!state) {
		php_error(E_RECOVERABLE_ERROR, "Error getting state from PhydroSignState object");
		return;
	}
	RETURN_BOOL(0 == hydro_sign_final_verify(state, ZSTR_VAL(sig), ZSTR_VAL(pubkey)));
} /* }}} */

/* {{{ proto string phydro_sign_create(string $message, string $context, string $seckey) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(sign_create_arginfo, ZEND_RETURN_VALUE, 3, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO(0, message, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, context, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, seckey, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_sign_create) {
	zend_string *message, *context, *seckey;
	uint8_t csig[hydro_sign_BYTES];
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "SSS", &message, &context, &seckey) == FAILURE) { return; }
	if (!validate(context, "Context", hydro_sign_CONTEXTBYTES) ||
		!validate(seckey, "Secret key", hydro_sign_SECRETKEYBYTES)) {
		return;
	}
	if (hydro_sign_create(csig, ZSTR_VAL(message), ZSTR_LEN(message), ZSTR_VAL(context), ZSTR_VAL(seckey))) {
		php_error(E_RECOVERABLE_ERROR, "Failed creating signature");
		return;
	}
	RETURN_STRINGL(csig, sizeof(csig));
} /* }}} */

/* {{{ proto bool phydro_sign_verify(string $message, string $signature, string $context, string $publickey) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(sign_verify_arginfo, ZEND_RETURN_VALUE, 4, _IS_BOOL, 1)
	ZEND_ARG_TYPE_INFO(0, message, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, signature, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, context, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, pubkey, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_sign_verify) {
	zend_string *message, *signature, *context, *pubkey;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "SSSS", &message, &signature, &context, &pubkey) == FAILURE) { return; }
	if (!validate(signature, "Signature", hydro_sign_BYTES) ||
		!validate(context, "Context", hydro_sign_CONTEXTBYTES) ||
		!validate(pubkey, "Public key", hydro_sign_PUBLICKEYBYTES)) {
		return;
	}
	RETURN_BOOL(0 == hydro_sign_verify(ZSTR_VAL(signature), ZSTR_VAL(message), ZSTR_LEN(message), ZSTR_VAL(context), ZSTR_VAL(pubkey)));
} /* }}} */

/*************************************************************************/
/* Key Exchange */

/* {{{ proto array phydro_kx_keygen([?string $seed = null])
 * Return array:
 * 'pubkey' => $pk
 * 'seckey' => $sk
 */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(kx_keygen_arginfo, ZEND_RETURN_VALUE, 0, IS_ARRAY, 1)
	ZEND_ARG_TYPE_INFO(0, seed, IS_STRING, 1)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_kx_keygen) {
	zend_string *seed = NULL;
	hydro_kx_keypair kp;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "|S!", &seed) == FAILURE) { return; }
	if (seed) {
		if (!validate(seed, "Seed", hydro_kx_SEEDBYTES)) { return; }
		hydro_kx_keygen_deterministic(&kp, ZSTR_VAL(seed));
	} else {
		hydro_kx_keygen(&kp);
	}
	array_init(return_value);
	add_assoc_stringl(return_value, "pubkey", kp.pk, sizeof(kp.pk));
	add_assoc_stringl(return_value, "seckey", kp.sk, sizeof(kp.sk));
	hydro_memzero(&kp, sizeof(kp));
} /* }}} */

/* {{{ proto array phydro_kx_n_1(string $psk, string $publicKey)
 * Return array:
 * 'packet' => $packet1
 * 'keys' => [ 'tx' => $tx, 'rx' => $rx ]
 */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(n1_arginfo, ZEND_RETURN_VALUE, 2, IS_ARRAY, 1)
	ZEND_ARG_TYPE_INFO(0, psk, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, publicKey, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_kx_n_1) {
	zend_string *psk, *pubkey;
	hydro_kx_session_keypair skp;
	uint8_t packet[hydro_kx_N_PACKET1BYTES];
	zval zskp;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "SS", &psk, &pubkey) == FAILURE) { return; }
	if (!validate(psk, "PSK", hydro_kx_PSKBYTES) ||
		!validate(pubkey, "Public key", hydro_kx_PUBLICKEYBYTES)) {
		return;
	}
	if (hydro_kx_n_1(&skp, packet, ZSTR_VAL(psk), ZSTR_VAL(pubkey))) {
		php_error(E_RECOVERABLE_ERROR, "Error generating N1 packet and session keys");
		return;
	}
	array_init(return_value);
	add_assoc_stringl(return_value, "packet", packet, sizeof(packet));

	array_init(&zskp);
	add_assoc_stringl(&zskp, "tx", skp.tx, sizeof(skp.tx));
	add_assoc_stringl(&zskp, "rx", skp.rx, sizeof(skp.rx));
	add_assoc_zval(return_value, "keys", &zskp);

	hydro_memzero(packet, sizeof(packet));
	hydro_memzero(&skp, sizeof(skp));
} /* }}} */

/* {{{ proto array phydro_kx_n_2(string $packet_1, string $psk, string $publicKey, string $secretKey)
 * Return array:
 * 'tx' => $tx
 * 'rx' => $rx
 */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(n2_arginfo, ZEND_RETURN_VALUE, 4, IS_ARRAY, 1)
	ZEND_ARG_TYPE_INFO(0, packet1, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, psk, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, publicKey, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, secretKey, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_kx_n_2) {
	zend_string *packet1, *psk, *pubkey, *seckey;
	hydro_kx_keypair kp;
	hydro_kx_session_keypair skp;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "SSSS", &packet1, &psk, &pubkey, &seckey) == FAILURE) { return; }
	if (!validate(packet1, "Packet 1", hydro_kx_N_PACKET1BYTES) ||
		!validate(psk, "PSK", hydro_kx_PSKBYTES) ||
		!validate(pubkey, "Public key", hydro_kx_PUBLICKEYBYTES) ||
		!validate(seckey, "Secret key", hydro_kx_SECRETKEYBYTES)) {
		return;
	}
	memcpy(kp.pk, ZSTR_VAL(pubkey), sizeof(kp.pk));
	memcpy(kp.sk, ZSTR_VAL(seckey), sizeof(kp.sk));
	if (hydro_kx_n_2(&skp, ZSTR_VAL(packet1), ZSTR_VAL(psk), &kp)) {
		hydro_memzero(&kp, sizeof(kp));
		php_error(E_RECOVERABLE_ERROR, "Failure generating session keys");
		return;
	}
	hydro_memzero(&kp, sizeof(kp));
	array_init(return_value);
	add_assoc_stringl(return_value, "tx", skp.tx, sizeof(skp.tx));
	add_assoc_stringl(return_value, "rx", skp.rx, sizeof(skp.rx));

	hydro_memzero(&skp, sizeof(skp));
} /* }}} */

/* {{{ proto array phydro_kx_kk_1(string $peerPublicKey, string $publicKey, string $secretKey)
 * Return array:
 * 'packet' => $packet1
 * 'state' => $state
 */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(kk1_arginfo, ZEND_RETURN_VALUE, 3, IS_ARRAY, 1)
	ZEND_ARG_TYPE_INFO(0, peerPublicKey, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, publicKey, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, secretKey, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_kx_kk_1) {
	zend_string *peer_pubkey, *pubkey, *seckey;
	hydro_kx_keypair kp;
	uint8_t packet[hydro_kx_KK_PACKET1BYTES];
	hydro_kx_state state;
	zend_object *state_obj;
	zval zstate;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "SSS", &peer_pubkey, &pubkey, &seckey) == FAILURE) { return; }
	if (!validate(peer_pubkey, "Peer public key", hydro_kx_PUBLICKEYBYTES) ||
		!validate(pubkey, "Public key", hydro_kx_PUBLICKEYBYTES) ||
		!validate(seckey, "Secret key", hydro_kx_SECRETKEYBYTES)) {
		return;
	}

	memcpy(kp.pk, ZSTR_VAL(pubkey), sizeof(kp.pk));
	memcpy(kp.sk, ZSTR_VAL(seckey), sizeof(kp.sk));
	if (hydro_kx_kk_1(&state, packet, ZSTR_VAL(peer_pubkey), &kp)) {
		hydro_memzero(&kp, sizeof(kp));
		php_error(E_RECOVERABLE_ERROR, "Failure generating packet");
		return;
	}
	hydro_memzero(&kp, sizeof(kp));
	state_obj = phydro_kx_state_init(&state);
	hydro_memzero(&state, sizeof(state));
	if (!state_obj) {
		php_error(E_RECOVERABLE_ERROR, "Unable to create state object");
		hydro_memzero(&packet, sizeof(packet));
		return;
	}
	ZVAL_OBJ(&zstate, state_obj);

	array_init(return_value);
	add_assoc_stringl(return_value, "packet", packet, sizeof(packet));
	add_assoc_zval(return_value, "state", &zstate);

	hydro_memzero(packet, sizeof(packet));
} /* }}} */

/* {{{ proto array phydro_kx_kk_2(string $packet1, string $peerPublicKey, string $publicKey, string $secretKey)
 * Return array:
 * 'packet' => $packet2
 * 'keys' => [ 'tx' => $tx, 'rx' => $rx ]
 */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(kk2_arginfo, ZEND_RETURN_VALUE, 4, IS_ARRAY, 1)
	ZEND_ARG_TYPE_INFO(0, packet1, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, peerPublicKey, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, publicKey, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, secretKey, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_kx_kk_2) {
	zend_string *packet1, *peer_pubkey, *pubkey, *seckey;
	hydro_kx_keypair kp;
	uint8_t packet2[hydro_kx_KK_PACKET2BYTES];
	hydro_kx_session_keypair skp;
	zval zskp;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "SSSS", &packet1, &peer_pubkey, &pubkey, &seckey) == FAILURE) { return; }
	if (!validate(packet1, "Packet 1", hydro_kx_KK_PACKET1BYTES) ||
		!validate(peer_pubkey, "Peer public key", hydro_kx_PUBLICKEYBYTES) ||
		!validate(pubkey, "Public key", hydro_kx_PUBLICKEYBYTES) ||
		!validate(seckey, "Secret key", hydro_kx_SECRETKEYBYTES)) {
		return;
	}

	memcpy(kp.pk, ZSTR_VAL(pubkey), sizeof(kp.pk));
	memcpy(kp.sk, ZSTR_VAL(seckey), sizeof(kp.sk));
	if (hydro_kx_kk_2(&skp, packet2, ZSTR_VAL(packet1), ZSTR_VAL(peer_pubkey), &kp)) {
		hydro_memzero(&kp, sizeof(kp));
		php_error(E_RECOVERABLE_ERROR, "Failure generating packet");
		return;
	}
	hydro_memzero(&kp, sizeof(kp));

	array_init(return_value);
	add_assoc_stringl(return_value, "packet", packet2, sizeof(packet2));
	hydro_memzero(packet2, sizeof(packet2));

	array_init(&zskp);
	add_assoc_stringl(&zskp, "tx", skp.tx, sizeof(skp.tx));
	add_assoc_stringl(&zskp, "rx", skp.rx, sizeof(skp.rx));
	add_assoc_zval(return_value, "keys", &zskp);

	hydro_memzero(&skp, sizeof(skp));
} /* }}} */

/* {{{ proto array phydro_kx_kk_3(PhydroKXState $state, string $packet2, string $peerPublicKey)
 * Return array:
 * "tx" => $tx
 * "rx" => $rx
 */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(kk3_arginfo, ZEND_RETURN_VALUE, 3, IS_ARRAY, 1)
	ZEND_ARG_OBJ_INFO(0, state, PhydroKXState, 0)
	ZEND_ARG_TYPE_INFO(0, packet2, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, peerPublicKey, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_kx_kk_3) {
	zval *zstate;
	zend_string *packet2, *peer_pubkey;
	hydro_kx_state *state;
	hydro_kx_session_keypair skp;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "OSS", &zstate, phydro_kx_ce, &packet2, &peer_pubkey) == FAILURE) { return; }
	if (!validate(packet2, "Packet 2", hydro_kx_KK_PACKET2BYTES) ||
		!validate(peer_pubkey, "Peer public key", hydro_kx_PUBLICKEYBYTES)) {
		return;
	}
	state = phydro_kx_get_state(Z_OBJ_P(zstate));
	if (hydro_kx_kk_3(state, &skp, ZSTR_VAL(packet2), ZSTR_VAL(peer_pubkey))) {
		php_error(E_RECOVERABLE_ERROR, "Failure generating session keys");
		return;
	}

	array_init(return_value);
	add_assoc_stringl(return_value, "tx", skp.tx, sizeof(skp.tx));
	add_assoc_stringl(return_value, "rx", skp.rx, sizeof(skp.rx));
	hydro_memzero(&skp, sizeof(skp));
} /* }}} */

/* {{{ proto array phydro_kx_xx_1(string $psk)
 * Return array:
 * 'packet' => $packet1
 * 'state' => $state
 */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(xx1_arginfo, ZEND_RETURN_VALUE, 1, IS_ARRAY, 1)
	ZEND_ARG_TYPE_INFO(0, psk, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_kx_xx_1) {
	zend_string *psk;
	hydro_kx_state state;
	uint8_t packet1[hydro_kx_XX_PACKET1BYTES];
	zend_object *state_obj;
	zval zstate;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "S", &psk) == FAILURE) { return; }
	if (!validate(psk, "PSK", hydro_kx_PSKBYTES)) { return; }

	if (hydro_kx_xx_1(&state, packet1, ZSTR_VAL(psk))) {
		php_error(E_RECOVERABLE_ERROR, "Unable to create packet");
		return;
	}

	state_obj = phydro_kx_state_init(&state);
	hydro_memzero(&state, sizeof(state));
	if (!state_obj) {
		php_error(E_RECOVERABLE_ERROR, "Unable to create state object");
		hydro_memzero(&packet1, sizeof(packet1));
		return;
	}
	ZVAL_OBJ(&zstate, state_obj);

	array_init(return_value);
	add_assoc_stringl(return_value, "packet", packet1, sizeof(packet1));
	add_assoc_zval(return_value, "state", &zstate);

	hydro_memzero(packet1, sizeof(packet1));
} /* }}} */

/* {{{ proto array phydro_kx_xx_2(string $packet1, string $psk, string $pubkey, string $seckey)
 * Return array:
 * 'packet' => $packet3
 * 'state' => $state
 */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(xx2_arginfo, ZEND_RETURN_VALUE, 4, IS_ARRAY, 1)
	ZEND_ARG_TYPE_INFO(0, packet1, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, psk, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, pubkey, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, seckey, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_kx_xx_2) {
	zend_string *packet1, *psk, *pubkey, *seckey;
	hydro_kx_state state;
	uint8_t packet2[hydro_kx_XX_PACKET2BYTES];
	hydro_kx_keypair kp;
	zend_object *state_obj;
	zval zstate;

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "SSSS", &packet1, &psk, &pubkey, &seckey) == FAILURE) { return; }
	if (!validate(packet1, "Packet 1", hydro_kx_XX_PACKET1BYTES) ||
		!validate(psk, "PSK", hydro_kx_PSKBYTES) ||
		!validate(pubkey, "Public key", hydro_kx_PUBLICKEYBYTES) ||
		!validate(seckey, "Secret Key", hydro_kx_SECRETKEYBYTES)) { return; }

	memcpy(kp.pk, ZSTR_VAL(pubkey), hydro_kx_PUBLICKEYBYTES);
	memcpy(kp.sk, ZSTR_VAL(seckey), hydro_kx_SECRETKEYBYTES);
	if (hydro_kx_xx_2(&state, packet2, ZSTR_VAL(packet1), ZSTR_VAL(psk), &kp)) {
		hydro_memzero(&kp, sizeof(kp));
		php_error(E_RECOVERABLE_ERROR, "Unable to create packet");
		return;
	}
	hydro_memzero(&kp, sizeof(kp));

	state_obj = phydro_kx_state_init(&state);
	hydro_memzero(&state, sizeof(state));
	if (!state_obj) {
		php_error(E_RECOVERABLE_ERROR, "Unable to create state object");
		hydro_memzero(&packet2, sizeof(packet2));
		return;
	}
	ZVAL_OBJ(&zstate, state_obj);

	array_init(return_value);
	add_assoc_stringl(return_value, "packet", packet2, sizeof(packet2));
	add_assoc_zval(return_value, "state", &zstate);

	hydro_memzero(packet2, sizeof(packet2));
} /* }}} */

/* {{{ proto array phydro_kx_xx_3(PhydroKXState $state, string $packet2, string $psk, string $pubkey, string $seckey)
 * Return array:
 * 'packet' => $packet3
 * 'keys' => [ 'tx' => $tx, 'rx' => $rx ]
 * 'peer' => $peerPublicKey
 */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(xx3_arginfo, ZEND_RETURN_VALUE, 5, IS_ARRAY, 1)
	ZEND_ARG_OBJ_INFO(0, state, PhydroKXState, 0)
	ZEND_ARG_TYPE_INFO(0, packet2, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, psk, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, pubkey, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, seckey, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_kx_xx_3) {
	zval *zstate;
	zend_string *packet2, *psk, *pubkey, *seckey;
	hydro_kx_state *state;
	hydro_kx_keypair kp;
	hydro_kx_session_keypair skp;
	zval zskp;
	uint8_t packet3[hydro_kx_XX_PACKET3BYTES];
	uint8_t peer[hydro_kx_PUBLICKEYBYTES];

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "OSSSS", &zstate, phydro_kx_ce, &packet2, &psk, &pubkey, &seckey) == FAILURE) { return; }
	if (!validate(packet2, "Packet 2", hydro_kx_XX_PACKET2BYTES) ||
		!validate(psk, "PSK", hydro_kx_PSKBYTES) ||
		!validate(pubkey, "Public key", hydro_kx_PUBLICKEYBYTES) ||
		!validate(seckey, "Secret key", hydro_kx_SECRETKEYBYTES)) {
		return;
	}
	state = phydro_kx_get_state(Z_OBJ_P(zstate));
	memcpy(kp.pk, ZSTR_VAL(pubkey), sizeof(kp.pk));
	memcpy(kp.sk, ZSTR_VAL(seckey), sizeof(kp.sk));
	if (hydro_kx_xx_3(state, &skp, packet3, peer, ZSTR_VAL(packet2), ZSTR_VAL(psk), &kp)) {
		hydro_memzero(&kp, sizeof(kp));
		php_error(E_RECOVERABLE_ERROR, "Failure generating packet");
		return;
	}
	hydro_memzero(&kp, sizeof(kp));

	array_init(return_value);
	add_assoc_stringl(return_value, "packet", packet3, sizeof(packet3));

	array_init(&zskp);
	add_assoc_stringl(&zskp, "tx", skp.tx, sizeof(skp.tx));
	add_assoc_stringl(&zskp, "rx", skp.rx, sizeof(skp.rx));
	add_assoc_zval(return_value, "keys", &zskp);

	add_assoc_stringl(return_value, "peer", peer, sizeof(peer));

	hydro_memzero(packet3, sizeof(packet3));
	hydro_memzero(&skp, sizeof(skp));
} /* }}} */

/* {{{ proto array phydro_kx_xx_4(PhydroKXState $state, string $packet3, string $psk)
 * Return array:
 * 'keys' => [ 'tx' => $tx, 'rx' => $rx ]
 * 'peer' => $peerPublicKey
 */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(xx4_arginfo, ZEND_RETURN_VALUE, 3, IS_ARRAY, 1)
	ZEND_ARG_OBJ_INFO(0, state, PhydroKXState, 0)
	ZEND_ARG_TYPE_INFO(0, packet3, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, psk, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_kx_xx_4) {
	zval *zstate;
	zend_string *packet3, *psk;
	hydro_kx_state *state;
	hydro_kx_session_keypair skp;
	zval zskp;
	uint8_t peer[hydro_kx_PUBLICKEYBYTES];

	if (zend_parse_parameters(ZEND_NUM_ARGS(), "OSS", &zstate, phydro_kx_ce, &packet3, &psk) == FAILURE) { return; }
	if (!validate(packet3, "Packet 3", hydro_kx_XX_PACKET3BYTES) ||
		!validate(psk, "PSK", hydro_kx_PSKBYTES)) {
		return;
	}
	state = phydro_kx_get_state(Z_OBJ_P(zstate));
	if (hydro_kx_xx_4(state, &skp, peer, ZSTR_VAL(packet3), ZSTR_VAL(psk))) {
		php_error(E_RECOVERABLE_ERROR, "Failure generating session keys");
		return;
	}

	array_init(return_value);

	array_init(&zskp);
	add_assoc_stringl(&zskp, "tx", skp.tx, sizeof(skp.tx));
	add_assoc_stringl(&zskp, "rx", skp.rx, sizeof(skp.rx));
	add_assoc_zval(return_value, "keys", &zskp);

	add_assoc_stringl(return_value, "peer", peer, sizeof(peer));

	hydro_memzero(&skp, sizeof(skp));
} /* }}} */

/*************************************************************************/
/* PWHash */

/* {{{ proto string phydro_pwhash_keygen() */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(pwhash_keygen_arginfo, ZEND_RETURN_VALUE, 0, IS_STRING, 1)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_pwhash_keygen) {
	uint8_t key[hydro_pwhash_MASTERKEYBYTES];
	zend_parse_parameters_none();
	hydro_pwhash_keygen(key);
	RETURN_STRINGL(key, sizeof(key));
} /* }}} */

static zend_bool validate_pwvals(zend_long opsLimit, zend_long memLimit, zend_long threads) {
	if (opsLimit < 0) {
		php_error(E_RECOVERABLE_ERROR, "Invalid opsLimit: %ld", opsLimit);
		return 0;
	}
	if (memLimit < 0) {
		php_error(E_RECOVERABLE_ERROR, "Invalid memLimit: %ld", memLimit);
		return 0;
	}
	if ((threads < 0) || (threads > 255)) {
		php_error(E_RECOVERABLE_ERROR, "Invalid thread count: %ld", threads);
		return 0;
	}
	return 1;
}

/* {{{ proto string phydro_pwhash_deterministic(int $len, string $password, string $context, string $masterKey, int $opsLimit, int $memlimit, int $threads) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(pwhash_deterministic_arginfo, ZEND_RETURN_VALUE, 7, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO(0, len, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, password, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, context, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, masterKey, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, opsLimit, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, memLimit, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, threads, IS_LONG, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_pwhash_deterministic) {
	zend_long len, opsLimit, memLimit, threads;
	zend_string *password, *context, *key, *ret;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "lSSSlll", &len, &password, &context, &key, &opsLimit, &memLimit, &threads) == FAILURE) { return; }
	if (!validate(context, "Context", hydro_pwhash_CONTEXTBYTES) ||
		!validate(key, "Master key", hydro_pwhash_MASTERKEYBYTES) ||
		!validate_pwvals(opsLimit, memLimit, threads)) {
		return;
	}
	if (len <= 0) {
		php_error(E_RECOVERABLE_ERROR, "Invalid length: %ld", len);
		return;
	}
	ret = zend_string_alloc(len, 0);
	if (hydro_pwhash_deterministic(ZSTR_VAL(ret), ZSTR_LEN(ret), ZSTR_VAL(password), ZSTR_LEN(password),
	                               ZSTR_VAL(context), ZSTR_VAL(key), (uint64_t)opsLimit, (size_t)memLimit, (uint8_t)threads)) {
		php_error(E_RECOVERABLE_ERROR, "Failed creating deterministic password hash");
		return;
	}
	ZSTR_VAL(ret)[ZSTR_LEN(ret)] = 0;
	RETURN_NEW_STR(ret);
} /* }}} */

/* {{{ proto string phydro_pwhash_create(string $password, string $masterKey, int $opsLimit, int $memlimit, int $threads) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(pwhash_create_arginfo, ZEND_RETURN_VALUE, 5, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO(0, password, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, masterKey, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, opsLimit, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, memLimit, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, threads, IS_LONG, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_pwhash_create) {
	zend_string *password, *key;
	zend_long opsLimit, memLimit, threads;
	uint8_t stored[hydro_pwhash_STOREDBYTES];
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "SSlll", &password, &key, &opsLimit, &memLimit, &threads) == FAILURE) { return; }
	if (!validate(key, "Master key", hydro_pwhash_MASTERKEYBYTES) ||
		!validate_pwvals(opsLimit, memLimit, threads)) {
		return;
	}
	if (hydro_pwhash_create(stored, ZSTR_VAL(password), ZSTR_LEN(password),
	                        ZSTR_VAL(key), (uint64_t)opsLimit, (size_t)memLimit, (uint8_t)threads)) {
		php_error(E_RECOVERABLE_ERROR, "Failed creating password hash");
		return;
	}
	RETVAL_STRINGL(stored, sizeof(stored));
	hydro_memzero(stored, sizeof(stored));
} /* }}} */

/* {{{ proto bool phydro_pwhash_verify(string $subkey, string $masterKey, int $opsLimit, int $memlimit, int $threads) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(pwhash_verify_arginfo, ZEND_RETURN_VALUE, 6, _IS_BOOL, 1)
	ZEND_ARG_TYPE_INFO(0, subkey, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, password, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, masterKey, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, opsLimit, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, memLimit, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, threads, IS_LONG, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_pwhash_verify) {
	zend_string *subkey, *password, *key;
	zend_long opsLimit, memLimit, threads;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "SSSlll", &subkey, &password, &key, &opsLimit, &memLimit, &threads) == FAILURE) { return; }
	if (!validate(subkey, "Subkey", hydro_pwhash_STOREDBYTES) ||
		!validate(key, "Master key", hydro_pwhash_MASTERKEYBYTES) ||
		!validate_pwvals(opsLimit, memLimit, threads)) {
		return;
	}
	RETURN_BOOL(0 == hydro_pwhash_verify(ZSTR_VAL(subkey), ZSTR_VAL(password), ZSTR_LEN(password),
	                                     ZSTR_VAL(key), (uint64_t)opsLimit, (size_t)memLimit, (uint8_t)threads));
} /* }}} */

/* {{{ proto string phydro_pwhash_derive_static_key(int $len, string $subkey, string $password, string $context, string $masterKey, int $opsLimit, int $memlimit, int $threads) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(pwhash_derive_static_key_arginfo, ZEND_RETURN_VALUE, 8, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO(0, len, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, subkey, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, password, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, context, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, masterKey, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, opsLimit, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, memLimit, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, threads, IS_LONG, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_pwhash_derive_static_key) {
	zend_long len, opsLimit, memLimit, threads;
	zend_string *subkey, *password, *context, *key, *ret;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "lSSSSlll", &len, &subkey, &password, &context, &key, &opsLimit, &memLimit, &threads) == FAILURE) { return; }
	if (!validate(subkey, "Subkey", hydro_pwhash_STOREDBYTES) ||
		!validate(context, "Context", hydro_pwhash_CONTEXTBYTES) ||
		!validate(key, "Master key", hydro_pwhash_MASTERKEYBYTES) ||
		!validate_pwvals(opsLimit, memLimit, threads)) {
		return;
	}
	if (len <= 0) {
		php_error(E_RECOVERABLE_ERROR, "Invalid length: %ld", len);
		return;
	}
	ret = zend_string_alloc(len, 0);
	if (hydro_pwhash_derive_static_key(ZSTR_VAL(ret), ZSTR_LEN(ret), ZSTR_VAL(subkey), ZSTR_VAL(password), ZSTR_LEN(password),
	                                   ZSTR_VAL(context), ZSTR_VAL(key), (uint64_t)opsLimit, (size_t)memLimit, (uint8_t)threads)) {
		php_error(E_RECOVERABLE_ERROR, "Failed deriving static key");
		return;
	}
	ZSTR_VAL(ret)[ZSTR_LEN(ret)] = 0;
	RETURN_NEW_STR(ret);
} /* }}} */

/* {{{ proto string phydro_pwhash_reencrypt(string $subkey, string $oldmaster, string $newmaster) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(pwhash_reencrypt_arginfo, ZEND_RETURN_VALUE, 3, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO(0, subkey, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, oldmaster, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, newmaster, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_pwhash_reencrypt) {
	zend_string *subkey, *oldkey, *newkey;
	uint8_t       stored[hydro_pwhash_STOREDBYTES];
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "SSS", &subkey, &oldkey, &newkey) == FAILURE) { return; }
	if (!validate(subkey, "Subkey", hydro_pwhash_STOREDBYTES) ||
		!validate(oldkey, "Old master key", hydro_pwhash_MASTERKEYBYTES) ||
		!validate(newkey, "New master key", hydro_pwhash_MASTERKEYBYTES)) {
		return;
	}
	memcpy(stored, ZSTR_VAL(subkey), sizeof(stored));
	if (hydro_pwhash_reencrypt(stored, ZSTR_VAL(oldkey), ZSTR_VAL(newkey))) {
		hydro_memzero(stored, sizeof(stored));
		php_error(E_RECOVERABLE_ERROR, "Unable to reencrypt key");
		return;
	}
	RETVAL_STRINGL(stored, sizeof(stored));
	hydro_memzero(stored, sizeof(stored));
} /* }}} */

/* {{{ proto string phydro_pwhash_upgrade(string $subkey, string $masterKey, int $opsLimit, int $memlimit, int $threads) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(pwhash_upgrade_arginfo, ZEND_RETURN_VALUE, 5, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO(0, subkey, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, masterKey, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, opsLimit, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, memLimit, IS_LONG, 0)
	ZEND_ARG_TYPE_INFO(0, threads, IS_LONG, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_pwhash_upgrade) {
	zend_string *subkey, *key;
	zend_long opsLimit, memLimit, threads;
	uint8_t       stored[hydro_pwhash_STOREDBYTES];
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "SSlll", &subkey, &key, &opsLimit, &memLimit, &threads) == FAILURE) { return; }
	if (!validate(subkey, "Subkey", hydro_pwhash_STOREDBYTES) ||
		!validate(key, "Master key", hydro_pwhash_MASTERKEYBYTES) ||
		!validate_pwvals(opsLimit, memLimit, threads)) {
		return;
	}
	memcpy(stored, ZSTR_VAL(subkey), sizeof(stored));
	if (hydro_pwhash_upgrade(stored, ZSTR_VAL(key), (uint64_t)opsLimit, (size_t)memLimit, (uint8_t)threads)) {
		hydro_memzero(stored, sizeof(stored));
		php_error(E_RECOVERABLE_ERROR, "Unable to upgrade key");
		return;
	}
	RETVAL_STRINGL(stored, sizeof(stored));
	hydro_memzero(stored, sizeof(stored));
} /* }}} */

/*************************************************************************/
/* Misc */

/* {{{ proto bool phydro_equal(string $a, string $b) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(equal_arginfo, ZEND_RETURN_VALUE, 2, _IS_BOOL, 1)
	ZEND_ARG_TYPE_INFO(0, a, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, b, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_equal) {
	zend_string *a, *b;
	zend_long minlen;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "SS", &a, &b) == FAILURE) { return; }
	/* This API doesn't allow us to maintain constant time if lengths differ. :( */
	minlen = (ZSTR_LEN(a) < ZSTR_LEN(b)) ? ZSTR_LEN(a) : ZSTR_LEN(b);
	RETURN_BOOL(hydro_equal(ZSTR_VAL(a), ZSTR_VAL(b), minlen));
} /* }}} */

/* {{{ proto string phydro_bin2hex(string $str) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(bin2hex_arginfo, ZEND_RETURN_VALUE, 1, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO(0, str, IS_STRING, 0)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_bin2hex) {
	zend_string *in, *out;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "S", &in) == FAILURE) { return; }
	out = zend_string_alloc(2 * ZSTR_LEN(in), 0);
	if (!hydro_bin2hex(ZSTR_VAL(out), ZSTR_LEN(out) + 1, ZSTR_VAL(in), ZSTR_LEN(in))) {
		zend_string_release(out);
		php_error(E_RECOVERABLE_ERROR, "Failed encoding string to hex");
		return;
	}
	ZSTR_LEN(out) = strlen(ZSTR_VAL(out));
	RETURN_NEW_STR(out);
} /* }}} */

/* {{{ proto string phydro_hex2bin(strign $str[, ?string $ignore = null]) */
ZEND_BEGIN_ARG_WITH_RETURN_TYPE_INFO_EX(hex2bin_arginfo, ZEND_RETURN_VALUE, 1, IS_STRING, 1)
	ZEND_ARG_TYPE_INFO(0, str, IS_STRING, 0)
	ZEND_ARG_TYPE_INFO(0, ignore, IS_STRING, 1)
ZEND_END_ARG_INFO();
static PHP_FUNCTION(phydro_hex2bin) {
	zend_string *in, *ignore = NULL, *out;
	const char *end = NULL;
	if (zend_parse_parameters(ZEND_NUM_ARGS(), "S|P!", &in, &ignore) == FAILURE) { return; }
	out = zend_string_alloc((ZSTR_LEN(in) / 2) + 1, 0);
	ZSTR_LEN(out) = hydro_hex2bin(ZSTR_VAL(out), ZSTR_LEN(out) + 1, ZSTR_VAL(in), ZSTR_LEN(in), ignore ? ZSTR_VAL(ignore) : NULL, &end);
	if (ZSTR_LEN(out) == -1) {
		zend_string_release(out);
		php_error(E_RECOVERABLE_ERROR, "Failed decoding string from hex");
		return;
	}
	if (end && *end) {
		zend_string_release(out);
		php_error(E_RECOVERABLE_ERROR, "Non-hex encountered in input string");
		return;
	}
	ZSTR_VAL(out)[ZSTR_LEN(out)] = 0;
	RETURN_NEW_STR(out);
} /* }}} */

/*************************************************************************/

static zend_function_entry php_phydro_functions[] = {
	PHP_FE(phydro_random_u32, random_u32_arginfo)
	PHP_FE(phydro_random_uniform, random_uniform_arginfo)
	PHP_FE(phydro_random_buf, random_buf_arginfo)
	PHP_FE(phydro_random_ratchet, NULL)
	PHP_FE(phydro_random_reseed, NULL)

	PHP_FE(phydro_hash_keygen, hash_keygen_arginfo)
	PHP_FE(phydro_hash_init, hash_init_arginfo)
	PHP_FE(phydro_hash_update, hash_update_arginfo)
	PHP_FE(phydro_hash_final, hash_final_arginfo)
	PHP_FE(phydro_hash_hash, hash_hash_arginfo)

	PHP_FE(phydro_secretbox_keygen, box_keygen_arginfo)
	PHP_FE(phydro_secretbox_encrypt, box_encrypt_arginfo)
	PHP_FE(phydro_secretbox_decrypt, box_decrypt_arginfo)
	PHP_FE(phydro_secretbox_probe_create, box_probe_create_arginfo)
	PHP_FE(phydro_secretbox_probe_verify, box_probe_verify_arginfo)

	PHP_FE(phydro_kdf_keygen, kdf_keygen_arginfo)
	PHP_FE(phydro_kdf_derive_from_key, kdf_derive_from_key_arginfo)

	PHP_FE(phydro_sign_keygen, sign_keygen_arginfo)
	PHP_FE(phydro_sign_init, sign_init_arginfo)
	PHP_FE(phydro_sign_update, sign_update_arginfo)
	PHP_FE(phydro_sign_final_create, sign_final_create_arginfo)
	PHP_FE(phydro_sign_final_verify, sign_final_verify_arginfo)
	PHP_FE(phydro_sign_create, sign_create_arginfo)
	PHP_FE(phydro_sign_verify, sign_verify_arginfo)

	PHP_FE(phydro_kx_keygen, kx_keygen_arginfo)
	PHP_FE(phydro_kx_n_1, n1_arginfo)
	PHP_FE(phydro_kx_n_2, n2_arginfo)
	PHP_FE(phydro_kx_kk_1, kk1_arginfo)
	PHP_FE(phydro_kx_kk_2, kk2_arginfo)
	PHP_FE(phydro_kx_kk_3, kk3_arginfo)
	PHP_FE(phydro_kx_xx_1, xx1_arginfo)
	PHP_FE(phydro_kx_xx_2, xx2_arginfo)
	PHP_FE(phydro_kx_xx_3, xx3_arginfo)
	PHP_FE(phydro_kx_xx_4, xx4_arginfo)

	PHP_FE(phydro_pwhash_keygen, pwhash_keygen_arginfo)
	PHP_FE(phydro_pwhash_deterministic, pwhash_deterministic_arginfo)
	PHP_FE(phydro_pwhash_create, pwhash_create_arginfo)
	PHP_FE(phydro_pwhash_verify, pwhash_verify_arginfo)
	PHP_FE(phydro_pwhash_derive_static_key, pwhash_derive_static_key_arginfo)
	PHP_FE(phydro_pwhash_reencrypt, pwhash_reencrypt_arginfo)
	PHP_FE(phydro_pwhash_upgrade, pwhash_upgrade_arginfo)

	PHP_FE(phydro_equal, equal_arginfo)
	PHP_FE(phydro_bin2hex, bin2hex_arginfo)
	PHP_FE(phydro_hex2bin, hex2bin_arginfo)
	PHP_FE_END
};

/* {{{ PHP_MINI_FUNCTION */
PHP_MINIT_FUNCTION(phydro) {
	hydro_init();
	REGISTER_LONG_CONSTANT("PHYDRO_VERSION_MAJOR", HYDRO_VERSION_MAJOR, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_VERSION_MINOR", HYDRO_VERSION_MINOR, CONST_CS | CONST_PERSISTENT);

#ifdef HYDRO_HWTYPE
	REGISTER_LONG_CONSTANT("PHYDRO_HWTYPE", HYDRO_HWTYPE, CONST_CS | CONST_PERSISTENT);
#else
	REGISTER_NULL_CONSTANT("PHYDRO_HWTYPE", CONST_CS | CONST_PERSISTENT);
#endif
	REGISTER_LONG_CONSTANT("PHYDRO_HWTYPE_ATMEGA328", HYDRO_HWTYPE_ATMEGA328, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("PHYDRO_RANDOM_SEEDBYTES", hydro_random_SEEDBYTES, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("PHYDRO_HASH_BYTES", hydro_hash_BYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_HASH_BYTES_MIN", hydro_hash_BYTES_MIN, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_HASH_BYTES_MAX", hydro_hash_BYTES_MAX, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_HASH_CONTEXTBYTES", hydro_hash_CONTEXTBYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_HASH_KEYBYTES", hydro_hash_KEYBYTES, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("PHYDRO_SECRETBOX_CONTEXTBYTES", hydro_secretbox_CONTEXTBYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_SECRETBOX_HEADERBYTES", hydro_secretbox_HEADERBYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_SECRETBOX_KEYBYTES", hydro_secretbox_KEYBYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_SECRETBOX_PROBEBYTES", hydro_secretbox_PROBEBYTES, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("PHYDRO_KDF_BYTES_MIN", hydro_kdf_BYTES_MIN, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_KDF_BYTES_MAX", hydro_kdf_BYTES_MAX, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_KDF_CONTEXTBYTES", hydro_kdf_CONTEXTBYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_KDF_KEYBYTES", hydro_kdf_KEYBYTES, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("PHYDRO_SIGN_BYTES", hydro_sign_BYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_SIGN_CONTEXTBYTES", hydro_sign_CONTEXTBYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_SIGN_PUBLICKEYBYTES", hydro_sign_PUBLICKEYBYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_SIGN_SECRETKEYBYTES", hydro_sign_SECRETKEYBYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_SIGN_SEEDBYTES", hydro_sign_SEEDBYTES, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("PHYDRO_KX_SESSIONKEYBYTES", hydro_kx_SESSIONKEYBYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_KX_PUBLICKEYBYTES", hydro_kx_PUBLICKEYBYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_KX_SECRETKEYBYTES", hydro_kx_SECRETKEYBYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_KX_PSKBYTES", hydro_kx_PSKBYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_KX_SEEDBYTES", hydro_kx_SEEDBYTES, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("PHYDRO_KX_N_PACKET1BYTES", hydro_kx_N_PACKET1BYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_KX_KK_PACKET1BYTES", hydro_kx_KK_PACKET1BYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_KX_KK_PACKET2BYTES", hydro_kx_KK_PACKET2BYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_KX_XX_PACKET1BYTES", hydro_kx_XX_PACKET1BYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_KX_XX_PACKET2BYTES", hydro_kx_XX_PACKET2BYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_KX_XX_PACKET3BYTES", hydro_kx_XX_PACKET3BYTES, CONST_CS | CONST_PERSISTENT);

	REGISTER_LONG_CONSTANT("PHYDRO_PWHASH_CONTEXTBYTES", hydro_pwhash_CONTEXTBYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_PWHASH_MASTERKEYBYTES", hydro_pwhash_MASTERKEYBYTES, CONST_CS | CONST_PERSISTENT);
	REGISTER_LONG_CONSTANT("PHYDRO_PWHASH_STOREDBYTES", hydro_pwhash_STOREDBYTES, CONST_CS | CONST_PERSISTENT);

	return ((1 == 1)
			&& (PHP_MINIT(phydro_hash)(INIT_FUNC_ARGS_PASSTHRU) == SUCCESS)
			&& (PHP_MINIT(phydro_kx)(INIT_FUNC_ARGS_PASSTHRU) == SUCCESS)
			&& (PHP_MINIT(phydro_sign)(INIT_FUNC_ARGS_PASSTHRU) == SUCCESS)
			) ? SUCCESS : FAILURE;
} /* }}} */

/* {{{ PHP_MINFO_FUNCTION */
PHP_MINFO_FUNCTION(phydro) {
	char version[64];
	snprintf(version, sizeof(version), "%d.%d", HYDRO_VERSION_MAJOR, HYDRO_VERSION_MINOR);

	php_info_print_table_start();
	php_info_print_table_row(2, "phydro support", "enabled");
	php_info_print_table_row(2, "libhydrogen version", version);
	php_info_print_table_end();
} /* }}} */

/* {{{ hydro_module_entry
 */
zend_module_entry phydro_module_entry = {
	STANDARD_MODULE_HEADER,
	"phydro",
	php_phydro_functions,
	PHP_MINIT(phydro),
	NULL, /* MSHUTDOWN */
	NULL, /* RINIT */
	NULL, /* RSHUTDOWN */
	PHP_MINFO(phydro),
	"7.3.0-dev",
	STANDARD_MODULE_PROPERTIES
};
/* }}} */

#ifdef COMPILE_DL_PHYDRO
ZEND_GET_MODULE(phydro)
#endif

/*
 * Local variables:
 * tab-width: 4
 * c-basic-offset: 4
 * End:
 * vim600: noet sw=4 ts=4 fdm=marker
 * vim<600: noet sw=4 ts=4
 */
