#include "php_phydro.h"
#include "hydrogen.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

PHP_MINIT_FUNCTION(phydro_hash);
extern zend_class_entry *phydro_hash_ce;
hydro_hash_state* phydro_hash_get_state(zend_object* zobj);
zend_object* phydro_hash_init(zend_string *context, zend_string *key);

PHP_MINIT_FUNCTION(phydro_kx);
extern zend_class_entry *phydro_kx_ce;
hydro_kx_state* phydro_kx_get_state(zend_object* zobj);
zend_object* phydro_kx_state_init(hydro_kx_state* state);

PHP_MINIT_FUNCTION(phydro_sign);
extern zend_class_entry *phydro_sign_ce;
hydro_sign_state* phydro_sign_get_state(zend_object* zobj);
zend_object* phydro_sign_init(zend_string *context);

