#include "phydro.h"

zend_class_entry *phydro_hash_ce;
static zend_object_handlers hash_handlers;

typedef struct _hash_object {
	hydro_hash_state state;
	zend_object std;
} hash_object;

static inline zend_object* hash_to_zend_object(hash_object *objval) {
	return ((zend_object*)(objval + 1)) - 1;
}

static inline hash_object* hash_from_zend_object(zend_object* objval) {
	return ((hash_object*)(objval + 1)) - 1;
}

static PHP_METHOD(PhydroHash, __construct) {}
static zend_function_entry hash_methods[] = {
	// TODO: Give this an OOP API?
	PHP_ME(PhydroHash, __construct, NULL, ZEND_ACC_PRIVATE | ZEND_ACC_CTOR)
	PHP_FE_END
};

static zend_object* hash_create(zend_class_entry* ce) {
	hash_object* object = ecalloc(1, sizeof(hash_object) + zend_object_properties_size(ce));
	zend_object* ret = hash_to_zend_object(object);
	zend_object_std_init(ret, ce);
	ret->handlers = &hash_handlers;
	object_properties_init(ret, ce);
	return ret;
}

static zend_object* hash_clone(zval *zobj) {
	hash_object* src = hash_from_zend_object(Z_OBJ_P(zobj));
	zend_object* ret = hash_create(Z_OBJCE_P(zobj));
	hash_object* dest = hash_from_zend_object(ret);
	zend_objects_clone_members(ret, Z_OBJ_P(zobj));
	memcpy(&(dest->state), &(src->state), sizeof(hydro_hash_state));
    return ret;
}

static void hash_free(zend_object *obj) {
	hash_object* objval = hash_from_zend_object(obj);
	hydro_memzero(&(objval->state), sizeof(hydro_hash_state));
	zend_object_std_dtor(obj);
}

zend_object* phydro_hash_init(zend_string *context, zend_string *key) {
	zval tmp;
	hash_object *obj;
	object_init_ex(&tmp, phydro_hash_ce);
	obj = hash_from_zend_object(Z_OBJ(tmp));
	if (hydro_hash_init(&(obj->state), ZSTR_VAL(context), ZSTR_VAL(key))) {
		zval_dtor(&tmp);
		return NULL;
	}

	return Z_OBJ(tmp);
}

hydro_hash_state* phydro_hash_get_state(zend_object* zobj) {
	if (!instanceof_function(zobj->ce, phydro_hash_ce)) {
		return NULL;
	}
	return &(hash_from_zend_object(zobj)->state);
}

PHP_MINIT_FUNCTION(phydro_hash) {
	zend_class_entry ce;

	INIT_CLASS_ENTRY(ce, "PhydroHash", hash_methods);
	phydro_hash_ce = zend_register_internal_class(&ce);
	phydro_hash_ce->create_object = hash_create;
	phydro_hash_ce->ce_flags |= ZEND_ACC_FINAL;

	memcpy(&hash_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	hash_handlers.offset = XtOffsetOf(hash_object, std);
	hash_handlers.clone_obj = hash_clone;
	hash_handlers.free_obj = hash_free;

	return SUCCESS;
}
