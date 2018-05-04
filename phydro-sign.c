#include "phydro.h"

zend_class_entry *phydro_sign_ce;
static zend_object_handlers sign_handlers;

typedef struct _sign_object {
	hydro_sign_state state;
	zend_object std;
} sign_object;

static inline zend_object* sign_to_zend_object(sign_object *objval) {
	return ((zend_object*)(objval + 1)) - 1;
}

static inline sign_object* sign_from_zend_object(zend_object* objval) {
	return ((sign_object*)(objval + 1)) - 1;
}

static PHP_METHOD(PhydroSignState, __construct) {}
static zend_function_entry sign_methods[] = {
	// TODO: Give this an OOP API?
	PHP_ME(PhydroSignState, __construct, NULL, ZEND_ACC_PRIVATE | ZEND_ACC_CTOR)
	PHP_FE_END
};

static zend_object* sign_create(zend_class_entry* ce) {
	sign_object* object = ecalloc(1, sizeof(sign_object) + zend_object_properties_size(ce));
	zend_object* ret = sign_to_zend_object(object);
	zend_object_std_init(ret, ce);
	ret->handlers = &sign_handlers;
	object_properties_init(ret, ce);
	return ret;
}

static zend_object* sign_clone(zval *zobj) {
	sign_object* src = sign_from_zend_object(Z_OBJ_P(zobj));
	zend_object* ret = sign_create(Z_OBJCE_P(zobj));
	sign_object* dest = sign_from_zend_object(ret);
	zend_objects_clone_members(ret, Z_OBJ_P(zobj));
	memcpy(&(dest->state), &(src->state), sizeof(hydro_sign_state));
    return ret;
}

static void sign_free(zend_object *obj) {
	sign_object* objval = sign_from_zend_object(obj);
	hydro_memzero(&(objval->state), sizeof(hydro_sign_state));
	zend_object_std_dtor(obj);
}

zend_object* phydro_sign_init(zend_string *context) {
	zval tmp;
	sign_object *obj;
	object_init_ex(&tmp, phydro_sign_ce);
	obj = sign_from_zend_object(Z_OBJ(tmp));
	if (hydro_sign_init(&(obj->state), ZSTR_VAL(context))) {
		zval_dtor(&tmp);
		return NULL;
	}

	return Z_OBJ(tmp);
}

hydro_sign_state* phydro_sign_get_state(zend_object* zobj) {
	if (!instanceof_function(zobj->ce, phydro_sign_ce)) {
		return NULL;
	}
	return &(sign_from_zend_object(zobj)->state);
}

PHP_MINIT_FUNCTION(phydro_sign) {
	zend_class_entry ce;

	INIT_CLASS_ENTRY(ce, "PhydroSignState", sign_methods);
	phydro_sign_ce = zend_register_internal_class(&ce);
	phydro_sign_ce->create_object = sign_create;
	phydro_sign_ce->ce_flags |= ZEND_ACC_FINAL;

	memcpy(&sign_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	sign_handlers.offset = XtOffsetOf(sign_object, std);
	sign_handlers.clone_obj = sign_clone;
	sign_handlers.free_obj = sign_free;

	return SUCCESS;
}
