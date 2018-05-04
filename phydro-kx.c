#include "phydro.h"

zend_class_entry *phydro_kx_ce;
static zend_object_handlers kx_handlers;

typedef struct _kx_object {
	hydro_kx_state state;
	zend_object std;
} kx_object;

static inline zend_object* kx_to_zend_object(kx_object *objval) {
	return ((zend_object*)(objval + 1)) - 1;
}

static inline kx_object* kx_from_zend_object(zend_object* objval) {
	return ((kx_object*)(objval + 1)) - 1;
}

static PHP_METHOD(PhydroKXState, __construct) {}
static zend_function_entry kx_methods[] = {
	// TODO: Give this an OOP API?
	PHP_ME(PhydroKXState, __construct, NULL, ZEND_ACC_PRIVATE | ZEND_ACC_CTOR)
	PHP_FE_END
};

static zend_object* kx_create(zend_class_entry* ce) {
	kx_object* object = ecalloc(1, sizeof(kx_object) + zend_object_properties_size(ce));
	zend_object* ret = kx_to_zend_object(object);
	zend_object_std_init(ret, ce);
	ret->handlers = &kx_handlers;
	object_properties_init(ret, ce);
	return ret;
}

static zend_object* kx_clone(zval *zobj) {
	kx_object* src = kx_from_zend_object(Z_OBJ_P(zobj));
	zend_object* ret = kx_create(Z_OBJCE_P(zobj));
	kx_object* dest = kx_from_zend_object(ret);
	zend_objects_clone_members(ret, Z_OBJ_P(zobj));
	memcpy(&(dest->state), &(src->state), sizeof(hydro_kx_state));
    return ret;
}

static void kx_free(zend_object *obj) {
	kx_object* objval = kx_from_zend_object(obj);
	hydro_memzero(&(objval->state), sizeof(hydro_kx_state));
	zend_object_std_dtor(obj);
}

zend_object* phydro_kx_state_init(hydro_kx_state *state) {
	zval tmp;
	kx_object *obj;
	object_init_ex(&tmp, phydro_kx_ce);
	obj = kx_from_zend_object(Z_OBJ(tmp));
	memcpy(&(obj->state), state, sizeof(obj->state));
	return Z_OBJ(tmp);
}

hydro_kx_state* phydro_kx_get_state(zend_object* zobj) {
	if (!instanceof_function(zobj->ce, phydro_kx_ce)) {
		return NULL;
	}
	return &(kx_from_zend_object(zobj)->state);
}

PHP_MINIT_FUNCTION(phydro_kx) {
	zend_class_entry ce;

	INIT_CLASS_ENTRY(ce, "PhydroKXState", kx_methods);
	phydro_kx_ce = zend_register_internal_class(&ce);
	phydro_kx_ce->create_object = kx_create;
	phydro_kx_ce->ce_flags |= ZEND_ACC_FINAL;

	memcpy(&kx_handlers, zend_get_std_object_handlers(), sizeof(zend_object_handlers));
	kx_handlers.offset = XtOffsetOf(kx_object, std);
	kx_handlers.clone_obj = kx_clone;
	kx_handlers.free_obj = kx_free;

	return SUCCESS;
}
