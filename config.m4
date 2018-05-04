dnl config.m4 for extension hydro

PHP_ARG_WITH(phydro, whether to enable libhydrogen support,
[  --without-phydro=[DIR]   Disable libhydrogen support], yes)

if test "$PHP_PHYDRO" != "no"; then
  dnl Header
  AC_MSG_CHECKING(for hydrogen.h)
  for i in $PHP_PHYDRO /usr/local /usr /opt; do
    if test -f $i/hydrogen.h; then
      HYDROGEN_INCLUDE=$i
      break
    elif test -f $i/include/hydrogen.h; then
      HYDROGEN_INCLUDE=$i/include
      break
    fi
  done
  if test -z "$HYDROGEN_INCLUDE"; then
    AC_MSG_ERROR(not found)
  fi
  PHP_ADD_INCLUDE($HYDROGEN_INCLUDE)

  dnl Source
  AC_MSG_CHECKING(for libhydrogen.a or hydrogen.c)
  if test -f "$HYDROGEN_INCLUDE/hydrogen.c"; then
    HYDROGEN_SOURCE="$HYDROGEN_INCLUDE/hydrogen.c"
  elif test -f "$HYDROGEN_INCLUDE/libhydrogen.a"; then
    PHP_ADD_LIBPATH($HYDROGEN_INCLUDE, PHYDRO_SHARED_LIBADD)
    PHP_ADD_LIBRARY(hydrogen,, PHYDRO_SHARED_LIBADD)
  elif test -f "$HYDROGEN_INCLUDE/../$PHP_LIBDIR/libhydrogen.a"; then
    PHP_ADD_LIBPATH($HYDROGEN_INCLUDE/../$PHP_LIBDIR, PHYDRO_SHARED_LIBADD)
    PHP_ADD_LIBRARY(hydrogen,, PHYDRO_SHARED_LIBADD)
  else
    AC_MSG_ERROR(not found)
  fi

  PHP_NEW_EXTENSION(phydro, $HYDROGEN_SOURCE phydro.c phydro-hash.c phydro-kx.c, $ext_shared)
  PHP_SUBST(PHYDRO_SHARED_LIBADD)
fi
