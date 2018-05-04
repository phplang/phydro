--TEST--
phydro miscellaneous functions
--SKIPIF--
<?php extension_loaded('phydro') || print 'skip';
--FILE--
<?php

// libhydrogen and PHP are both clever here (perhaps too clever).
// If libhydrogen gets the same cstring pointer, it will return false
// on the grounds that "the comparison was probably made in error".
// Meanwhile PHP will go out of its way to make sure the same
// buffer gets reused for the same script string.
// Do an optimizer breaking increment to confuse PHP.
$hello = "helln";
$hello++;
$hello = ucfirst($hello);

var_dump(phydro_equal("Hello", $hello));
var_dump(phydro_equal("Hello", "World"));

var_dump(phydro_bin2hex("Hello World"));
var_dump(phydro_hex2bin("48656c6c6f20576f726c64"));
var_dump(phydro_hex2bin("48 65 6c 6c 6f 20 57 6f 72 6c 64", ' '));
--EXPECT--
bool(true)
bool(false)
string(22) "48656c6c6f20576f726c64"
string(11) "Hello World"
string(11) "Hello World"
