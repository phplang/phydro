--TEST--
phydro_secretbox_*() functions
--SKIPIF--
<?php extension_loaded('phydro') || print 'skip';
--FILE--
<?php

$data = 'Lorem ipsum dolor';
$id = 1;
$context = str_repeat('a', PHYDRO_SECRETBOX_CONTEXTBYTES);
$key = phydro_secretbox_keygen();

$cipher = phydro_secretbox_encrypt($data, $id, $context, $key);
var_dump($cipher !== $data);

// Decrypts to original.
var_dump($data === phydro_secretbox_decrypt($cipher, $id, $context, $key));

// Probe verifies.
$probe = phydro_secretbox_probe_create($cipher, $context, $key);
var_dump(phydro_secretbox_probe_verify($probe, $cipher, $context, $key));

--EXPECT--
bool(true)
bool(true)
bool(true)
