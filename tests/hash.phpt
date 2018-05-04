--TEST--
phydro_hash API
--SKIPIF--
<?php extension_loaded('phydro') || print 'skip';
--FILE--
<?php

$data = 'Lorem ipsum dolor';
$len = PHYDRO_HASH_BYTES;
$key = phydro_hash_keygen();
$key2 = phydro_hash_keygen();
$context = phydro_random_buf(PHYDRO_HASH_CONTEXTBYTES);
$context2 = phydro_random_buf(PHYDRO_HASH_CONTEXTBYTES);

// Changing context changes output.
var_dump(phydro_hash_hash($data, $len, $context, $key) !== phydro_hash_hash($data, $len, $context2, $key));

// Changing key changes output.
var_dump(phydro_hash_hash($data, $len, $context, $key) !== phydro_hash_hash($data, $len, $context, $key2));

// Changing data changes output.
var_dump(phydro_hash_hash($data, $len, $context, $key) !== phydro_hash_hash($data.'x', $len, $context, $key));

// Hash is deterministic.
var_dump(phydro_hash_hash($data, $len, $context, $key) === phydro_hash_hash($data, $len, $context, $key));

// Hash length is correct.
var_dump(strlen(phydro_hash_hash($data, $len, $context, $key)) === $len);

// Extended API.
$hash = phydro_hash_init($context, $key);
var_dump(get_class($hash));
var_dump($hash instanceof \PhydroHash);
var_dump(phydro_hash_update($hash, $data));
var_dump(strlen(phydro_hash_final($hash, $len)) === $len);

--EXPECT--
bool(true)
bool(true)
bool(true)
bool(true)
bool(true)
string(10) "PhydroHash"
bool(true)
bool(true)
bool(true)
