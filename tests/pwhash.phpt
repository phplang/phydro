--TEST--
Phydro pwhash tests
--SKIPIF--
<?php extension_loaded('phydro') || print 'skip';
--FILE--
<?php declare(strict_types=1);

$key = phydro_pwhash_keygen();
$fixed_key = str_repeat('x', PHYDRO_PWHASH_MASTERKEYBYTES);
$password = 'secret';
$context = str_repeat('w', PHYDRO_PWHASH_CONTEXTBYTES);
$opsLimit = 10000;
$memLimit = 0;
$threads = 3;

// Fixed key, deterministic result.
var_dump(bin2hex(phydro_pwhash_deterministic(24, $password, $context, $fixed_key, $opsLimit, $memLimit, $threads)));

$subkey = phydro_pwhash_create($password, $key, $opsLimit, $memLimit, $threads);
var_dump(phydro_pwhash_verify($subkey, $password, $key, $opsLimit, $memLimit, $threads));
var_dump(phydro_pwhash_verify($subkey, strrev($password), $key, $opsLimit, $memLimit, $threads));

$subkey = phydro_pwhash_reencrypt($subkey, $key, $fixed_key);
var_dump(phydro_pwhash_verify($subkey, $password, $key, $opsLimit, $memLimit, $threads));
var_dump(phydro_pwhash_verify($subkey, $password, $fixed_key, $opsLimit, $memLimit, $threads));

$subkey = phydro_pwhash_upgrade($subkey, $fixed_key, $opsLimit * 2, $memLimit, $threads);
var_dump(phydro_pwhash_verify($subkey, $password, $fixed_key, $opsLimit, $memLimit, $threads));
$opsLimit *= 2;
var_dump(phydro_pwhash_verify($subkey, $password, $fixed_key, $opsLimit, $memLimit, $threads));


--EXPECT--
string(48) "1aab89465e4c8dc318c0514ae353b6eafc207feaa952b533"
bool(true)
bool(false)
bool(false)
bool(true)
bool(false)
bool(true)
