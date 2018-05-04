--TEST--
Phydro Signing
--SKIPIF--
<?php extension_loaded('phydro') || print 'skip';
--FILE--
<?php

$data = [
  'Lorem',
  'Ipsum',
  'Dolor',
];

[ 'pubkey' => $pk, 'seckey' => $sk ] = phydro_sign_keygen();
$context = str_repeat('x', PHYDRO_SIGN_CONTEXTBYTES);

// Sign
$state = phydro_sign_init($context);
foreach ($data as $word) {
  phydro_sign_update($state, $word);
}
$sig = phydro_sign_final_create($state, $sk);

// Verify
$state = phydro_sign_init($context);
foreach ($data as $word) {
  phydro_sign_update($state, $word);
}
var_dump(phydro_sign_final_verify($state, $sig, $pk));

// Simple API
$words = implode('', $data);
var_dump(phydro_sign_verify($words, $sig, $context, $pk));

$sig = phydro_sign_create($words, $context, $sk);
var_dump(phydro_sign_verify($words, $sig, $context, $pk));

$badsig = substr($sig, 1) . $sig[0];
var_dump(phydro_sign_verify($words, $badsig, $context, $pk));


--EXPECT--
bool(true)
bool(true)
bool(true)
bool(false)
