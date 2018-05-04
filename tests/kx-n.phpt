--TEST--
phydro key exchange N protocol
--SKIPIF--
<?php extension_loaded('phydro') || print 'skip';
--FILE--
<?php

$seed = str_repeat('a', PHYDRO_KX_SEEDBYTES);
$psk = str_repeat('b', PHYDRO_KX_PSKBYTES);
[ 'pubkey' => $pk, 'seckey' => $sk ] = phydro_kx_keygen($seed);
[ 'packet' => $packet, 'keys' => [ 'tx' => $tx, 'rx' => $rx ] ] = phydro_kx_n_1($psk, $pk);

[ 'tx' => $tx2, 'rx' => $rx2 ] = phydro_kx_n_2($packet, $psk, $pk, $sk);
var_dump($tx == $rx2);
var_dump($rx == $tx2);
--EXPECT--
bool(true)
bool(true)
