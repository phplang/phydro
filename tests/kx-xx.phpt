--TEST--
phydro key exchange XX protocol
--SKIPIF--
<?php extension_loaded('phydro') || print 'skip';
--FILE--
<?php

$seed = str_repeat('a', PHYDRO_KX_SEEDBYTES);
[ $server_pk, $server_sk ] = phydro_kx_keygen($seed);
[ $client_pk, $client_sk ] = phydro_kx_keygen();
$psk = str_repeat('b',PHYDRO_KX_PSKBYTES);

[ $packet1, $client_state ] = phydro_kx_xx_1($psk);
var_dump(get_class($client_state));

[ $packet2, $server_state ] = phydro_kx_xx_2($packet1, $psk, $server_pk, $server_sk);
var_dump(get_class($server_state));

[ $packet3, [ $client_tx, $client_rx ], $client_peer ] = phydro_kx_xx_3($client_state, $packet2, $psk, $client_pk,$client_sk);
var_dump($client_peer === $server_pk);

[ [ $server_tx, $server_rx ], $server_peer ] = phydro_kx_xx_4($server_state, $packet3, $psk);
var_dump($server_peer === $client_pk);

var_dump($server_tx == $client_rx);
var_dump($server_rx == $client_tx);
--EXPECT--
string(13) "PhydroKXState"
string(13) "PhydroKXState"
bool(true)
bool(true)
bool(true)
bool(true)
