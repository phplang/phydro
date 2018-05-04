--TEST--
phydro key exchange KK protocol
--SKIPIF--
<?php extension_loaded('phydro') || print 'skip';
--FILE--
<?php

$seed = str_repeat('a', PHYDRO_KX_SEEDBYTES);
[ $server_pk, $server_sk ] = phydro_kx_keygen($seed);
[ $client_pk, $client_sk ] = phydro_kx_keygen();
[ $packet1, $state ] = phydro_kx_kk_1($server_pk, $client_pk, $client_sk);
var_dump(get_class($state));

[ $packet2, [ $server_tx, $server_rx ] ] = phydro_kx_kk_2($packet1, $client_pk, $server_pk, $server_sk);
[ $client_tx, $client_rx ] = phydro_kx_kk_3($state, $packet2, $server_pk);

var_dump($server_tx == $client_rx);
var_dump($server_rx == $client_tx);
--EXPECT--
string(13) "PhydroKXState"
bool(true)
bool(true)
