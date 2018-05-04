--TEST--
phydro key exchange XX protocol
--SKIPIF--
<?php extension_loaded('phydro') || print 'skip';
--FILE--
<?php

$seed = str_repeat('a', PHYDRO_KX_SEEDBYTES);
[ 'pubkey' => $server_pk, 'seckey' => $server_sk ] = phydro_kx_keygen($seed);
[ 'pubkey' => $client_pk, 'seckey' => $client_sk ] = phydro_kx_keygen();
$psk = str_repeat('b',PHYDRO_KX_PSKBYTES);

[ 'packet' => $packet1, 'state' => $client_state ] = phydro_kx_xx_1($psk);
var_dump(get_class($client_state));

[ 'packet' => $packet2, 'state' => $server_state ] = phydro_kx_xx_2($packet1, $psk, $server_pk, $server_sk);
var_dump(get_class($server_state));

[ 'packet' => $packet3, 'keys' => [ 'tx' => $client_tx, 'rx' => $client_rx ], 'peer' => $client_peer ] = phydro_kx_xx_3($client_state, $packet2, $psk, $client_pk,$client_sk);
var_dump($client_peer === $server_pk);

[ 'keys' => [ 'tx' => $server_tx, 'rx' => $server_rx ], 'peer' => $server_peer ] = phydro_kx_xx_4($server_state, $packet3, $psk);
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
