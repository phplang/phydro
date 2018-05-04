--TEST--
phydro_random_buf
--SKIPIF--
<?php extension_loaded('phydro') || print 'skip';
--FILE--
<?php

// Demote recoverable errors to warnigns.
set_error_handler(function($errno, $errstr) {
  echo "Error: $errstr\n";
  return true;
}, E_RECOVERABLE_ERROR);

// Error cases
phydro_random_buf(10, '');
phydro_random_buf(10, str_repeat('a', PHYDRO_RANDOM_SEEDBYTES - 1));
phydro_random_buf(10, str_repeat('a', PHYDRO_RANDOM_SEEDBYTES + 1));

// Working cases
var_dump(strlen(phydro_random_buf(10)) === 10);
var_dump(bin2hex(phydro_random_buf(10, str_repeat('a', PHYDRO_RANDOM_SEEDBYTES))));

for ($i = 0; $i < 1000; ++$i) {
  $x = phydro_random_buf($i);
  if (strlen($x) !== $i) {
      var_dump($i, $x);
  }
}
echo "DONE\n";
var_dump($i);
--EXPECT--
Error: Seed must be precisely 32 bytes long
Error: Seed must be precisely 32 bytes long
Error: Seed must be precisely 32 bytes long
bool(true)
string(20) "471ba1606424c1c058f0"
DONE
int(1000)
