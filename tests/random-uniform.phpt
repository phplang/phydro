--TEST--
phydro_random_uniform
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
phydro_random_uniform(-1);
phydro_random_uniform(0);
phydro_random_uniform(1);
phydro_random_uniform(0x100000000);

// Working cases
phydro_random_uniform(2);
for ($i = 0; $i < 1000; ++$i) {
  $x = phydro_random_uniform(1000);
  if (($x < 0) || ($x >= 1000)) {
      var_dump($x);
  }
}
echo "DONE\n";
var_dump($i);
--EXPECT--
Error: Upper bound -1 overflows libhydrogen's uint32_t limit
Error: Invalid upper bound 0, this will always result in zero
Error: Invalid upper bound 1, this will always result in zero
Error: Upper bound 4294967296 overflows libhydrogen's uint32_t limit
DONE
int(1000)
