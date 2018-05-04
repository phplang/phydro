--TEST--
hydro_random_u32
--SKIPIF--
<?php extension_loaded('phydro') || print 'skip';
--FILE--
<?php

for ($i = 0; $i < 1000; ++$i) {
  $x = phydro_random_u32();
  if (($x < 0) || ($x > 0xFFFFFFFF)) {
      var_dump($x);
  }
}
echo "DONE\n";
var_dump($i);
--EXPECT--
DONE
int(1000)
