--TEST--
phydro_random_ratchet and phydro_random_reseed
--SKIPIF--
<?php extension_loaded('phydro') || print 'skip';
--FILE--
<?php

// Just test that they run.
// They don't take args, and don't return a value.
phydro_random_ratchet();
phydro_random_reseed();
echo "DONE\n";
--EXPECT--
DONE
