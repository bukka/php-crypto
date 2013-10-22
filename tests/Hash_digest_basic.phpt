--TEST--
Crypto\Hash::digest basic usage.
--FILE--
<?php
$hash = new Crypto\Hash('sha256');
$hash->update('data1data2');
echo bin2hex($hash->digest()) . "\n";
echo "SUCCESS\n";
?>
--EXPECT--
53ddc03623f867c7d4a631ded19c2613f2cb61d47b6aa214f47ff3cc15445bcd
SUCCESS