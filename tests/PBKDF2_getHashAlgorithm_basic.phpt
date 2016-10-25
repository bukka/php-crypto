--TEST--
Crypto\PBKDF2::getHashAlgorithm basic usage.
--FILE--
<?php
$pbkdf2 = new Crypto\PBKDF2('sha256');
echo $pbkdf2->getHashAlgorithm() . "\n";
?>
--EXPECT--
SHA256
