--TEST--
Crypto\PBKDF2::getHashAlgorithm basic usage.
--SKIPIF--
<?php if (!class_exists('Crypto\PBKDF2')) die("Skip: PBKDF2 is not supported (update OpenSSL version)"); ?>
--FILE--
<?php
$pbkdf2 = new Crypto\PBKDF2('sha256', 32);
echo $pbkdf2->getHashAlgorithm() . "\n";
?>
--EXPECT--
SHA256
