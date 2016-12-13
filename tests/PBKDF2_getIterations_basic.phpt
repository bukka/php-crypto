--TEST--
Crypto\PBKDF2::getIterations basic usage.
--SKIPIF--
<?php if (!class_exists('Crypto\PBKDF2')) die("Skip: PBKDF2 is not supported (update OpenSSL version)"); ?>
--FILE--
<?php
$pbkdf2 = new Crypto\PBKDF2('sha256', 32, 'salt', 900);
var_dump($pbkdf2->getIterations());
?>
--EXPECT--
int(900)
