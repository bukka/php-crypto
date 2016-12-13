--TEST--
Crypto\PBKDF2::setIterations basic usage.
--SKIPIF--
<?php if (!class_exists('Crypto\PBKDF2')) die("Skip: PBKDF2 is not supported (update OpenSSL version)"); ?>
--FILE--
<?php
$pbkdf2 = new Crypto\PBKDF2('sha256', 32);
$pbkdf2->setIterations(800);
var_dump($pbkdf2->getIterations());
?>
--EXPECT--
int(800)
