--TEST--
Crypto\PBKDF2::setIterations basic usage.
--FILE--
<?php
$pbkdf2 = new Crypto\PBKDF2('sha256', 32);
$pbkdf2->setIterations(800);
var_dump($pbkdf2->getIterations());
?>
--EXPECT--
int(800)
