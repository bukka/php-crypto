--TEST--
Crypto\PBKDF2::getIterations basic usage.
--FILE--
<?php
$pbkdf2 = new Crypto\PBKDF2('sha256', 'salt', 900);
var_dump($pbkdf2->getIterations());
?>
--EXPECT--
int(900)
