--TEST--
Crypto\Cipher::hasAlgorithm basic usage.
--FILE--
<?php
echo Crypto\Cipher::hasAlgorithm('nnnn') ? "nnnn\n" : "";
// the following algorigthms should exists on any platform
echo Crypto\Cipher::hasAlgorithm('aes-256-cbc') ? "HAS aes-256-cbc\n" : "";
?>
--EXPECT--
HAS aes-256-cbc