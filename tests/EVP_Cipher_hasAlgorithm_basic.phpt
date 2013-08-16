--TEST--
Crypto\EVP\Cipher::hasAlogirthm basic usage.
--FILE--
<?php
echo Crypto\EVP\Cipher::hasAlgorithm('nnnn') ? "nnnn\n" : "";
// the following algorigthms should exists on any platform
echo Crypto\EVP\Cipher::hasAlgorithm('aes-256-ctr') ? "HAS aes-256-ctr\n" : "";
echo Crypto\EVP\Cipher::hasAlgorithm('aes-256-cbc') ? "HAS aes-256-cbc\n" : "";
?>
--EXPECT--
HAS aes-256-ctr
HAS aes-256-cbc