--TEST--
Crypto\EVP\Cipher::hasAlogirthm basic usage.
--FILE--
<?php
var_dump(Crypto\EVP\Cipher::hasAlgorithm('nnnn'));
// the following algorigthms should exists on any platform
var_dump(Crypto\EVP\Cipher::hasAlgorithm('aes-256-ctr'));
var_dump(Crypto\EVP\Cipher::hasAlgorithm('aes-256-cbc'));
?>
--EXPECTF--
bool(false)
bool(true)
bool(true)