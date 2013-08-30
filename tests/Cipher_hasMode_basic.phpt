--TEST--
Crypto\Cipher::hasMode basic usage.
--FILE--
<?php
// this value is defined for flag EVP_CIPH_VARIABLE_LENGTH which is not mode 
echo Crypto\Cipher::hasMode(8) ? "" : "NOT DEFINED\n";
// the CBC mode exists on any supported OpenSSL version
echo Crypto\Cipher::hasMode(Crypto\Cipher::MODE_CBC) ? "CBC\n" : "";
?>
--EXPECT--
NOT DEFINED
CBC
