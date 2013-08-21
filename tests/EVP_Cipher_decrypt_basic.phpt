--TEST--
Crypto\EVP\Cipher::decrypt basic usage.
--FILE--
<?php
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);

$ciphertext = base64_decode('j4hToWhWBxM8ue4Px6W4pXEDk1y8OepoDe8NsHZ+lU4=');

$cipher = new Crypto\EVP\Cipher('aes-256-cbc');

// init first
echo $cipher->decrypt($ciphertext, $key, $iv) . "\n";

?>
--EXPECT--
aaaaaaaaaaaaaaaa
