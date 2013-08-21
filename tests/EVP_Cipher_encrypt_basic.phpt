--TEST--
Crypto\EVP\Cipher::encrypt basic usage.
--FILE--
<?php
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);

$data = str_repeat('a', 16);

$cipher = new Crypto\EVP\Cipher('aes-256-cbc');

// init first
echo base64_encode($cipher->encrypt($data, $key, $iv)) . "\n";

?>
--EXPECT--
j4hToWhWBxM8ue4Px6W4pXEDk1y8OepoDe8NsHZ+lU4=
