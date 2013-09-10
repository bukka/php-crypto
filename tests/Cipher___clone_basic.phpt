--TEST--
Crypto\Cipher::__clone basic usage.
--FILE--
<?php
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);
$data1 = str_repeat('a', 16);
$data2 = str_repeat('b', 16);

// basic creation
$cipher = new Crypto\Cipher('aes-256-cbc');
$cipher->encryptInit($key, $iv);
$cipher->encryptUpdate($data1);
$cipher_clone = clone $cipher;
echo $cipher_clone->getAlgorithmName() . "\n";

$cipher->encryptUpdate($data2);
echo base64_encode($cipher->encryptFinal()) . "\n";

$cipher_clone->encryptUpdate($data2);
echo base64_encode($cipher_clone->encryptFinal()) . "\n";

echo "SUCCESS\n";
?>
--EXPECT--
aes-256-cbc
JH13/w5qiyhS89Egcsq5FQ==
JH13/w5qiyhS89Egcsq5FQ==
SUCCESS


