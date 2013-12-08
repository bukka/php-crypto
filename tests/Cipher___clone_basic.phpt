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
echo bin2hex($cipher->encryptFinish()) . "\n";

$cipher_clone->encryptUpdate($data2);
echo bin2hex($cipher_clone->encryptFinish()) . "\n";

echo "SUCCESS\n";
?>
--EXPECT--
AES-256-CBC
247d77ff0e6a8b2852f3d12072cab915
247d77ff0e6a8b2852f3d12072cab915
SUCCESS


