--TEST--
Crypto\Cipher::__callStatic basic usage.
--FILE--
<?php
// basic creation
$cipher = Crypto\Cipher::aes('256-cbc');
if ($cipher instanceof Crypto\Cipher)
	echo "FOUND\n";
// invalid creation
try {
	$cipher = new Crypto\Cipher('nnn');	
}
catch (Crypto\CipherException $e) {
	if ($e->getCode() === Crypto\CipherException::ALGORITHM_NOT_FOUND) {
		echo "NOT FOUND\n";
	}
}

$cipher = Crypto\Cipher::aes(Crypto\Cipher::MODE_CBC, 256);
echo $cipher->getAlgorithmName() . "\n";
$cipher = Crypto\Cipher::rc4();
echo $cipher->getAlgorithmName() . "\n";
$cipher = Crypto\Cipher::rc4("40");
echo $cipher->getAlgorithmName() . "\n";
$cipher = Crypto\Cipher::aes("cfb8", 128);
echo $cipher->getAlgorithmName() . "\n";

?>
--EXPECT--
FOUND
NOT FOUND
AES-256-CBC
RC4
RC4-40
AES-128-CFB8

