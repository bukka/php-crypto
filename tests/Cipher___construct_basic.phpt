--TEST--
Crypto\Cipher::__construct basic usage.
--FILE--
<?php
// basic creation
$cipher = new Crypto\Cipher('aes-256-cbc');
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

$cipher = new Crypto\Cipher('aes', Crypto\Cipher::MODE_CBC, 256);
echo $cipher->getAlgorithmName() . "\n";
$cipher = new Crypto\Cipher('RC4');
echo $cipher->getAlgorithmName() . "\n";
$cipher = new Crypto\Cipher('RC4', "40");
echo $cipher->getAlgorithmName() . "\n";
$cipher = new Crypto\Cipher('aes', "cfb8", 128);
echo $cipher->getAlgorithmName() . "\n";

// sub classing
class SubCipher extends Crypto\Cipher {
	function __construct($algorithm, $mode = null, $key_size = null) {
		parent::__construct($algorithm, $mode, $key_size);
		echo $this->algorithm . "\n";
	}
}
$subcipher = new SubCipher('aes-256-cbc');
$subcipher = new SubCipher('aes', Crypto\Cipher::MODE_CBC, 256);
?>
--EXPECT--
FOUND
NOT FOUND
AES-256-CBC
RC4
RC4-40
AES-128-CFB8
AES-256-CBC
AES-256-CBC

