--TEST--
Crypto\EVP\Cipher::__construct basic usage.
--FILE--
<?php
// basic creation
$cipher = new Crypto\EVP\Cipher('aes-256-cbc');
if ($cipher instanceof Crypto\EVP\Cipher)
	echo "FOUND\n";
// invalid creation
try {
	$cipher = new Crypto\EVP\Cipher('nnn');	
}
catch (Crypto\EVP\AlgorithmException $e) {
	if ($e->getCode() === Crypto\EVP\AlgorithmException::CIPHER_NOT_FOUND) {
		echo "NOT FOUND\n";
	}
}
// sub classing
class SubCipher extends Crypto\EVP\Cipher {
	function __construct($algorithm) {
		parent::__construct($algorithm);
		echo $this->algorithm . "\n";
	}
}
$subcipher = new SubCipher('aes-256-cbc');
?>
--EXPECT--
FOUND
NOT FOUND
aes-256-cbc
