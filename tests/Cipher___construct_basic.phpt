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
catch (Crypto\AlgorithmException $e) {
	if ($e->getCode() === Crypto\AlgorithmException::CIPHER_NOT_FOUND) {
		echo "NOT FOUND\n";
	}
}
// sub classing
class SubCipher extends Crypto\Cipher {
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
