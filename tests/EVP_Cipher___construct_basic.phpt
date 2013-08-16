--TEST--
Crypto\EVP\Cipher::__construct basic usage.
--SKIPIF--
<?php if (!Crypto\EVP\Cipher::hasAlgorithm('aes-256-cbc')) die("Skip: aes-256-cbc is not supported"); ?>
--FILE--
<?php
// basic creation
$cipher = new Crypto\EVP\Cipher('aes-256-cbc');
if ($cipher instanceof Crypto\EVP\Cipher)
	echo "Correct algorithm\n";
// invalid creation
try {
	$cipher = new Crypto\EVP\Cipher('nnn');	
}
catch (Crypto\EVP\AlgorithmException $e) {
	echo "Invalid algorithm\n";
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
Correct algorithm
Invalid algorithm
aes-256-cbc
