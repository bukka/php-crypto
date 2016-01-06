--TEST--
Crypto\Hash::__construct basic usage.
--FILE--
<?php
// basic creation
$hash = new Crypto\Hash('sha256');
if ($hash instanceof Crypto\Hash)
	echo "FOUND\n";
// invalid creation
try {
	$hash = new Crypto\Hash('nnn');	
}
catch (Crypto\HashException $e) {
	if ($e->getCode() === Crypto\HashException::HASH_ALGORITHM_NOT_FOUND) {
		echo "NOT FOUND\n";
	}
}
// sub classing
class SubHash extends Crypto\Hash {
	function __construct($algorithm) {
		parent::__construct($algorithm);
		echo $this->algorithm . "\n";
	}
}
$subhash = new SubHash('sha256');
?>
--EXPECT--
FOUND
NOT FOUND
SHA256
