--TEST--
Crypto\Digest::__construct basic usage.
--FILE--
<?php
// basic creation
$digest = new Crypto\Digest('sha256');
if ($digest instanceof Crypto\Digest)
	echo "FOUND\n";
// invalid creation
try {
	$digest = new Crypto\Digest('nnn');	
}
catch (Crypto\AlgorithmException $e) {
	if ($e->getCode() === Crypto\AlgorithmException::DIGEST_NOT_FOUND) {
		echo "NOT FOUND\n";
	}
}
// sub classing
class SubDigest extends Crypto\Digest {
	function __construct($algorithm) {
		parent::__construct($algorithm);
		echo $this->algorithm . "\n";
	}
}
$subcipher = new SubDigest('sha256');
?>
--EXPECT--
FOUND
NOT FOUND
sha256
