--TEST--
Crypto\HMAC::__construct basic usage.
--FILE--
<?php
// basic creation
$hmac = new Crypto\HMAC('key', 'sha256');
if ($hmac instanceof Crypto\HMAC)
	echo "FOUND\n";
// invalid creation
try {
	$hmac = new Crypto\HMAC('key', 'nnn');
}
catch (Crypto\MACException $e) {
	if ($e->getCode() === Crypto\MACException::MAC_ALGORITHM_NOT_FOUND) {
		echo "NOT FOUND\n";
	}
}
// sub classing
class SubHMAC extends Crypto\HMAC {
	function __construct($key, $algorithm) {
		parent::__construct($key, $algorithm);
		echo $this->algorithm . "\n";
	}
}
$subhmac = new SubHMAC('key', 'sha256');
?>
--EXPECT--
FOUND
NOT FOUND
SHA256
