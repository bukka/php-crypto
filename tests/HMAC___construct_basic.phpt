--TEST--
Crypto\HMAC::__construct basic usage.
--FILE--
<?php
// basic creation
$hmac = new Crypto\HMAC('sha256', 'key');
if ($hmac instanceof Crypto\HMAC)
	echo "FOUND\n";
// invalid creation
try {
	$hmac = new Crypto\HMAC('nnn', 'key');
}
catch (Crypto\HashException $e) {
	if ($e->getCode() === Crypto\HashException::ALGORITHM_NOT_FOUND) {
		echo "NOT FOUND\n";
	}
}
// sub classing
class SubHMAC extends Crypto\HMAC {
	function __construct($algorithm, $key) {
		parent::__construct($algorithm, $key);
		echo $this->algorithm . "\n";
	}
}
$subhmac = new SubHMAC('sha256', 'key');
?>
--EXPECT--
FOUND
NOT FOUND
SHA256
