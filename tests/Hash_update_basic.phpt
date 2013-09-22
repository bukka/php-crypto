--TEST--
Crypto\Hash::update basic usage.
--FILE--
<?php
$hash = new Crypto\Hash('sha256');
try {
	$hash->update('data');
}
catch (Crypto\AlgorithmException $e) {
	if ($e->getCode() === Crypto\AlgorithmException::HASH_UPDATE_STATUS) {
		echo "UPDATE STATUS\n";
	} else {
		echo "WRONG EXCEPTION\n";
	}
}

$hash->init();
$hash->update('data');
echo "SUCCESS\n";
?>
--EXPECT--
UPDATE STATUS
SUCCESS
