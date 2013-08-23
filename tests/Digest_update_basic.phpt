--TEST--
Crypto\Digest::update basic usage.
--FILE--
<?php
$digest = new Crypto\Digest('sha256');
try {
	$digest->update('data');
}
catch (Crypto\AlgorithmException $e) {
	if ($e->getCode() === Crypto\AlgorithmException::DIGEST_UPDATE_STATUS) {
		echo "UPDATE STATUS\n";
	} else {
		echo "WRONG EXCEPTION\n";
	}
}

$digest->init();
$digest->update('data');
echo "SUCCESS\n";
?>
--EXPECT--
UPDATE STATUS
SUCCESS
