--TEST--
Crypto\Hash::final basic usage.
--FILE--
<?php
$hash = new Crypto\Hash('sha256');
try {
	$hash->final();
}
catch (Crypto\AlgorithmException $e) {
	if ($e->getCode() === Crypto\AlgorithmException::HASH_FINAL_STATUS) {
		echo "FINAL STATUS\n";
	} else {
		echo "WRONG EXCEPTION\n";
	}
}

$hash->init();
echo bin2hex($hash->final()) . "\n";

$hash->init();
$hash->update('data1');
$hash->update('data2');
echo bin2hex($hash->final()) . "\n";

$hash->init();
$hash->update('data1data2');

echo bin2hex($hash->final()) . "\n";
echo "SUCCESS\n";
?>
--EXPECT--
FINAL STATUS
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
53ddc03623f867c7d4a631ded19c2613f2cb61d47b6aa214f47ff3cc15445bcd
53ddc03623f867c7d4a631ded19c2613f2cb61d47b6aa214f47ff3cc15445bcd
SUCCESS
