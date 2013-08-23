--TEST--
Crypto\Digest::final basic usage.
--FILE--
<?php
$digest = new Crypto\Digest('sha256');
try {
	$digest->final();
}
catch (Crypto\AlgorithmException $e) {
	if ($e->getCode() === Crypto\AlgorithmException::DIGEST_FINAL_STATUS) {
		echo "FINAL STATUS\n";
	} else {
		echo "WRONG EXCEPTION\n";
	}
}

$digest->init();
echo bin2hex($digest->final()) . "\n";

$digest->init();
$digest->update('data1');
$digest->update('data2');
echo bin2hex($digest->final()) . "\n";

$digest->init();
$digest->update('data1data2');

echo bin2hex($digest->final()) . "\n";
echo "SUCCESS\n";
?>
--EXPECT--
FINAL STATUS
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
53ddc03623f867c7d4a631ded19c2613f2cb61d47b6aa214f47ff3cc15445bcd
53ddc03623f867c7d4a631ded19c2613f2cb61d47b6aa214f47ff3cc15445bcd
SUCCESS
