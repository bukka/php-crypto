--TEST--
Crypto\Digest::__clone basic usage.
--FILE--
<?php
$data1 = "data1";
$data2 = "data2";

$digest = new Crypto\Digest('sha256');
$digest->init();
$digest->update($data1);
$digest_clone = clone $digest;
echo $digest_clone->getAlgorithm() . "\n";

$digest->update($data2);
echo bin2hex($digest->final()) . "\n";

$digest_clone->update($data2);
echo bin2hex($digest_clone->final()) . "\n";

echo "SUCCESS\n";
?>
--EXPECT--
sha256
53ddc03623f867c7d4a631ded19c2613f2cb61d47b6aa214f47ff3cc15445bcd
53ddc03623f867c7d4a631ded19c2613f2cb61d47b6aa214f47ff3cc15445bcd
SUCCESS
