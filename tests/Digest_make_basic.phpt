--TEST--
Crypto\Digest::make basic usage.
--FILE--
<?php
$digest = new Crypto\Digest('sha256');
echo bin2hex($digest->make('data1data2')) . "\n";
echo "SUCCESS\n";
?>
--EXPECT--
53ddc03623f867c7d4a631ded19c2613f2cb61d47b6aa214f47ff3cc15445bcd
SUCCESS
