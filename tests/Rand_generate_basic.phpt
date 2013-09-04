--TEST--
Crypto\Rand::generate basic usage.
--FILE--
<?php
// generate pseudo bytes
$strong = 1; // this will be casted to bool
$data = Crypto\Rand::generate(1000, false, $strong);
echo is_bool($strong) ? "STRONG SET" . PHP_EOL : "";
echo strlen($data) . PHP_EOL;
?>
--EXPECT--
STRONG SET
1000