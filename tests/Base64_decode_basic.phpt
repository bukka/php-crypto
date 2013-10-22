--TEST--
Crypto\Base64::decode basic usage.
--FILE--
<?php
$data_part = "abcdefghijklmnopqrstuv+**^%$";
$data_orig = str_repeat($data_part, 6);

// result from Crypto\Base64::encode
$data_encoded = <<<EOI
YWJjZGVmZ2hpamtsbW5vcHFyc3R1disqKl4lJGFiY2RlZmdoaWprbG1ub3BxcnN0
dXYrKipeJSRhYmNkZWZnaGlqa2xtbm9wcXJzdHV2KyoqXiUkYWJjZGVmZ2hpamts
bW5vcHFyc3R1disqKl4lJGFiY2RlZmdoaWprbG1ub3BxcnN0dXYrKipeJSRhYmNk
ZWZnaGlqa2xtbm9wcXJzdHV2KyoqXiUk
EOI;

echo ($data_orig == Crypto\Base64::decode($data_encoded) ? "SUCCESS" : "ERROR") . "\n";

?>
--EXPECT--
SUCCESS
