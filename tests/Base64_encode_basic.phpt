--TEST--
Crypto\Base64::encode basic usage.
--FILE--
<?php
$data = "abcdefghijklmnopqrstuv+**^%$";
$data = str_repeat($data, 6);

echo Crypto\Base64::encode($data) . "\n";
?>
--EXPECT--
YWJjZGVmZ2hpamtsbW5vcHFyc3R1disqKl4lJGFiY2RlZmdoaWprbG1ub3BxcnN0
dXYrKipeJSRhYmNkZWZnaGlqa2xtbm9wcXJzdHV2KyoqXiUkYWJjZGVmZ2hpamts
bW5vcHFyc3R1disqKl4lJGFiY2RlZmdoaWprbG1ub3BxcnN0dXYrKipeJSRhYmNk
ZWZnaGlqa2xtbm9wcXJzdHV2KyoqXiUk

