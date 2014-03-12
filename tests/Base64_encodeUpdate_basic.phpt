--TEST--
Crypto\Base64::encodeUpdate basic usage.
--FILE--
<?php
$data = "abcdefghijklmnopqrstuv+**^%$";

// try state exception
$b64 = new Crypto\Base64;
$b64->decodeUpdate("abc");
try {
	$b64->encodeUpdate($data);
}
catch (Crypto\Base64Exception $e) {
	if ($e->getCode() == Crypto\Base64Exception::ENCODE_UPDATE_FORBIDDEN) {
		echo "ENCODE UPDATE STATUS EXCEPTION\n";
	}
}

$b64 = new Crypto\Base64;
$result = $b64->encodeUpdate(str_repeat($data, 10));
echo "$result\n";

$b64 = new Crypto\Base64;
for ($i = 0; $i < 20; $i++) {
	echo $b64->encodeUpdate("abcde") . "\n";
}

?>
--EXPECT--
ENCODE UPDATE STATUS EXCEPTION
YWJjZGVmZ2hpamtsbW5vcHFyc3R1disqKl4lJGFiY2RlZmdoaWprbG1ub3BxcnN0
dXYrKipeJSRhYmNkZWZnaGlqa2xtbm9wcXJzdHV2KyoqXiUkYWJjZGVmZ2hpamts
bW5vcHFyc3R1disqKl4lJGFiY2RlZmdoaWprbG1ub3BxcnN0dXYrKipeJSRhYmNk
ZWZnaGlqa2xtbm9wcXJzdHV2KyoqXiUkYWJjZGVmZ2hpamtsbW5vcHFyc3R1disq
Kl4lJGFiY2RlZmdoaWprbG1ub3BxcnN0dXYrKipeJSRhYmNkZWZnaGlqa2xtbm9w










YWJjZGVhYmNkZWFiY2RlYWJjZGVhYmNkZWFiY2RlYWJjZGVhYmNkZWFiY2RlYWJj










ZGVhYmNkZWFiY2RlYWJjZGVhYmNkZWFiY2RlYWJjZGVhYmNkZWFiY2RlYWJjZGVh
