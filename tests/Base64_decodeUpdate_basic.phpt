--TEST--
Crypto\Base64::decodeUpdate basic usage.
--FILE--
<?php

$data_encoded = <<<EOI
YWJjZGVmZ2hpamtsbW5vcHFyc3R1disqKl4lJGFiY2RlZmdoaWprbG1ub3BxcnN0
dXYrKipeJSRhYmNkZWZnaGlqa2xtbm9wcXJzdHV2KyoqXiUkYWJjZGVmZ2hpamts
bW5vcHFyc3R1disqKl4lJGFiY2RlZmdoaWprbG1ub3BxcnN0dXYrKipeJSRhYmNk
ZWZnaGlqa2xtbm9wcXJzdHV2KyoqXiUk
EOI;

$data_chunks = str_split($data_encoded, 20);

// try state exception
$b64 = new Crypto\Base64;
$b64->encodeUpdate("abc");
try {
	$b64->decodeUpdate($data_encoded);
}
catch (Crypto\Base64Exception $e) {
	if ($e->getCode() == Crypto\Base64Exception::DECODE_UPDATE_FORBIDDEN) {
		echo "DECODE UPDATE STATUS EXCEPTION\n";
	}
}

$b64 = new Crypto\Base64;
echo $b64->decodeUpdate($data_encoded) . "\n";

$b64 = new Crypto\Base64;
$data = '';
foreach ($data_chunks as $data_chunk) {
	$data .= $b64->decodeUpdate($data_chunk);
}
echo "$data\n";

?>
--EXPECT--
DECODE UPDATE STATUS EXCEPTION
abcdefghijklmnopqrstuv+**^%$abcdefghijklmnopqrstuv+**^%$abcdefghijklmnopqrstuv+**^%$abcdefghijklmnopqrstuv+**^%$abcdefghijklmnopqrstuv+**^%$abcdefghijklmnopqrstuv+**^%$
abcdefghijklmnopqrstuv+**^%$abcdefghijklmnopqrstuv+**^%$abcdefghijklmnopqrstuv+**^%$abcdefghijklmnopqrstuv+**^%$abcdefghijklmnopqrstuv+**^%$abcdefghijklmnopqrstuv+**^%$
