--TEST--
Crypto\Base64::decodeFinish basic usage.
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
try {
	$b64->decodeFinish();
}
catch (Crypto\Base64Exception $e) {
	if ($e->getCode() == Crypto\Base64Exception::DECODE_FINISH_FORBIDDEN) {
		echo "DECODE FINISH STATUS EXCEPTION\n";
	}
}

$b64 = new Crypto\Base64;
$data = '';
foreach ($data_chunks as $data_chunk) {
	$data .= $b64->decodeUpdate($data_chunk);
}
echo "$data\n";
echo "FINISH: " . $b64->decodeFinish() . "\n";
?>
--EXPECT--
DECODE FINISH STATUS EXCEPTION
abcdefghijklmnopqrstuv+**^%$abcdefghijklmnopqrstuv+**^%$abcdefghijklmnopqrstuv+**^%$abcdefghijklmnopqrstuv+**^%$abcdefghijklmnopqrstuv+**^%$abcdefghijklmnopqrstuv+**^%$
FINISH:

