--TEST--
Crypto\Base64::encodeFinish basic usage.
--FILE--
<?php
// max block of data in final (block size = 48)
$data = str_repeat("a", 47);

// try state exception
$b64 = new Crypto\Base64;
try {
	$b64->encodeFinish();
}
catch (Crypto\Base64Exception $e) {
	if ($e->getCode() == Crypto\Base64Exception::ENCODE_FINISH_FORBIDDEN) {
		echo "ENCODE FINISH STATUS EXCEPTION\n";
	}
}

$b64 = new Crypto\Base64;
echo $b64->encodeUpdate($data);
echo $b64->encodeFinish();

$b64 = new Crypto\Base64;
for ($i = 0; $i < 20; $i++) {
	$b64->encodeUpdate('a');
}
echo $b64->encodeFinish();
?>
--EXPECT--
ENCODE FINISH STATUS EXCEPTION
YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=
YWFhYWFhYWFhYWFhYWFhYWFhYWE=
