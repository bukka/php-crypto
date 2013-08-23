--TEST--
Crypto\Cipher::encryptFinal basic usage.
--FILE--
<?php
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);

$data = str_repeat('a', 16);

$cipher = new Crypto\Cipher('aes-256-cbc');
// invalid order
try {
	$cipher->encryptFinal();
}
catch (Crypto\AlgorithmException $e) {
	if ($e->getCode() === Crypto\AlgorithmException::ENCRYPT_FINAL_STATUS) {
		echo "FINAL STATUS\n";
	}
}
// init first
$cipher->encryptInit($key, $iv);
echo base64_encode($cipher->encryptUpdate($data)) . "\n";
echo base64_encode($cipher->encryptFinal()) . "\n";

?>
--EXPECT--
FINAL STATUS
j4hToWhWBxM8ue4Px6W4pQ==
cQOTXLw56mgN7w2wdn6VTg==
