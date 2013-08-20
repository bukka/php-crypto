--TEST--
Crypto\EVP\Cipher::encryptUpdate basic usage.
--FILE--
<?php
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);

$data = str_repeat('a', 16);

$cipher = new Crypto\EVP\Cipher('aes-256-cbc');
// invalid order
try {
	$cipher->encryptUpdate('ddd');
}
catch (Crypto\EVP\AlgorithmException $e) {
	if ($e->getCode() === Crypto\EVP\AlgorithmException::ENCRYPT_UPDATE_STATUS) {
		echo "UPDATE STATUS\n";
	}
}
// init first
$cipher->encryptInit($key, $iv);
echo base64_encode($cipher->encryptUpdate($data)) . "\n";

?>
--EXPECT--
UPDATE STATUS
j4hToWhWBxM8ue4Px6W4pQ==
