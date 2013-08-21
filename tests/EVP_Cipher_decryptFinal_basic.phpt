--TEST--
Crypto\EVP\Cipher::decryptFinal basic usage.
--FILE--
<?php
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);

$ciphertext = base64_decode('j4hToWhWBxM8ue4Px6W4pXEDk1y8OepoDe8NsHZ+lU4=');

$cipher = new Crypto\EVP\Cipher('aes-256-cbc');

// invalid order
try {
	$cipher->decryptFinal();
}
catch (Crypto\EVP\AlgorithmException $e) {
	if ($e->getCode() === Crypto\EVP\AlgorithmException::DECRYPT_FINAL_STATUS) {
		echo "FINAL STATUS\n";
	}
}

// init first
$cipher->decryptInit($key, $iv);
$result = $cipher->decryptUpdate($ciphertext);
$result .= $cipher->decryptFinal();
echo $result . "\n";
?>
--EXPECT--
FINAL STATUS
aaaaaaaaaaaaaaaa
