--TEST--
Crypto\EVP\Cipher::decryptInit basic usage.
--FILE--
<?php
$cipher = new Crypto\EVP\Cipher('aes-256-cbc');
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);
$ciphertext = base64_decode('j4hToWhWBxM8ue4Px6W4pXEDk1y8OepoDe8NsHZ+lU4=');

// key length
try {
	$cipher->decryptInit('short_key', $iv);
}
catch (Crypto\EVP\AlgorithmException $e) {
	if ($e->getCode() === Crypto\EVP\AlgorithmException::CIPHER_KEY_LENGTH) {
		echo "SHORT KEY\n";
	}
}

// iv length
try {
	$cipher->decryptInit($key, 'short_iv');
}
catch (Crypto\EVP\AlgorithmException $e) {
	if ($e->getCode() === Crypto\EVP\AlgorithmException::CIPHER_IV_LENGTH) {
		echo "SHORT IV\n";
	}
}

// iv empty when required
try {
	$cipher->decryptInit($key);
}
catch (Crypto\EVP\AlgorithmException $e) {
	if ($e->getCode() === Crypto\EVP\AlgorithmException::CIPHER_IV_LENGTH) {
		echo "NO IV\n";
	}
}

// both
try {
	$cipher->decryptInit('short_key');
}
catch (Crypto\EVP\AlgorithmException $e) {
	// key checking is first
	if ($e->getCode() === Crypto\EVP\AlgorithmException::CIPHER_KEY_LENGTH) {
		echo "BOTH\n";
	}
}

$cipher->decryptInit($key, $iv);
echo "SUCCESS\n";
?>
--EXPECT--
SHORT KEY
SHORT IV
NO IV
BOTH
SUCCESS
