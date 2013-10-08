--TEST--
Crypto\Cipher::encryptInit basic usage.
--FILE--
<?php
$cipher = new Crypto\Cipher('aes-256-cbc');
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);

// key length
try {
	$cipher->encryptInit('short_key', $iv);
}
catch (Crypto\AlgorithmException $e) {
	if ($e->getCode() === Crypto\AlgorithmException::CIPHER_KEY_LENGTH) {
		echo "SHORT KEY\n";
	}
}

// iv length
try {
	$cipher->encryptInit($key, 'short_iv');
}
catch (Crypto\AlgorithmException $e) {
	if ($e->getCode() === Crypto\AlgorithmException::CIPHER_IV_LENGTH) {
		echo "SHORT IV\n";
	}
}

// iv empty when required
try {
	$cipher->encryptInit($key);
}
catch (Crypto\AlgorithmException $e) {
	if ($e->getCode() === Crypto\AlgorithmException::CIPHER_IV_LENGTH) {
		echo "NO IV\n";
	}
}

// both
try {	
	$cipher->encryptInit('short_key');
}
catch (Crypto\AlgorithmException $e) {
	// key checking is first
	if ($e->getCode() === Crypto\AlgorithmException::CIPHER_KEY_LENGTH) {
		echo "BOTH\n";
	}
}

$cipher->encryptInit($key, $iv);
echo "SUCCESS\n";
?>
--EXPECT--
SHORT KEY
SHORT IV
NO IV
BOTH
SUCCESS
