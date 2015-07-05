--TEST--
Crypto\Cipher::decrypt basic usage.
--FILE--
<?php
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);

$ciphertext = pack("H*", '8f8853a1685607133cb9ee0fc7a5b8a57103935cbc39ea680def0db0767e954e');

$cipher = new Crypto\Cipher('aes-256-cbc');

// key length
try {
	$cipher->decrypt($ciphertext, 'short_key', $iv);
}
catch (Crypto\CipherException $e) {
	if ($e->getCode() === Crypto\CipherException::KEY_LENGTH_INVALID) {
		echo "SHORT KEY\n";
	}
}

// iv length
try {
	$cipher->decrypt($ciphertext, $key, 'short_iv');
}
catch (Crypto\CipherException $e) {
	if ($e->getCode() === Crypto\CipherException::IV_LENGTH_INVALID) {
		echo "SHORT IV\n";
	}
}

// init first
echo $cipher->decrypt($ciphertext, $key, $iv) . "\n";

?>
--EXPECT--
SHORT KEY
SHORT IV
aaaaaaaaaaaaaaaa
