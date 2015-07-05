--TEST--
Crypto\Cipher::encryptUpdate basic usage.
--FILE--
<?php
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);

$data = str_repeat('a', 16);

$cipher = new Crypto\Cipher('aes-256-cbc');
// invalid order
try {
	$cipher->encryptUpdate('ddd');
}
catch (Crypto\CipherException $e) {
	if ($e->getCode() === Crypto\CipherException::UPDATE_ENCRYPT_FORBIDDEN) {
		echo "UPDATE STATUS\n";
	}
}
// init first
$cipher->encryptInit($key, $iv);
echo bin2hex($cipher->encryptUpdate($data)) . "\n";

?>
--EXPECT--
UPDATE STATUS
8f8853a1685607133cb9ee0fc7a5b8a5
