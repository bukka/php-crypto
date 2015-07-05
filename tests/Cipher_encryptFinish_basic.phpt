--TEST--
Crypto\Cipher::encryptFinish basic usage.
--FILE--
<?php
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);

$data = str_repeat('a', 16);

$cipher = new Crypto\Cipher('aes-256-cbc');
// invalid order
try {
	$cipher->encryptFinish();
}
catch (Crypto\CipherException $e) {
	if ($e->getCode() === Crypto\CipherException::FINISH_ENCRYPT_FORBIDDEN) {
		echo "FINAL STATUS\n";
	}
}
// init first
$cipher->encryptInit($key, $iv);
echo bin2hex($cipher->encryptUpdate($data)) . "\n";
echo bin2hex($cipher->encryptFinish()) . "\n";

?>
--EXPECT--
FINAL STATUS
8f8853a1685607133cb9ee0fc7a5b8a5
7103935cbc39ea680def0db0767e954e
