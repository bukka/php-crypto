--TEST--
Stream cipher cbc decryption filter for writing
--FILE--
<?php
$algorithm = 'aes-256-cbc';
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);
$ciphertext = pack("H*", '8f8853a1685607133cb9ee0fc7a5b8a57103935cbc39ea680def0db0767e954e');

$context = stream_context_create(array(
	'crypto' => array(
		'filters' => array(
			array(
				'type' => 'cipher',
				'action' => 'decrypt',
				'algorithm' => $algorithm,
				'key' => $key,
				'iv'  => $iv,
			)
		)
	),
));

$filename = (dirname( __FILE__) . "/stream_filters_cipher_cbc_dec_write.tmp");
file_put_contents("crypto.file://" . $filename, $ciphertext, 0, $context);

echo file_get_contents($filename);
?>
--CLEAN--
<?php
$filename = (dirname( __FILE__) . "/stream_filters_cipher_cbc_dec_write.tmp");
if (file_exists($filename))
	unlink($filename);
?>
--EXPECT--
aaaaaaaaaaaaaaaa