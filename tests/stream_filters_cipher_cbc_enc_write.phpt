--TEST--
Stream cipher cbc encryption filter for writing
--FILE--
<?php
$algorithm = 'aes-256-cbc';
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);
$data = str_repeat('a', 16);

$context = stream_context_create(array(
	'crypto' => array(
		'filters' => array(
			array(
				'type' => 'cipher',
				'action' => 'encrypt',
				'algorithm' => $algorithm,
				'key' => $key,
				'iv'  => $iv,
			)
		)
	),
));

$filename = (dirname( __FILE__) . "/stream_filters_cipher_cbc_enc_write.tmp");
file_put_contents("crypto.file://" . $filename, $data, 0, $context);

echo bin2hex(file_get_contents($filename));
?>
--CLEAN--
<?php
$filename = (dirname( __FILE__) . "/stream_filters_cipher_cbc_enc_write.tmp");
if (file_exists($filename))
	unlink($filename);
?>
--EXPECT--
8f8853a1685607133cb9ee0fc7a5b8a57103935cbc39ea680def0db0767e954e