--TEST--
Stream cipher cbc encryption filter for reading
--FILE--
<?php
$algorithm = 'aes-256-cbc';
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);
$data = str_repeat('a', 16);

$filename = (dirname( __FILE__) . "/stream_filters_cipher_cbc_enc_read.tmp");
file_put_contents($filename, $data);

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

// init first
echo bin2hex(file_get_contents("crypto.file://" . $filename, false, $context));
?>
--CLEAN--
<?php
$filename = (dirname( __FILE__) . "/stream_filters_cipher_cbc_enc_read.tmp");
if (file_exists($filename))
	unlink($filename);
?>
--EXPECT--
8f8853a1685607133cb9ee0fc7a5b8a57103935cbc39ea680def0db0767e954e