--TEST--
Stream cipher gcm encryption filter for reading
--SKIPIF--
<?php if (!Crypto\Cipher::hasMode(Crypto\Cipher::MODE_GCM)) die("Skip: GCM mode not defined (update OpenSSL version)"); ?>
--FILE--
<?php
$algorithm = 'aes-256-gcm';
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);
$aad = str_repeat('b', 16);
$data = str_repeat('a', 16);

$filename = (dirname( __FILE__) . "/stream_filters_cipher_gcm_enc_read.tmp");
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
				'aad' => $aad,
			)
		)
	),
));

$stream = fopen("crypto.file://" . $filename, "r", false, $context);
if (!$stream) {
	exit;
}
while ($data = fread($stream, strlen($data))) {
	echo bin2hex($data) . "\n";
}

$meta_data = stream_get_meta_data($stream);
echo $meta_data['wrapper_data'][0] . "\n";
?>
--CLEAN--
<?php
$filename = (dirname( __FILE__) . "/stream_filters_cipher_gcm_enc_read.tmp");
if (file_exists($filename))
	unlink($filename);
?>
--EXPECT--
622070d3bea6f720943d1198a7e6afa5
X-PHP-Crypto-Auth-Tag: f3c2954804f101d3342f6b37ba46ac8e
