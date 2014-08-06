--TEST--
Stream cipher gcm decryption filter for writing
--SKIPIF--
<?php if (!Crypto\Cipher::hasMode(Crypto\Cipher::MODE_GCM)) die("Skip: GCM mode not defined (update OpenSSL version)"); ?>
--FILE--
<?php
$algorithm = 'aes-256-gcm';
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);
$aad = str_repeat('b', 16);
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
				'aad' => $aad,
			)
		)
	),
));

$filename = (dirname( __FILE__) . "/stream_filters_cipher_gcm_enc_write.tmp");

$stream = fopen("crypto.file://" . $filename, "w", false, $context);
if (!$stream) {
	exit;
}
fwrite($stream, $data, strlen($data));
fflush($stream);

$meta_data = stream_get_meta_data($stream);
echo $meta_data['wrapper_data'][0] . "\n";

fclose($stream);

echo bin2hex(file_get_contents($filename));
?>
--CLEAN--
<?php
$filename = (dirname( __FILE__) . "/stream_filters_cipher_gcm_enc_write.tmp");
if (file_exists($filename))
	unlink($filename);
?>
--EXPECT--
X-PHP-Crypto-Auth-Tag: f3c2954804f101d3342f6b37ba46ac8e
622070d3bea6f720943d1198a7e6afa5
