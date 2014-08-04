--TEST--
Stream cipher gcm decryption filter for reading
--SKIPIF--
<?php if (!Crypto\Cipher::hasMode(Crypto\Cipher::MODE_GCM)) die("Skip: GCM mode not defined (update OpenSSL version)"); ?>
--FILE--
<?php
$algorithm = 'aes-256-gcm';
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);
$aad = str_repeat('b', 16);
$tag = pack("H*", 'f3c2954804f101d3342f6b37ba46ac8e');
$ciphertext = pack("H*", '622070d3bea6f720943d1198a7e6afa5');

$filename = (dirname( __FILE__) . "/stream_filters_cipher_gcm_dec_read.tmp");
file_put_contents($filename, $ciphertext);

$context = stream_context_create(array(
	'crypto' => array(
		'filters' => array(
			array(
				'type' => 'cipher',
				'action' => 'decrypt',
				'algorithm' => $algorithm,
				'key' => $key,
				'iv'  => $iv,
				'tag' => $tag,
				'aad' => $aad,
			)
		)
	),
));

$stream = fopen("crypto.file://" . $filename, "r", false, $context);
if (!$stream) {
	exit;
}
while ($data = fread($stream, strlen($ciphertext))) {
	echo $data . "\n";
}

$meta_data = stream_get_meta_data($stream);
echo $meta_data['wrapper_data'][0] . "\n";
?>
--CLEAN--
<?php
$filename = (dirname( __FILE__) . "/stream_filters_cipher_gcm_dec_read.tmp");
if (file_exists($filename))
	unlink($filename);
?>
--EXPECT--
aaaaaaaaaaaaaaaa
X-PHP-Crypto-Auth-Result: success