--TEST--
Stream cipher ccm error
--SKIPIF--
<?php
if (!Crypto\Cipher::hasMode(Crypto\Cipher::MODE_CCM)) {
	die("Skip: CCM mode not defined (update OpenSSL version)");
}
?>
--FILE--
<?php
$algorithm = 'aes-256-ccm';
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);
$aad = str_repeat('b', 16);
$tag = pack("H*", 'f3c2954804f101d3342f6b37ba46ac8e');

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

$filename = (dirname( __FILE__) . "/stream_filters_cipher_ccm_error.tmp");

$stream = fopen("crypto.file://" . $filename, "w", false, $context);
if (!$stream) {
	echo "NOT SUPPORTED";
}
?>
--CLEAN--
<?php
$filename = (dirname( __FILE__) . "/stream_filters_cipher_ccm_error.tmp");
if (file_exists($filename))
	unlink($filename);
?>
--EXPECTF--
Warning: fopen(): The CCM mode is not supported in stream in %s on line %d

Warning: %s failed to open stream: operation failed in %s on line %d
NOT SUPPORTED
