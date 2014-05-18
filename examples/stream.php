<?php

$filename = (dirname( __FILE__) . "/stream_file_plain_write.tmp");

$algorithm = 'aes-256-cbc';
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);
$data = str_repeat('a', 16);

// WRITE
$cipher_enc1_options = array(
	'action' => 'encode',
	'algorithm' => $algorithm,
	'key' => $key,
	'iv'  => $iv,
);
$context_write = stream_context_create(array(
	'crypto.file' => array('cipher' => $cipher_enc1_options),
));
$stream_write = fopen("crypto.file://" . $filename, "w", false, $context_write);
fwrite($stream_write, $data);
fflush($stream_write);
echo "FILE encrypted (base64):" . PHP_EOL;
echo base64_encode(file_get_contents($filename));
echo PHP_EOL;

// READ
$cipher_dec1_options = array(
	'action' => 'decode',
	'algorithm' => $algorithm,
	'key' => $key,
	'iv'  => $iv,
);
$context_read = stream_context_create(array(
	'crypto.file' => array('cipher' => $cipher_dec1_options),
));
echo "FILE decrypted (plain):" . PHP_EOL;
$stream_read = fopen("crypto.file://" . $filename, "r", false, $context_read);
while ($data = fread($stream_read, 5)) {
	echo $data;
}
echo PHP_EOL;
//echo file_get_contents("crypto.file://" . $filename, false, $context_read);

unlink($filename);
