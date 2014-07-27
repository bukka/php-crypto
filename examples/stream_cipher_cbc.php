<?php

// INIT

// temporary file
$filename = tempnam(sys_get_temp_dir(), 'php_crypto_');
// use AES with CBC mode
$algorithm = 'aes-256-cbc';
$key = str_repeat('x', 32);
$iv = str_repeat('i', 16);
$data = str_repeat('a', 16);


// ---------------------------
// WRITE to the encrypted file

// create a stream context with cipher filter
$context_write = stream_context_create(array(
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
$stream_write = fopen("crypto.file://" . $filename, "w", false, $context_write);
if (!$stream_write) {
	exit;
}
fwrite($stream_write, $data);
fflush($stream_write);
echo "FILE '$filename' encrypted (base64):" . PHP_EOL;
echo base64_encode(file_get_contents($filename));
echo PHP_EOL;


// ---------------------------
// READ encrypted file

// create a stream context with cipher filter
$context_read = stream_context_create(array(
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
echo "FILE '$filename' decrypted (plain):" . PHP_EOL;
$stream_read = fopen("crypto.file://" . $filename, "r", false, $context_read);
if (!$stream_read) {
	exit;
}
while ($data = fread($stream_read, 5)) {
	echo $data;
}
echo file_get_contents("crypto.file://" . $filename, false, $context_read);
echo PHP_EOL;


// ---------------------------
// DELETE the temporary file
if (unlink($filename)) {
	echo "FILE '$filename' deleted" . PHP_EOL;
}
