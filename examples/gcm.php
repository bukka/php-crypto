<?php
use Crypto\Cipher;
use Crypto\AlgorihtmException;

/**
 * Encrypt plaintext using AES cipher with GCM mode and 256 bit key
 * @param string $pt Plaintext
 * @param string $key Key
 * @param string $iv Initial vector
 * @param string $aad Additional application data
 * @return array array with resulted ciphertext (idx 0) authentication tag (idx 1)
 * @throw Crypto\AlgorithmException if any of the method fails
 */
function gcm_encrypt($pt, $key, $iv, $aad) {
	echo "------- ENCRYPTION -------" . PHP_EOL;
	echo "Plaintext: " . bin2hex($pt) . PHP_EOL;
	$cipher = Cipher::aes(Cipher::MODE_GCM, 256);
	$cipher->setAAD($aad);
	$ct = $cipher->encrypt($pt, $key, $iv);
	echo "Ciphertext: " . bin2hex($ct) . PHP_EOL;
	$tag = $cipher->getTag();
	echo "Tag: " . bin2hex($tag) . PHP_EOL;
	return array($ct, $tag);
}

/**
 * Decrypt ciphertext using AES cipher with GCM mode and 256 bit key
 * @param string $ct Ciphertext
 * @param string $key Key
 * @param string $iv Initial vector
 * @param string $aad Additional application data
 * @param string $tag Authentication tag
 * @return string Plaintext
 * @throw Crypto\AlgorithmException if any of the method fails
 */
function gcm_decrypt($ct, $key, $iv, $aad, $tag) {
	echo "------- DECRYPTION -------\n";
	echo "Ciphertext: " . bin2hex($ct) . PHP_EOL;
	$cipher = Cipher::aes(Cipher::MODE_GCM, 256);
	$cipher->setTag($tag);
	$cipher->setAAD($aad);
	$pt = $cipher->decrypt($ct, $key, $iv);
	echo "Plaintext: " . bin2hex($pt) . PHP_EOL;
}

$gcm_key = pack(
	"C*",
	0xee,0xbc,0x1f,0x57,0x48,0x7f,0x51,0x92,0x1c,0x04,0x65,0x66,
	0x5f,0x8a,0xe6,0xd1,0x65,0x8b,0xb2,0x6d,0xe6,0xf8,0xa0,0x69,
	0xa3,0x52,0x02,0x93,0xa5,0x72,0x07,0x8f
);
$gcm_iv = pack(
	"C*",
	0x99,0xaa,0x3e,0x68,0xed,0x81,0x73,0xa0,0xee,0xd0,0x66,0x84
);
$gcm_pt = pack(
	"C*",
	0xf5,0x6e,0x87,0x05,0x5b,0xc3,0x2d,0x0e,0xeb,0x31,0xb2,0xea,
	0xcc,0x2b,0xf2,0xa5
);
$gcm_aad = pack(
	"C*",
	0x4d,0x23,0xc3,0xce,0xc3,0x34,0xb4,0x9b,0xdb,0x37,0x0c,0x43,
	0x7f,0xec,0x78,0xde
);

try {
	// encryption
	list($ct, $tag) = gcm_encrypt($gcm_pt, $gcm_key, $gcm_iv, $gcm_aad);
	echo PHP_EOL;
	
	// decryption
	$pt = gcm_decrypt($ct, $gcm_key, $gcm_iv, $gcm_aad, $tag);
}
catch (AlgorithmException $e) {
	echo $e->getMessage() . PHP_EOL;
}
