--TEST--
Crypto\PBKDF2::derive basic usage.
--SKIPIF--
<?php if (!class_exists('Crypto\PBKDF2')) die("Skip: PBKDF2 is not supported (update OpenSSL version)"); ?>
--FILE--
<?php
$vectors = array(
    array(
	    'H' => 'sha1',
		'P' => 'password',
		'S' => 'salt',
		'c' => 1,
		'dkLen' => 20,
		'DK' => "0c 60 c8 0f 96 1f 0e 71 f3 a9 b5 24 af 60 12 06 2f e0 37 a6"
	),
	array(
		'H' => 'sha1',
		'P' => 'password',
		'S' => 'salt',
		'c' => 2,
		'dkLen' => 20,
		'DK' => "ea 6c 01 4d c7 2d 6f 8c cd 1e d9 2a ce 1d 41 f0 d8 de 89 57"
	),
	array(
		'H' => 'sha1',
		'P' => 'password',
		'S' => 'salt',
		'c' => 4096,
		'dkLen' => 20,
		'DK' => "4b 00 79 01 b7 65 48 9a be ad 49 d9 26 f7 21 d0 65 a4 29 c1"
	),
	array(
		'H' => 'sha1',
		'P' => 'passwordPASSWORDpassword',
		'S' => 'saltSALTsaltSALTsaltSALTsaltSALTsalt',
		'c' => 4096,
		'dkLen' => 25,
		'DK' => "3d 2e ec 4f e4 1c 84 9b 80 c8 d8 36 62 c0 e4 4a 8b 29 1a 96 4c f2 f0 70 38"
	),
	array(
		'H' => 'sha1',
		'P' => "pass\0word",
		'S' => "sa\0lt",
		'c' => 4096,
		'dkLen' => 16,
		'DK' => "56 fa 6a a7 55 48 09 9d cc 37 d7 f0 34 25 e0 c3"
	),
);

foreach ($vectors as $v) {
    $pbkdf2 = new Crypto\PBKDF2($v['H'], $v['dkLen'], $v['S'], $v['c']);
	$dk = pack('H*', str_replace(' ', '', $v['DK']));
	if ($dk !== $pbkdf2->derive($v['P'])) {
	    print_r($v);
	}
}
echo "DONE";
?>
--EXPECT--
DONE
