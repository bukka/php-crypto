--TEST--
Crypto\PBKDF2::derive basic usage.
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
	)
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
