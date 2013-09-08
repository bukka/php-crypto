--TEST--
Crypto\Rand::egd basic usage.
--SKIPIF--
<?php if ( @stat("/tmp/entropy") === false ) die("Skip: EGD entropy file is not at /tmp/entropy"); ?>
--FILE--
<?php
// seed the default number of bytes (255)
Crypto\Rand::egd("/tmp/entropy");

// seed 200 bytes
Crypto\Rand::egd("/tmp/entropy", 200);

// return 255 bytes
$egd_bytes = Crypto\Rand::egd("/tmp/entropy", 255, false);
echo strlen($egd_bytes) . PHP_EOL;
?>
--EXPECT--
255