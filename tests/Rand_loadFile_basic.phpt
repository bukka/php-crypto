--TEST--
Crypto\Rand::loadFile basic usage.
--FILE--
<?php
$filename = (dirname( __FILE__ ) . "/rand_load_file.tmp" );
file_put_contents($filename, str_repeat('a', 400));
$bytes_loaded = Crypto\Rand::loadFile($filename);
echo $bytes_loaded . "\n";
$bytes_loaded = Crypto\Rand::loadFile($filename, 200);
echo $bytes_loaded . "\n";
?>
--CLEAN--
<?php
$filename = (dirname( __FILE__ ) . "/rand_load_file.tmp");
if (file_exists($filename))
	unlink($filename);
?>
--EXPECT--
400
200
