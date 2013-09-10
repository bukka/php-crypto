--TEST--
Crypto\Rand::writeFile basic usage.
--FILE--
<?php
$filename = (dirname( __FILE__) . "/rand_write_file.tmp");
$bytes_written = Crypto\Rand::writeFile($filename);
$content = file_get_contents($filename);
echo $bytes_written . "\n";
echo strlen($content) . "\n";
if (strlen($content) === $bytes_written)
	echo "SUCCESS\n";
?>
--CLEAN--
<?php
$filename = (dirname( __FILE__) . "/rand_write_file.tmp");
if (file_exists($filename))
	unlink($filename);
?>
--EXPECTF--
%d
%d
SUCCESS