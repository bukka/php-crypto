--TEST--
Stream crypto.file plain seek test
--FILE--
<?php
$filename = (dirname( __FILE__) . "/stream_file_plain_seek.tmp");
file_put_contents($filename, "data1data2data3");
$stream = fopen("crypto.file://" . $filename, "r");
fseek($stream, 5);
while ($data = fread($stream, 5)) {
	echo $data . "\n";
}
fseek($stream, 10);
while ($data = fread($stream, 5)) {
	echo $data . "\n";
}

$rc = fseek($stream, 10);
var_dump(ftell($stream));
var_dump($rc);
$rc = fseek($stream, 2, SEEK_END);
var_dump($rc);

?>
--CLEAN--
<?php
$filename = (dirname( __FILE__) . "/stream_file_plain_seek.tmp");
if (file_exists($filename))
	unlink($filename);
?>
--EXPECTF--
data2
data3
data3
int(10)
int(0)

Warning: fseek(): Requested seek operation is forbidden (only SEEK_SET is allowed) in %s
int(-1)