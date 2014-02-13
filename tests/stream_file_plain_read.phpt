--TEST--
Stream crypto.file plain read test
--FILE--
<?php
$filename = (dirname( __FILE__) . "/stream_file_plain_read.tmp");
file_put_contents($filename, "data1data2data3");
$stream = fopen("crypto.file://" . $filename, "r");
while ($data = fread($stream, 5)) {
	echo $data . "\n";
}
echo file_get_contents("crypto.file://" . $filename);
?>
--CLEAN--
<?php
$filename = (dirname( __FILE__) . "/stream_file_plain_read.tmp");
if (file_exists($filename))
	unlink($filename);
?>
--EXPECT--
data1
data2
data3
data1data2data3