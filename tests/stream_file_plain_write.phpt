--TEST--
Stream crypto.file plain write test
--FILE--
<?php
$filename = (dirname( __FILE__) . "/stream_file_plain_write.tmp");
$stream = fopen("crypto.file://" . $filename, "w");
fwrite($stream, "data");
fflush($stream);
echo file_get_contents($filename);
?>
--CLEAN--
<?php
$filename = (dirname( __FILE__) . "/stream_file_plain_write.tmp");
if (file_exists($filename))
	unlink($filename);
?>
--EXPECT--
data