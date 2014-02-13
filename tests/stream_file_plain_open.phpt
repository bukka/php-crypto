--TEST--
Stream crypto.file plain open test
--FILE--
<?php
$filename = (dirname( __FILE__) . "/stream_file_plain_open.tmp");
if (file_exists($filename)) // make sure that the file does not exist
	unlink($filename);
$stream = fopen("crypto.file://" . $filename, "r");
touch($filename);
$stream = fopen("crypto.file://" . $filename, "r");
var_dump($stream);
var_dump(fclose($stream));
// test script closing
$stream = fopen("crypto.file://" . $filename, "r");
?>
--CLEAN--
<?php
$filename = (dirname( __FILE__) . "/stream_file_plain_open.tmp");
if (file_exists($filename))
	unlink($filename);
?>
--EXPECTF--

Warning: fopen(crypto.file://%s): failed to open stream: operation failed in %s on line %d
resource(%d) of type (stream)
bool(true)