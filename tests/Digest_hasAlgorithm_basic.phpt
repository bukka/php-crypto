--TEST--
Crypto\Digest::hasAlgorithm basic usage.
--FILE--
<?php
echo Crypto\Digest::hasAlgorithm('nnnn') ? "nnnn\n" : "";
// the following algorigthms should exists on any platform
echo Crypto\Digest::hasAlgorithm('sha256') ? "HAS sha256\n" : "";
echo Crypto\Digest::hasAlgorithm('md5') ? "HAS md5\n" : "";
?>
--EXPECT--
HAS sha256
HAS md5