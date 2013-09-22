--TEST--
Crypto\Hash::hasAlgorithm basic usage.
--FILE--
<?php
echo Crypto\Hash::hasAlgorithm('nnnn') ? "nnnn\n" : "";
// the following algorigthms should exists on any platform
echo Crypto\Hash::hasAlgorithm('sha256') ? "HAS sha256\n" : "";
echo Crypto\Hash::hasAlgorithm('md5') ? "HAS md5\n" : "";
?>
--EXPECT--
HAS sha256
HAS md5