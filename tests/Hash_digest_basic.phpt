--TEST--
Crypto\Hash::digest basic usage.
--FILE--
<?php

$one_block_msg = "abc";
$multi_block_msg = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";

function crypto_test_hash_digest_run($alg, $title, $msg) {
	echo "$title\n";
	$hash = new Crypto\Hash($alg);
	if (strlen($msg))
		$hash->update($msg);
	echo bin2hex($hash->digest()) . "\n";
}

function crypto_test_hash_digest($alg) {
	global $one_block_msg, $multi_block_msg;

	crypto_test_hash_digest_run(
		$alg, "$alg (empty message)", '');
	crypto_test_hash_digest_run(
		$alg, "$alg (one-block message)", $one_block_msg);
	crypto_test_hash_digest_run(
		$alg, "$alg (multi-block message)", $multi_block_msg);
}

crypto_test_hash_digest('md5');
crypto_test_hash_digest('sha1');
crypto_test_hash_digest('sha256');
crypto_test_hash_digest('sha512');
crypto_test_hash_digest('sha384');
echo "SUCCESS\n";
?>
--EXPECT--
md5 (empty message)
d41d8cd98f00b204e9800998ecf8427e
md5 (one-block message)
900150983cd24fb0d6963f7d28e17f72
md5 (multi-block message)
8215ef0796a20bcaaae116d3876c664a
sha1 (empty message)
da39a3ee5e6b4b0d3255bfef95601890afd80709
sha1 (one-block message)
a9993e364706816aba3e25717850c26c9cd0d89d
sha1 (multi-block message)
84983e441c3bd26ebaae4aa1f95129e5e54670f1
sha256 (empty message)
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
sha256 (one-block message)
ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
sha256 (multi-block message)
248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1
sha512 (empty message)
cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
sha512 (one-block message)
ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f
sha512 (multi-block message)
204a8fc6dda82f0a0ced7beb8e08a41657c16ef468b228a8279be331a703c33596fd15c13b1b07f9aa1d3bea57789ca031ad85c7a71dd70354ec631238ca3445
sha384 (empty message)
38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b
sha384 (one-block message)
cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7
sha384 (multi-block message)
3391fdddfc8dc7393707a65b1b4709397cf8b1d162af05abfe8f450de5f36bc6b0455a8520bc4e6f5fe95b1fe3c8452b
SUCCESS
