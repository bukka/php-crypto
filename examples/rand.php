<?php
namespace Crypto;

/* this is just for testing - you should use a proper random so */
$seed = str_repeat("a", 32);
Rand::seed($seed);
$bytes = Rand::generate(32);
Rand::cleanup();
echo base64_encode($bytes) . PHP_EOL;