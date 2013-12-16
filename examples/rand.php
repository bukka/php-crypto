<?php
use Crypto\Rand;

/* this is just for testing - you should use a proper random seed
   or nothing as it is seeded from RAND_poll anyway */
$seed = str_repeat("a", 32);
Rand::seed($seed, 32);
$is_strong = false;
$bytes = Rand::generate(100, false, $is_strong);
Rand::cleanup();
echo "STRONG: " . ($is_strong ? 'yes' : 'no') . PHP_EOL;
echo base64_encode($bytes) . PHP_EOL;