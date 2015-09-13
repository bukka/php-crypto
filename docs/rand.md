## Rand

The `Rand` class provides set of static functions for getting
random values. It includes functions for adding entropy to
the PRNG algorithm.

### Static Methods

#### `Rand::generate($num, $must_be_strong, &$returned_strong_result)`

#### `Rand::seed($buf, $entropy)`

#### `Rand::cleanup()`

#### `Rand::loadFile($filename, $max_bytes)`

#### `Rand::writeFile($filename)`