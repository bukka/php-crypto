<?php

class Apidoc {

	private $indent = 0;
	private $indent_str = "    ";
	
	private $conf = array(
		'classes' => array(
			array(
				'name' => 'Crypto\Algorithm',
				'description' => 'Alorithm class (parent of cipher and digest algorithms)',
				'vars' => array(
					array(
						'prefix' => 'protected',
						'name' => '$algorithm',
						'description' => 'Algorithm name',
						'type' => 'string',
						'isref' => false,
					)
				),
			),
			array(
				'name' => 'Crypto\Cipher',
				'parent' => 'Crypto\Algorithm',
				'description' => 'Class providing cipher algorithms',
				'constants' => array(
					array( 'name' => 'MODE_ECB', 'value' => 0x1 ),
					array( 'name' => 'MODE_CBC', 'value' => 0x2 ),
					array( 'name' => 'MODE_CFB', 'value' => 0x3 ),
					array( 'name' => 'MODE_OFB', 'value' => 0x4 ),
					array( 'name' => 'MODE_CTR', 'value' => 0x5 ),
					array( 'name' => 'MODE_GCM', 'value' => 0x6 ),
					array( 'name' => 'MODE_CCM', 'value' => 0x7 ),
					array( 'name' => 'MODE_XTS', 'value' => 0x10001 ),
				),
			),
			array(
				'name' => 'Crypto\Hash',
				'parent' => 'Crypto\Algorithm',
				'description' => 'Class providing hash algorithms',
			),
			array(
				'name' => 'Crypto\AlgorithmException',
				'parent' => 'Exception',
				'description' => 'Exception class for algorithms errors',
			),
			array(
				'name' => 'Crypto\Base64',
				'description' => 'Class for base64 encoding and docoding',
			),
			array(
				'name' => 'Crypto\Base64Exception',
				'parent' => 'Exception',
				'description' => 'Exception class for base64 errors',
			),
			array(
				'name' => 'Crypto\Rand',
				'description' => 'Class for generating random numbers',
			),
		),
		'methods' => array(
			'files' => array( '/crypto_alg.c', '/crypto_base64.c', '/crypto_rand.c' ),
			'macro' => 'PHP_CRYPTO_METHOD',
		),
		'constants' => array(
			'Crypto\AlgorithmException' => array(
				'file' => '/php_crypto_alg.h',
				'macro' => 'PHP_CRYPTO_ALG_E',
			),
			'Crypto\Base64Exception' => array(
				'file' => '/php_crypto_base64.h',
				'macro' => 'PHP_CRYPTO_BASE64_E',
			),
		)
	);

	private $s = array();

	private function getFile($name) {
		$path = dirname(__DIR__) . $name;
		return new SplFileObject($path);
	}
	
	private function makeClasses() {
		foreach ($this->conf['classes'] as $c) {
			$this->s[$c['name']] = $c;
		}
	}

	private function makeConstants() {
		foreach ($this->conf['constants'] as $cname => $conf) {
			$macro = $conf['macro'];
			$file = $this->getFile($conf['file']);
			$value = 1;
			$c = array();
			foreach ($file as $line) {
				if ((strpos(trim($line), $macro) === 0) && preg_match("/$macro\(([^)]*)/", $line, $matches)) {
					$c[] = array( 'name' => $matches[1], 'value' => $value++ );
				}
			}
			$this->s[$cname]['constants'] = $c;
		}
	}

	private function makeMethods() {
		foreach ($this->conf['methods']['files'] as $fname) {
			$file = $this->getFile($fname);
			$nextComment = false;
			foreach ($file as $line) {
				if ($nextComment) {
					$comment = trim($line);
					if (strlen($comment) >= 2 && substr($comment, -2) == '*/') {
						$comment = substr($comment, 0, -2);
						$m['description'] = trim($m['description'] . ' ' . $comment);
						$this->s[$cname]['methods'][] = $m;
						$nextComment = false;
					} else {
						$m['description'] .= ' ' . $comment;
					}
				}
				elseif (preg_match("/proto\s+(static\s+)?(\w+\s+)?([^:]+)::(\w+)\((.*)\)/", $line, $matches)) {
					$params = array();
					if (strlen($matches[5])) {
						$pss = explode(',', $matches[5]);
						foreach ($pss as $ps) {
							list($ptn, $pdefault) = strpos($ps, '=') ? explode('=', $ps) : array($ps, null);
							if (!is_null($pdefault))
								$pdefault = trim($pdefault);
							list ($ptype, $pname) = explode(' ', trim($ptn));
							if ($ptype{0} == '&') {
								$isref = true;
								$ptype = substr($ptype, 1);
							} else {
								$isref = false;
							}	
							
							$params[] = array(
								'name' => $pname,
								'type' => $ptype,
								'default' => $pdefault,
								'isref' => $isref,
							);
						}
					}
					$cname = $matches[3];
					$m = array(
						'prefix' => empty($matches[1]) ? 'public' : 'public static',
						'name' => $matches[4],
						'params' => $params,
						'return' => empty($matches[2]) ? null : rtrim($matches[2]),
						'description' => '',
					);
					if (!strpos($line, '*/'))
						$nextComment = true;
					else
						$this->s[$cname]['methods'][] = $m;
				}
			}
		}
	}

	public function make() {
		$this->makeClasses();
		$this->makeConstants();
		$this->makeMethods();
	}

	private function out() {
		$args = func_get_args();
		if (empty($args))
			$args = array('');
		$indent = str_repeat($this->indent_str, $this->indent);
		$pattern = $indent . $args[0] . PHP_EOL;
		if (count($args) > 1)
			vprintf($pattern, array_splice($args, 1));
		else
			echo $pattern;
	}

	private function ckey_exists($key, $c) {
		return isset($c[$key]) && is_array($c[$key]) && count($c[$key]) > 0;
	}
	
	public function generatePHP() {
		$this->indent = 0;
		foreach ($this->s as $c) {
			$cprefix = isset($c['prefix']) && strlen($c['prefix']) ? $c['prefix'] . ' ' : '';
			$this->out('/**');
			$this->out(' * %s', $c['description']);
			$this->out(' */');
			$extends = isset($c['parent']) ? ' extends ' . $c['parent'] : '';
			$this->out('%sclass %s%s {', $cprefix, $c['name'], $extends);
			$this->indent++;
			// constants
			if ($this->ckey_exists('constants', $c)) {
				foreach ($c['constants'] as $const) {
					$this->out('const %s = %s;', $const['name'], $const['value']);
				}
				$this->out();
			}
			// vars
			if ($this->ckey_exists('vars', $c)) {
				foreach ($c['vars'] as $v) {
					$this->out('/**');
					$this->out(' * %s', $v['description']);
					$this->out(' * @var %s', $v['type']);
					$this->out(' */');
					$this->out('%s %s;', $v['prefix'], $v['name']);
					$this->out();
				}
			}
			// methods
			if ($this->ckey_exists('methods', $c)) {
				foreach ($c['methods'] as $m) {
					$this->out('/**');
					$this->out(' * %s', $m['description']);
					$params = array();
					if ($this->ckey_exists('params', $m)) {
						foreach ($m['params'] as $p) {
							$this->out(' * @param %s %s', $p['type'], $p['name']);
							$params[] = ($p['isref'] ? '&' : '') . $p['name'] . (isset($p['default']) && strlen($p['default']) ? ' = ' . $p['default'] : '');
						}
					}
					if (isset($m['return']) && !is_null($m['return'])) {
						$this->out(' * @return %s', ($m['return'] == 'void' ? 'null' : $m['return']));
					}
					$this->out(' */');
					$mdef = strpos($m['prefix'], 'abstract') === false ? ' {}' : ';';
					$this->out('%s function %s(%s)%s', $m['prefix'], $m['name'], implode(', ', $params), $mdef);
					$this->out();
				}
			}
			$this->indent--;
			$this->out('}');
			$this->out();
		}
	}

}

$apidoc = new Apidoc;
$apidoc->make();
$apidoc->generatePHP();
