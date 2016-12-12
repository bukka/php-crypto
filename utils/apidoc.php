<?php

class Apidoc {

	private $indent = 0;
	private $indent_str = "    ";
	private $description_width = 80;
	
	private $conf = array(
		'classes' => array(
			array(
				'name' => 'Crypto\Cipher',
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
				'name' => 'Crypto\CipherException',
				'parent' => 'Exception',
				'description' => 'Exception class for cipher errors',
			),
			array(
				'name' => 'Crypto\Hash',
				'description' => 'Class providing hash algorithms',
			),
			array(
				'name' => 'Crypto\HashException',
				'parent' => 'Exception',
				'description' => 'Exception class for hash errors',
			),
			array(
				'name' => 'Crypto\MAC',
				'abstract' => true,
				'parent' => 'Crypto\Hash',
				'description' => 'Abstract class for MAC subclasses',
			),
			array(
				'name' => 'Crypto\MACException',
				'parent' => 'Crypto\HashException',
				'description' => 'Exception class for MAC errors',
			),
			array(
				'name' => 'Crypto\HMAC',
				'parent' => 'Crypto\MAC',
				'description' => 'Class providing HMAC functionality',
			),
			array(
				'name' => 'Crypto\CMAC',
				'parent' => 'Crypto\MAC',
				'description' => 'Class providing CMAC functionality',
			),
			array(
				'name' => 'Crypto\KDF',
				'abstract' => true,
				'description' => 'Abstract class for KDF subclasses',
			),
			array(
				'name' => 'Crypto\KDFException',
				'description' => 'Exception class for KDF errors',
			),
			array(
				'name' => 'Crypto\PBKDF2',
				'parent' => 'Crypto\KDF',
				'description' => 'Class providing PBKDF2 functionality',
			),
			array(
				'name' => 'Crypto\PBKDF2Exception',
				'parent' => 'Crypto\KDFException',
				'description' => 'Exception class for PBKDF2 errors',
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
			array(
				'name' => 'Crypto\RandException',
				'parent' => 'Exception',
				'description' => 'Exception class for rand errors',
			),
		),
		'methods' => array(
			'files' => array(
				'/crypto_cipher.c',
				'/crypto_hash.c',
				'/crypto_kdf.c',
				'/crypto_base64.c',
				'/crypto_rand.c'
			),
			'macro' => 'PHP_CRYPTO_METHOD',
		),
		'constants' => array(
			'exceptions' => array(
				'Crypto\CipherException' => array(
					'name' => 'Cipher',
					'file' => '/crypto_cipher.c',
				),
				'Crypto\HashException' => array(
					'name' => 'Hash',
					'file' => '/crypto_hash.c',
				),
				'Crypto\MACException' => array(
					'name' => 'MAC',
					'file' => '/crypto_hash.c',
				),
				'Crypto\KDFException' => array(
					'name' => 'KDF',
					'file' => '/crypto_kdf.c',
				),
				'Crypto\PBKDF2Exception' => array(
					'name' => 'PBKDF2',
					'file' => '/crypto_kdf.c',
				),
				'Crypto\Base64Exception' => array(
					'name' => 'Base64',
					'file' => '/crypto_base64.c',
				),
				'Crypto\RandException' => array(
					'name' => 'Rand',
					'file' => '/crypto_rand.c',
				),

			),
			'macros' => array(
				'begin' => 'PHP_CRYPTO_ERROR_INFO_BEGIN',
				'end'   => 'PHP_CRYPTO_ERROR_INFO_END',
				'entry' => 'PHP_CRYPTO_ERROR_INFO_ENTRY',
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
		$macros = $this->conf['constants']['macros'];
		foreach ($this->conf['constants']['exceptions'] as $cname => $conf) {
			$file = $this->getFile($conf['file']);
			$begin = sprintf("%s(%s)", $macros['begin'], $conf['name']);
			$value = 1;
			$state = -1;
			$c = array();
			foreach ($file as $line) {
				switch ($state) {
				case -1:
					if ((strpos($line, $begin) !== false)) {
						$state = 0;
					}
					break;
				case 0:
					if ((strpos($line, $macros['entry']) !== false)) {
						$state = 1;
					} elseif ((strpos($line, $macros['end']) !== false)) {
						// ignore the rest of the file
						$state = 100;
					}
					break;
				case 1:
					$name = rtrim(trim($line), ",");
					$desc = "";
					$state = 2;
					break;
				case 2:
					$tline = trim($line);
					if ($tline === ")") {
						$c[] = array(
							'name'        => $name,
							'value'       => $value++,
							'description' => $desc,
						);
						$state = 0;
					} else {
						$desc .= trim($tline, '"');
					}
					break;
				}
			}
			$this->s[$cname]['constants'] = $c;
		}
	}

	private function makeMethods() {
		$protoPattern = "/proto\s+(static\s+)?(\w+\s+)?([^:]+)::(\w+)\((.*)\)/";
		foreach ($this->conf['methods']['files'] as $fname) {
			$file = $this->getFile($fname);
			$nextComment = false;
			$nextProto = false;
			$proto = '';
			foreach ($file as $line) {
				$tline = trim($line);
				if ($nextComment) {
					$comment = $tline;
					if (strlen($comment) >= 2 && substr($comment, -2) == '*/') {
						$comment = substr($comment, 0, -2);
						$m['description'] = trim($m['description'] . ' ' . $comment);
						$this->s[$cname]['methods'][] = $m;
						$nextComment = false;
					} else {
						$m['description'] .= ' ' . $comment;
					}
				}
				elseif ($nextProto || strpos($tline, '{{{ proto') !== false) {
					$nextProto = ($tline[strlen($tline) - 1] !== ')');
					$proto .= ' ' . $tline;
				}

				if (!$nextProto && $proto) {
					if (preg_match($protoPattern, $proto, $matches)) {
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
					$proto = '';
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

	private function splitDescription($desc) {
	    return explode("\n", wordwrap($desc, $this->description_width));
	}

	private function outDescriptionPHP($description) {
		$descs = $this->splitDescription($description);
		foreach ($descs as $desc) {
			$this->out(' * %s', $desc);
		}
	}
	
	public function generatePHP() {
		$this->indent = 0;
		$this->out("<?php");
		foreach ($this->s as $c) {
			$cprefix = isset($c['prefix']) && strlen($c['prefix']) ? $c['prefix'] . ' ' : '';
			if (isset($c['abstract']) && $c['abstract']) {
				$cprefix = 'abstract ' . $cprefix;
			}
			$this->out('/**');
			$this->out(' * %s', $c['description']);
			$this->out(' */');
			$extends = isset($c['parent']) ? ' extends ' . $c['parent'] : '';
			$this->out('%sclass %s%s {', $cprefix, $c['name'], $extends);
			$this->indent++;
			// constants
			if ($this->ckey_exists('constants', $c)) {
				foreach ($c['constants'] as $const) {
					if (isset($const['description'])) {
						$this->out();
						$this->out('/**');
						$this->outDescriptionPHP($const['description']);
						$this->out(' */');
					}
					$this->out('const %s = %s;', $const['name'], $const['value']);
				}
				$this->out();
			}
			// vars
			if ($this->ckey_exists('vars', $c)) {
				foreach ($c['vars'] as $v) {
					$this->out('/**');
					$this->out(' * %s', $v['description']);
					$this->outDescriptionPHP($v['description']);
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
					$this->outDescriptionPHP($m['description']);
					$params = array();
					if ($this->ckey_exists('params', $m)) {
						foreach ($m['params'] as $p) {
							$this->out(' * @param %s %s', $p['type'], $p['name']);
							$params[] = ($p['isref'] ? '&' : '') . $p['name']
								. (isset($p['default']) && strlen($p['default']) ? ' = ' . $p['default'] : '');
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
