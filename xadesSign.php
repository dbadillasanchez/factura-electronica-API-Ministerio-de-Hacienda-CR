 <?php
 
 namespace sasco\LibreDTE;
  
	class FirmaElectronica
	{
  
	   private $config; 
	   private $certs; 
	   private $data; 
  
	   public function __construct(array $config = [])
	   {
		   	// crear configuración
		   	if (!$config) {
		   		if (class_exists('\sowerphp\core\Configure')) {
		   			$config = (array)\sowerphp\core\Configure::read('firma_electronica.default');
		   		} else {
		   			$config = [];
   				}
   			}

		   $this->config = array_merge([
							   'file' => null,
							   'pass' => null,
							   'data' => null,
							   'wordwrap' => 64,
   							], $config);

		   // cargar firma electrónica desde el contenido del archivo .p12 si no
		   // se pasaron como datos del arreglo de configuración
   		   if (!$this->config['data'] and $this->config['file']) {
   				if (is_readable($this->config['file'])) {
   					$this->config['data'] = file_get_contents($this->config['file']);
   				} else {
   					return $this->error('Archivo de la firma electrónica '.basename($this->config['file']).' no puede ser leído');
   				}
   			}
   			// leer datos de la firma electrónica
   			if ($this->config['data'] and openssl_pkcs12_read($this->config['data'], $this->certs, $this->config['pass'])===false) {
   				return $this->error('No fue posible leer los datos de la firma electrónica (verificar la contraseña)');
   			}
   			$this->data = openssl_x509_parse($this->certs['cert']);
   			// quitar datos del contenido del archivo de la firma
   			unset($this->config['data']);
   		}
  
	   private function error($msg)
	   {
   			if (class_exists('\sasco\LibreDTE\Estado') and class_exists('\sasco\LibreDTE\Log')) {
   				$msg = \sasco\LibreDTE\Estado::get(\sasco\LibreDTE\Estado::FIRMA_ERROR, $msg);
   					\sasco\LibreDTE\Log::write(\sasco\LibreDTE\Estado::FIRMA_ERROR, $msg);
   				return false;
   			} else {
   			throw new \Exception($msg);
   			}
   		}
  
	   private function normalizeCert($cert)
	   {
		   if (strpos($cert, '-----BEGIN CERTIFICATE-----')===false) {
			   $body = trim($cert);
			   $cert = '-----BEGIN CERTIFICATE-----'."\n";
			   $cert .= wordwrap($body, $this->config['wordwrap'], "\n", true)."\n";
			   $cert .= '-----END CERTIFICATE-----'."\n";
		   }
		   return $cert;
		}
  
	   public function getID()
	   {
		   // RUN/RUT se encuentra en la extensión del certificado, esto de acuerdo
		   // a Ley 19.799 sobre documentos electrónicos y firma electrónica
		   $x509 = new \phpseclib\File\X509();
		   $cert = $x509->loadX509($this->certs['cert']);
		   if (isset($cert['tbsCertificate']['extensions'])) {
		   		foreach ($cert['tbsCertificate']['extensions'] as $e) {
		   			if ($e['extnId']=='id-ce-subjectAltName') {
		   				return ltrim($e['extnValue'][0]['otherName']['value']['ia5String'], '0');
		   			}
		   		}
	   		}
	   		// se obtiene desde serialNumber (esto es sólo para que funcione la firma para tests)
	   		if (isset($this->data['subject']['serialNumber'])) {
	   			return ltrim($this->data['subject']['serialNumber'], '0');
	   		}
   			// no se encontró el RUN
   			return $this->error('No fue posible obtener el ID de la firma');
  		}
  
	   public function getName()
	   {
		   if (isset($this->data['subject']['CN']))
		   		return $this->data['subject']['CN'];
		   		return $this->error('No fue posible obtener el Name (subject.CN) de la firma');
	   }
  
	   public function getEmail()
	   {
	   		if (isset($this->data['subject']['emailAddress']))
	   			return $this->data['subject']['emailAddress'];
	   			return $this->error('No fue posible obtener el Email (subject.emailAddress) de la firma');
	   }
  
	   public function getFrom()
	   {
	   		return date('Y-m-d H:i:s', $this->data['validFrom_time_t']);
	   }
  
	   public function getTo()
	   {
	   		return date('Y-m-d H:i:s', $this->data['validTo_time_t']);
	   }
  
	   public function getIssuer()
	   {
	   		return $this->data['issuer']['CN'];
	   }
  
	   public function getData()
	   {
	   		return $this->data;
	   }
  
	   public function getModulus()
	   {
	   		$details = openssl_pkey_get_details(openssl_pkey_get_private($this->certs['pkey']));
	   		return wordwrap(base64_encode($details['rsa']['n']), $this->config['wordwrap'], "\n", true);
	   }
  
	   public function getExponent()
	   {
	   		$details = openssl_pkey_get_details(openssl_pkey_get_private($this->certs['pkey']));
	   		return wordwrap(base64_encode($details['rsa']['e']), $this->config['wordwrap'], "\n", true);
	   }
  
	   public function getCertificate($clean = false)
	   {
	   		if ($clean) {
	   			return trim(str_replace(
	   				['-----BEGIN CERTIFICATE-----', '-----END CERTIFICATE-----'],
	   				'',
	   				$this->certs['cert']
	   			));
	   		} else {
	   			return $this->certs['cert'];
	   		}
	   }
  
	   public function getPrivateKey($clean = false)
	   {
		   if ($clean) {
			   return trim(str_replace(
			   ['-----BEGIN PRIVATE KEY-----', '-----END PRIVATE KEY-----'],
			   '',
			   $this->certs['pkey']
			   ));
		   } else {
		   		return $this->certs['pkey'];
		   }
	   }
  
	   public function sign($data, $signature_alg = OPENSSL_ALGO_SHA1)
	   {
		   $signature = null;
		   if (openssl_sign($data, $signature, $this->certs['pkey'], $signature_alg)==false) {
		   		return $this->error('No fue posible firmar los datos');
		   }
		   return base64_encode($signature);
   		}
  
	   public function verify($data, $signature, $pub_key = null, $signature_alg = OPENSSL_ALGO_SHA1)
	   {
		   if ($pub_key === null)
			   $pub_key = $this->certs['cert'];
			   $pub_key = $this->normalizeCert($pub_key);
			   return openssl_verify($data, base64_decode($signature), $pub_key, $signature_alg) == 1 ? true : false;
	   }
  
	   public function signXML($xml, $reference = '', $tag = null, $xmlns_xsi = false)
	   {
		   $doc = new XML();
		   $doc->loadXML($xml);
		   if (!$doc->documentElement) {
		   		return $this->error('No se pudo obtener el documentElement desde el XML a firmar (posible XML mal formado)');
	   		}
		   // crear nodo para la firma
		   $Signature = $doc->importNode((new XML())->generate([
			   'Signature' => [
			   		'@attributes' => [
			   			'xmlns' => 'http://www.w3.org/2000/09/xmldsig#',
		   			],
			   		'SignedInfo' => [
			   			'@attributes' => [
			   				'xmlns' => 'http://www.w3.org/2000/09/xmldsig#',
			   				'xmlns:xsi' => $xmlns_xsi ? 'http://www.w3.org/2001/XMLSchema-instance' : false,
		   				],
			   		'CanonicalizationMethod' => [
			   			'@attributes' => [
			   				'Algorithm' => 'http://www.w3.org/TR/2001/REC-xml-c14n-20010315',
		   				],
		   			],
		   			'SignatureMethod' => [
		   				'@attributes' => [
		   					'Algorithm' => 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
		   				],
		   			],
		   			'Reference' => [
		   				'@attributes' => [
		   					'URI' => $reference,
		   				],
		   				'Transforms' => [
		   					'Transform' => [
		   						'@attributes' => [
		   							'Algorithm' => 'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
		   						],
		   					],
		   				],
		   				'DigestMethod' => [
		   					'@attributes' => [
		   						'Algorithm' => 'http://www.w3.org/2000/09/xmldsig#sha1',
		   					],
		   				],
		   				'DigestValue' => null,
		   				],
		   			],
		   			'SignatureValue' => null,
		   			'KeyInfo' => [
		   				'KeyValue' => [
		   					'RSAKeyValue' => [
		   						'Modulus' => null,
		   						'Exponent' => null,
		   					],
		   				],
		   				'X509Data' => [
		   					'X509Certificate' => null,
		   				],
		   			],
		   		],
		   ])->documentElement, true);
		   // calcular DigestValue
		   if ($tag) {
			   $item = $doc->documentElement->getElementsByTagName($tag)->item(0);
			   if (!$item) {
			   		return $this->error('No fue posible obtener el nodo con el tag '.$tag);
		   		}
		   		$digest = base64_encode(sha1($item->C14N(), true));
		   } else {
		   		$digest = base64_encode(sha1($doc->C14N(), true));
		   }

		   $Signature->getElementsByTagName('DigestValue')->item(0)->nodeValue = $digest;
		   // calcular SignatureValue
		   $SignedInfo = $doc->saveHTML($Signature->getElementsByTagName('SignedInfo')->item(0));
		   $firma = $this->sign($SignedInfo);

		   if (!$firma)
		   		return false;

		   $signature = wordwrap($firma, $this->config['wordwrap'], "\n", true);
		   // reemplazar valores en la firma de
		   $Signature->getElementsByTagName('SignatureValue')->item(0)->nodeValue = $signature;
		   $Signature->getElementsByTagName('Modulus')->item(0)->nodeValue = $this->getModulus();
		   $Signature->getElementsByTagName('Exponent')->item(0)->nodeValue = $this->getExponent();
		   $Signature->getElementsByTagName('X509Certificate')->item(0)->nodeValue = $this->getCertificate(true);
		   // agregar y entregar firma
		   $doc->documentElement->appendChild($Signature);
		   return $doc->saveXML();
		}
  
	   public function verifyXML($xml_data, $tag = null)
	   {
		   $doc = new XML();
		   $doc->loadXML($xml_data);
		   // preparar datos que se verificarán
		   $SignaturesElements = $doc->documentElement->getElementsByTagName('Signature');
		   $Signature = $doc->documentElement->removeChild($SignaturesElements->item($SignaturesElements->length-1));
		   $SignedInfo = $Signature->getElementsByTagName('SignedInfo')->item(0);
		   $SignedInfo->setAttribute('xmlns', $Signature->getAttribute('xmlns'));
		   $signed_info = $doc->saveHTML($SignedInfo);
		   $signature = $Signature->getElementsByTagName('SignatureValue')->item(0)->nodeValue;
		   $pub_key = $Signature->getElementsByTagName('X509Certificate')->item(0)->nodeValue;
		   // verificar firma
		   if (!$this->verify($signed_info, $signature, $pub_key))
		   		return false;
		   // verificar digest
		   $digest_original = $Signature->getElementsByTagName('DigestValue')->item(0)->nodeValue;
		   if ($tag) {
		   		$digest_calculado = base64_encode(sha1($doc->documentElement->getElementsByTagName($tag)->item(0)->C14N(), true));
		   } else {
		    	$digest_calculado = base64_encode(sha1($doc->C14N(), true));
		   }
		   return $digest_original == $digest_calculado;
	   }
  
	   public static function getFromModulusExponent($modulus, $exponent)
	   {
		   $rsa = new \phpseclib\Crypt\RSA();
		   $modulus = new \phpseclib\Math\BigInteger(base64_decode($modulus), 256);
		   $exponent = new \phpseclib\Math\BigInteger(base64_decode($exponent), 256);
		   $rsa->loadKey(['n' => $modulus, 'e' => $exponent]);
		   $rsa->setPublicKey();
		   return $rsa->getPublicKey();
	   }
  
  
  	}