<?php

namespace keurope\jwt;

use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Decoder;
use Lcobucci\JWT\Encoder;
use Lcobucci\JWT\Parser;
use Lcobucci\JWT\Signer;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\PermittedFor;
use Lcobucci\JWT\Validation\Constraint\IdentifiedBy;
use Yii;
use yii\base\Component;
use yii\base\InvalidArgumentException;


class Jwt extends Component
{

    /**
     * @var array Supported algorithms
     */
    public $supportedAlgs = [
        'HS256' => \Lcobucci\JWT\Signer\Hmac\Sha256::class,
        'HS384' => \Lcobucci\JWT\Signer\Hmac\Sha384::class,
        'HS512' => \Lcobucci\JWT\Signer\Hmac\Sha512::class,
        'ES256' => \Lcobucci\JWT\Signer\Ecdsa\Sha256::class,
        'ES384' => \Lcobucci\JWT\Signer\Ecdsa\Sha384::class,
        'ES512' => \Lcobucci\JWT\Signer\Ecdsa\Sha512::class,
        'RS256' => \Lcobucci\JWT\Signer\Rsa\Sha256::class,
        'RS384' => \Lcobucci\JWT\Signer\Rsa\Sha384::class,
        'RS512' => \Lcobucci\JWT\Signer\Rsa\Sha512::class,
    ];

    /**
     * @var Key|string $key The key either file location like file:// or string for symetric keys
     */
    public $key;

    /**
     * @var Aud|string $aud The audience claim
     */
    public $aud;

    /**
     * @var Iss|string $iss The IssuedBy claim
     */
    public $iss;

    /**
     * @var Alg|string $alg The encription algorithm
     */
    public $alg;

    /**
     * @var Jti|string $jti The IdentifiedBy claim
     */
    public $jti;


    private Configuration $config;

    public function init()
    {
        if (!$this->alg) {
            throw new InvalidArgumentException("JWT signer algorithm must be set");
        } elseif (in_array($this->alg, ['HS256', 'HS384', 'HS512'])) {
            $this->config = Configuration::forSymmetricSigner($this->getSigner(), $this->getKey());
        } else {
            $this->config = Configuration::forAsymmetricSigner($this->getSigner(), $this->getKey());
        }

        $validationConstaints[] = new SignedWith($this->config->signer(), $this->config->signingKey());
        if($this->iss != null)
            $validationConstaints[] = new IssuedBy($this->iss);
        if($this->aud != null)
            $validationConstaints[] = new PermittedFor($this->aud);
        if($this->jti != null)
            $validationConstaints[] = new IdentifiedBy($this->jti);

        $this->config->setValidationConstraints(...$validationConstaints);
    }

    /**
     * @return Builder
     * @see [[Lcobucci\JWT\Builder::__construct()]]
     */
    public function getBuilder()
    {
        return $this->config->builder();
    }

    /**
     * @return Parser
     * @see [[Lcobucci\JWT\Parser::__construct()]]
     */
    public function getParser()
    {
        return $this->config->parser();
    }

    /**
     * @param string $alg
     * @return Signer
     */
    public function getSigner($alg = null)
    {
        $alg = $alg ?: $this->alg;
        $class = $this->supportedAlgs[$alg];

        return new $class();
    }

    /**
     * @param strng $content
     * @return Key
     */
    public function getKey($content = null)
    {
        $content = $content ?: $this->key;

        if (strpos($content, 'file://') === 0) {
            return InMemory::file($content);
        }

        return InMemory::plainText($content);
    }

    /**
     * Parses the JWT and returns a token class
     * @param string $token JWT
     * @return Token|null
     * @throws \Throwable
     */
    public function loadToken($token)
    {
        try {
            $token = $this->config->parser()->parse((string)$token);
        } catch (\RuntimeException $e) {
            Yii::warning('Invalid JWT provided: ' . $e->getMessage(), 'jwt');
            return null;
        } catch (\InvalidArgumentException $e) {
            Yii::warning('Invalid JWT provided: ' . $e->getMessage(), 'jwt');
            return null;
        }

        if (!$this->config->validator()->validate($token, ...$this->config->validationConstraints())) {
            return null;
        }

        return $token;
    }


    /**
     * @param Signer $signer
     * @param Key $key
     * @param Encoder|null $encoder
     * @param Decoder|null $decoder
     * @return Configuration
     */
    public function getConfigurationForSymmetricSigner(Signer $signer, Key $key, Encoder $encoder = null, Decoder $decoder = null)
    {
        return Configuration::forSymmetricSigner($signer, $key, $encoder, $decoder);
    }

    /**
     * @param Signer $signer
     * @param Key $signingKey
     * @param Key $verificationKey
     * @param Encoder|null $encoder
     * @param Decoder|null $decoder
     * @return Configuration
     */
    public function getConfigurationForAsymmetricSigner(Signer $signer, Key $signingKey, Key $verificationKey, Encoder $encoder = null, Decoder $decoder = null)
    {
        return Configuration::forAsymmetricSigner($signer, $signingKey, $verificationKey, $encoder, $decoder);
    }
}
