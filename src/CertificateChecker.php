<?php

namespace Takuya\PhpCertChecker;

use DateTime;
use RuntimeException;

class CertificateChecker {
  
  protected string $domain;
  protected array $certInfo;
  protected \OpenSSLCertificate $cert;
  
  public function __construct ( string $domain ) {
    $this->setDomain( $domain );
    $this->cert = self::getCertificate( $domain );
    $this->certInfo = $this->parse_cert( $this->cert );
  }
  
  public function setDomain ( string $domain ) {
    $this->domain = $domain;
  }
  
  public function getDaysRemains (): string {
    return $this->getExpiredAt()->diff( new DateTime() )->format( "%a" );
  }
  
  public function getSubjectAltName (): ?string {
    $alt = $this->certInfo['extensions']['subjectAltName'];
    preg_match_all( '/DNS:([^,$]+)/', $alt, $m );
    return sizeof( $m ) > 1 ? $m[1][0] : null;
  }
  
  public function getCN (): string {
    return $this->certInfo['subject']['CN'];
  }
  
  public function getSubjectDomainNames (): array {
    $cn = $this->getCN();
    $alt = [$this->getSubjectAltName()];
    return array_unique( array_merge( [$cn], $alt ) );
  }
  
  public static function getCertificate ( $domain, $port = 443 ): \OpenSSLCertificate {
    if ( empty( $domain ) ) {
      throw new RuntimeException( 'domain name args ($domain) required' );
    }
    $addr = "tls://${domain}:${port}";
    $ctx = stream_context_create( [
      'ssl' => [
        'verify_peer_name' => false,
        'verify_peer' => false,
        'capture_peer_cert' => true,
      ],
    ] );
    $fp = stream_socket_client(
      $addr, $errno, $err_msg, 5, STREAM_CLIENT_CONNECT, $ctx );
    $result = stream_context_get_params( $fp );
    return $result['options']['ssl']['peer_certificate'];
  }
  
  protected function parse_cert ( \OpenSSLCertificate $cert ): bool|array {
    $cert_info = openssl_x509_parse( $cert );
    return $cert_info;
  }
  
  public function getCertInfo (): array {
    return $this->certInfo;
  }
  
  public function getValidThru (): array {
    return [
      'from' => $this->getValidFrom(),
      'to' => $this->getExpiredAt(),
    ];
  }
  
  public function getValidFrom (): DateTime {
    return ( new DateTime() )
      ->setTimestamp( $this->certInfo["validFrom_time_t"] )
      ->setTime( 0, 0, 0 );
  }
  
  public function getExpiredAt (): DateTime {
    return ( new DateTime() )
      ->setTimestamp( $this->certInfo["validTo_time_t"] )
      ->setTime( 0, 0, 0 );
  }
  
  public function isCertExpired ( $date = "today" ): bool {
    $due_date = $this->getExpiredAt();
    return ( $due_date <= ( new DateTime() )->setTimestamp( strtotime( $date ) ) );
  }
  
  public static function getCertExpiredTime ( $domain ): DateTime {
    $cert = static::getCertificate( $domain );
    $cert_info = openssl_x509_parse( $cert );
    $expired_at_time_t = $cert_info["validTo_time_t"];
    return ( new DateTime() )
      ->setTimestamp( $expired_at_time_t )
      ->setTime( 0, 0, 0 );
  }
}