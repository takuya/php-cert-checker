<?php

namespace Test\Feature;

use Tests\TestCase;
use Takuya\PhpCertChecker\CertificateChecker;


class GetCertificateTest extends TestCase {
  public function test_get_certificate () {
    $domain = "apple.com";
    $ret = CertificateChecker::getCertificate( $domain );
    $this->assertEquals( \OpenSSLCertificate::class, get_class( $ret ) );
    
    $checker = new CertificateChecker( $domain );
    $this->assertArrayHasKey( 'extensions', $checker->getCertInfo() );
    $this->assertArrayHasKey( 'issuer', $checker->getCertInfo() );
    $this->assertArrayHasKey( 'subject', $checker->getCertInfo() );
    $this->assertArrayHasKey( 'validTo', $checker->getCertInfo() );
    $this->assertArrayHasKey( 'validFrom', $checker->getCertInfo() );
    $this->assertArrayHasKey( 'from', $checker->getValidThru() );
    $this->assertArrayHasKey( 'to', $checker->getValidThru() );
    $this->assertInstanceOf( \DateTime::class, $checker->getValidThru()['from'] );
    $this->assertInstanceOf( \DateTime::class, $checker->getValidThru()['to'] );
    $this->assertInstanceOf( \DateTime::class, $checker->getExpiredAt() );
    $this->assertEquals( $domain, $checker->getSubjectAltName() );
    $this->assertContains( $domain, $checker->getSubjectDomainNames() );
    $this->assertEquals( CertificateChecker::getCertExpiredTime( $domain ),
      $checker->getExpiredAt() );
    
    $this->assertFalse( $checker->isCertExpired() );
    $this->assertGreaterThan( 0, $checker->getDaysRemains() );
  }
}