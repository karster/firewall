<?php

namespace karster\security\tests\protection;

use karster\security\protection\CookieProtection;
use karster\security\tests\TestCase;

class CookieProtectionTest extends TestCase
{
    /**
     * @var CookieProtection
     */
    private $cookieProtection;

    public function setUp()
    {
        $this->cookieProtection = new CookieProtection();
    }

    public function testProtect()
    {
        $this->markTestIncomplete(
            'This test has not been implemented yet.'
        );
    }
}