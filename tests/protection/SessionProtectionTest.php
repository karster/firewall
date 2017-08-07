<?php

namespace karster\security\tests\protection;

use karster\security\protection\SessionProtection;
use karster\security\tests\TestCase;

class SessionProtectionTest extends TestCase
{
    /**
     * @var SessionProtection
     */
    private $sessionProtection;

    public function setUp()
    {
        $this->sessionProtection = new SessionProtection();
    }

    public function testProtect()
    {
        $this->markTestIncomplete(
            'This test has not been implemented yet.'
        );
    }
}