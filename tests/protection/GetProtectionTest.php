<?php

namespace karster\security\tests\protection;

use karster\security\protection\GetProtection;
use karster\security\tests\TestCase;

class GetProtectionTest extends TestCase
{
    /**
     * @var GetProtection
     */
    private $getProtection;

    public function setUp()
    {
        $this->getProtection = new GetProtection();
    }

    public function testProtect()
    {
        $this->markTestIncomplete(
            'This test has not been implemented yet.'
        );
    }
}