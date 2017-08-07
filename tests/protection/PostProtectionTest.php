<?php

namespace karster\security\tests\protection;

use karster\security\protection\PostProtection;
use karster\security\tests\TestCase;

class PostProtectionTest extends TestCase
{
    /**
     * @var PostProtection
     */
    private $postProtection;

    public function setUp()
    {
        $this->postProtection = new PostProtection();
    }

    public function testProtect()
    {
        $this->markTestIncomplete(
            'This test has not been implemented yet.'
        );
    }
}