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

    /**
     * @dataProvider safeDataProvider
     */
    public function testRunProtectionWithSafeInput($method)
    {
        $_SESSION['item'] = $method;
        $this->sessionProtection->setRules(['onunload', 'onblur']);
        $result = $this->sessionProtection->protect();

        $this->assertFalse($result);

    }

    public function safeDataProvider()
    {
        return [['bar'],['foo']];
    }

    /**
     * @dataProvider dangerDataProvider
     */
    public function testRunProtectionWithDangerInput($method)
    {
        $_SESSION['item'] = $method;
        $this->sessionProtection->setRules(['onunload', 'onblur']);
        $result = $this->sessionProtection->protect();

        $this->assertTrue($result);
    }

    public function dangerDataProvider()
    {
        return [['onunload="attack();"'],['onblur="void(0);']];
    }
}