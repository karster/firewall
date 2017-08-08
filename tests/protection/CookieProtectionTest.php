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

    /**
     * @dataProvider safeDataProvider
     */
    public function testRunProtectionWithSafeInput($method)
    {
        $_COOKIE['item'] = $method;
        $this->cookieProtection->setRules(['onunload', 'onblur']);
        $result = $this->cookieProtection->protect();

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
        $_COOKIE['item'] = $method;
        $this->cookieProtection->setRules(['onunload', 'onblur']);
        $result = $this->cookieProtection->protect();

        $this->assertTrue($result);
    }

    public function dangerDataProvider()
    {
        return [['onunload="attack();"'],['onblur="void(0);']];
    }
}