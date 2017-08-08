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

    /**
     * @dataProvider safeDataProvider
     */
    public function testRunProtectionWithSafeInput($method)
    {
        $_GET['item'] = $method;
        $this->getProtection->setRules(['onunload', 'onblur']);
        $result = $this->getProtection->protect();

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
        $_GET['item'] = $method;
        $this->getProtection->setRules(['onunload', 'onblur']);
        $result = $this->getProtection->protect();

        $this->assertTrue($result);
    }

    public function dangerDataProvider()
    {
        return [['onunload="attack();"'],['onblur="void(0);']];
    }
}