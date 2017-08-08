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

    /**
     * @dataProvider safeDataProvider
     */
    public function testRunProtectionWithSafeInput($method)
    {
        $_POST['item'] = $method;
        $this->postProtection->setRules(['onunload', 'onblur']);
        $result = $this->postProtection->protect();

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
        $_POST['item'] = $method;
        $this->postProtection->setRules(['onunload', 'onblur']);
        $result = $this->postProtection->protect();

        $this->assertTrue($result);
    }

    public function dangerDataProvider()
    {
        return [['onunload="attack();"'],['onblur="void(0);']];
    }
}