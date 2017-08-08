<?php

namespace karster\security\tests\protection;

use karster\security\protection\AllowedGlobals;
use karster\security\tests\TestCase;

class AllowedGlobalsTest extends TestCase
{
    /**
     * @var AllowedGlobals
     */
    private $allowedGlobals;

    public function setUp()
    {
        $this->allowedGlobals = new AllowedGlobals();
    }

    /**
     * @dataProvider setRulesProvider
     *
     * @access public
     */
    public function testSetRules($actual, $expected)
    {
        $this->allowedGlobals->setRules($actual);
        $result = $this->allowedGlobals->getRules();

        $this->assertEquals($expected, $result);
    }

    public function setRulesProvider()
    {
        return [
            [
                ['_post', '_session', '_Get'],
                ['_POST', '_SESSION', '_GET', 'GLOBALS']
            ]
        ];
    }

    /**
     * @dataProvider safeDataProvider
     */
    public function testRunProtectionWithSafeInput($method)
    {
        $_POST['title'] = $method;
        $_GET['password'] = $method;
        $this->allowedGlobals->setRules(['_GET', '_POST']);
        $this->allowedGlobals->protect();

        $this->assertArrayHasKey('_GET', $GLOBALS);
        $this->assertArrayHasKey('_POST', $GLOBALS);
    }

    public function safeDataProvider()
    {
        return [['foo'],['bar']];
    }

    /**
     * @dataProvider dangerDataProvider
     */
    public function testRunProtectionWithDangerInput($method)
    {
        $_SERVER['title'] = $method;
        $_ENV['password'] = $method;
        $this->allowedGlobals->setRules(['_GET', '_POST']);
        $result = $this->allowedGlobals->protect();

        $this->assertArrayNotHasKey('_SERVER', $GLOBALS);
        $this->assertArrayNotHasKey('_ENV', $GLOBALS);
        $this->assertTrue($result);
    }

    public function dangerDataProvider()
    {
        return [['select'],['delete']];
    }
}