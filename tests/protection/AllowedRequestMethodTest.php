<?php

namespace karster\security\tests\protection;

use karster\security\protection\AllowedRequestMethod;
use karster\security\tests\TestCase;

class AllowedRequestMethodTest extends TestCase
{
    /**
     * @var AllowedRequestMethod
     */
    private $allowedRequestMethod;

    public function setUp()
    {
        $this->allowedRequestMethod = new AllowedRequestMethod();
    }

    /**
     * @dataProvider setRulesProvider
     *
     * @access public
     */
    public function testSetRules($actual, $expected)
    {
        $this->allowedRequestMethod->setRules($actual);
        $result = $this->allowedRequestMethod->getRules();

        $this->assertEquals($expected, $result);
    }

    public function setRulesProvider()
    {
        return [
            [
                ['POST', 'get', 'Delete'],
                ['POST', 'GET', 'DELETE']
            ]
        ];
    }

    /**
     * @dataProvider getRequestMethodProvider
     *
     * @access public
     */
    public function testGetRequestMethod($actual, $expected)
    {
        $_SERVER['REQUEST_METHOD'] = $actual;
        $request_method = $this->invokeMethod($this->allowedRequestMethod, 'getRequestMethod');

        $this->assertEquals($expected, $request_method);
    }

    public function getRequestMethodProvider()
    {
        return [
            ['post', 'POST'],
            ['Get', 'GET'],
            ['DELETE', 'DELETE']
        ];
    }

    /**
     * @dataProvider safeDataProvider
     */
    public function testRunProtectionWithSafeInput($method)
    {
        $_SERVER['REQUEST_METHOD'] = $method;
        $this->allowedRequestMethod->setRules(['GET', 'POST']);
        $result = $this->allowedRequestMethod->protect();

        $this->assertFalse($result);

    }

    public function safeDataProvider()
    {
        return [['GET'],['POST']];
    }

    /**
     * @dataProvider dangerDataProvider
     */
    public function testRunProtectionWithDangerInput($method)
    {
        $_SERVER['REQUEST_METHOD'] = $method;
        $this->allowedRequestMethod->setRules(['GET', 'POST']);
        $result = $this->allowedRequestMethod->protect();

        $this->assertTrue($result);
    }

    public function dangerDataProvider()
    {
        return [['DELETE'],['PUT']];
    }
}