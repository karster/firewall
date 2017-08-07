<?php

namespace karster\security\tests;

use karster\security\Firewall;

class FirewallTest extends TestCase
{
    /**
     * @var Firewall
     */
    private $firewall;

    public function setUp()
    {
        $this->firewall = new Firewall();
    }

    public function testCreateProtectionConfig()
    {
        $config = [
            'protection' => [
                'allowedRequestMethod' => [
                    'active' => false,
                    'rules' => ['GET', 'POST']
                ],
                'urlLength' => [
                    'active' => true,
                    'rules' => 200
                ]
            ]
        ];

        $result = $this->invokeMethod($this->firewall, 'createProtectionConfig', [$config]);

        $this->assertNotEmpty($result);
        $this->assertArrayHasKey('urlLength', $result);
        $this->assertArrayNotHasKey('allowedRequestMethod', $result);
        $this->assertInstanceOf('karster\security\protection\UrlLength', $result['urlLength']);
    }

    public function testIsProtectionActive()
    {
        $config['active'] = true;
        $result = $this->invokeMethod($this->firewall, 'isProtectionActive', [$config]);
        $this->assertTrue($result);

        $config['active'] = false;
        $result = $this->invokeMethod($this->firewall, 'isProtectionActive', [$config]);
        $this->assertFalse($result);
    }

    public function testGetRules()
    {
        $config['rules'] = ['POST', 'PUT'];
        $result = $this->invokeMethod($this->firewall, 'getRules', [$config, 'allowedRequestMethod']);
        $this->assertSame(["POST", "PUT"], $result);

        $result = $this->invokeMethod($this->firewall, 'getRules', ['', 'allowedRequestMethod']);
        $this->assertSame(["POST", "GET"], $result);
    }

    public function testLoadDefaultRules()
    {
        $result = $this->invokeMethod($this->firewall, 'loadDefaultRules', ['urlLength']);
        $this->assertSame(300, $result);

        $result = $this->invokeMethod($this->firewall, 'loadDefaultRules', ['foo']);
        $this->assertEmpty($result);
    }

    public function testRun()
    {
        $this->markTestIncomplete(
            'This test has not been implemented yet.'
        );
    }
}