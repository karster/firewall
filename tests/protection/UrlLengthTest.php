<?php

namespace karster\security\tests\protection;

use karster\security\protection\UrlLength;
use karster\security\tests\TestCase;

class UrlLengthTest extends TestCase
{
    /**
     * @var UrlLength
     */
    private $urlLength;

    public function setUp()
    {
        $this->urlLength = new UrlLength();
    }

    public function testGetQueryString()
    {
        $_SERVER['QUERY_STRING'] = 'id=foo&title=bar';
        $query = $this->invokeMethod($this->urlLength, 'getQueryString');

        $this->assertSame($_SERVER['QUERY_STRING'], $query);
    }

    /**
     * @dataProvider safeDataProvider
     */
    public function testRunProtectionWithSafeInput($url)
    {
        $_SERVER['QUERY_STRING'] = $url;
        $this->urlLength->setRules(10);
        $result = $this->urlLength->protect();

        $this->assertFalse($result);

    }

    public function safeDataProvider()
    {
        return [['bar'],['foo']];
    }

    /**
     * @dataProvider dangerDataProvider
     */
    public function testRunProtectionWithDangerInput($url)
    {
        $_SERVER['QUERY_STRING'] = $url;
        $this->urlLength->setRules(10);
        $result = $this->urlLength->protect();

        $this->assertTrue($result);
    }

    public function dangerDataProvider()
    {
        return [['onunload="attack();"'],['onblur="void(0);']];
    }
}