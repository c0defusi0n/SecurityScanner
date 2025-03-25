<?php
namespace C0defusi0n\SecurityScanner\Test\Unit\Helper;

use C0defusi0n\SecurityScanner\Helper\Telegram;
use Magento\Framework\App\Helper\Context;
use Magento\Framework\HTTP\Client\Curl;
use Magento\Framework\TestFramework\Unit\Helper\ObjectManager;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Magento\Store\Model\ScopeInterface;

class TelegramTest extends TestCase
{
    /**
     * @var Telegram
     */
    private $telegramHelper;

    /**
     * @var Context|\PHPUnit\Framework\MockObject\MockObject
     */
    private $contextMock;

    /**
     * @var Curl|\PHPUnit\Framework\MockObject\MockObject
     */
    private $curlMock;

    /**
     * @var LoggerInterface|\PHPUnit\Framework\MockObject\MockObject
     */
    private $loggerMock;

    /**
     * Set up the test
     */
    protected function setUp(): void
    {
        $this->contextMock = $this->createMock(Context::class);
        $this->curlMock = $this->createMock(Curl::class);
        $this->loggerMock = $this->createMock(LoggerInterface::class);

        $objectManager = new ObjectManager($this);
        $this->telegramHelper = $objectManager->getObject(
            Telegram::class,
            [
                'context' => $this->contextMock,
                'curl' => $this->curlMock,
                'logger' => $this->loggerMock
            ]
        );
    }

    /**
     * Test isNotificationsEnabled method
     */
    public function testIsNotificationsEnabled()
    {
        $scopeConfigMock = $this->getMockBuilder(\Magento\Framework\App\Config\ScopeConfigInterface::class)
            ->disableOriginalConstructor()
            ->getMockForAbstractClass();

        $scopeConfigMock->expects($this->once())
            ->method('getValue')
            ->with(
                Telegram::XML_PATH_ENABLED,
                ScopeInterface::SCOPE_STORE
            )
            ->willReturn('1');

        $reflection = new \ReflectionClass(get_class($this->telegramHelper));
        $reflectionProperty = $reflection->getProperty('scopeConfig');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($this->telegramHelper, $scopeConfigMock);

        $this->assertTrue($this->telegramHelper->isNotificationsEnabled());
    }

    /**
     * Test isBotTokenValid method
     */
    public function testIsBotTokenValid()
    {
        $token = "1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789";
        
        $this->assertTrue($this->telegramHelper->isBotTokenValid($token));
        
        $invalidToken = "invalid-token";
        $this->assertFalse($this->telegramHelper->isBotTokenValid($invalidToken));
    }

    /**
     * Test getBotToken method
     */
    public function testGetBotToken()
    {
        $botToken = "1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789";
        
        $scopeConfigMock = $this->getMockBuilder(\Magento\Framework\App\Config\ScopeConfigInterface::class)
            ->disableOriginalConstructor()
            ->getMockForAbstractClass();

        $scopeConfigMock->expects($this->once())
            ->method('getValue')
            ->with(
                Telegram::XML_PATH_BOT_TOKEN,
                ScopeInterface::SCOPE_STORE
            )
            ->willReturn($botToken);

        $reflection = new \ReflectionClass(get_class($this->telegramHelper));
        $reflectionProperty = $reflection->getProperty('scopeConfig');
        $reflectionProperty->setAccessible(true);
        $reflectionProperty->setValue($this->telegramHelper, $scopeConfigMock);

        $this->assertEquals($botToken, $this->telegramHelper->getBotToken());
    }
    
    /**
     * Test sanitizeChatId method
     */
    public function testSanitizeChatId()
    {
        $reflection = new \ReflectionClass(get_class($this->telegramHelper));
        $method = $reflection->getMethod('sanitizeChatId');
        $method->setAccessible(true);
        
        $this->assertEquals('123456789', $method->invoke($this->telegramHelper, '123456789'));
        $this->assertEquals('123456789', $method->invoke($this->telegramHelper, ' 123456789 '));
        $this->assertEquals('123456789', $method->invoke($this->telegramHelper, '@123456789'));
    }
}
