<?php
namespace C0defusi0n\SecurityScanner\Test\Unit\Controller\Adminhtml\Telegram;

use C0defusi0n\SecurityScanner\Controller\Adminhtml\Telegram\Test;
use C0defusi0n\SecurityScanner\Helper\Telegram;
use Magento\Backend\App\Action\Context;
use Magento\Framework\Controller\Result\Json;
use Magento\Framework\Controller\Result\JsonFactory;
use Magento\Framework\TestFramework\Unit\Helper\ObjectManager;
use PHPUnit\Framework\TestCase;

class TestTest extends TestCase
{
    /**
     * @var Test
     */
    private $controller;

    /**
     * @var Context|\PHPUnit\Framework\MockObject\MockObject
     */
    private $contextMock;

    /**
     * @var JsonFactory|\PHPUnit\Framework\MockObject\MockObject
     */
    private $resultJsonFactoryMock;

    /**
     * @var Telegram|\PHPUnit\Framework\MockObject\MockObject
     */
    private $telegramHelperMock;

    /**
     * @var Json|\PHPUnit\Framework\MockObject\MockObject
     */
    private $resultJsonMock;

    /**
     * Set up the test
     */
    protected function setUp(): void
    {
        $this->contextMock = $this->createMock(Context::class);
        $this->resultJsonFactoryMock = $this->createMock(JsonFactory::class);
        $this->telegramHelperMock = $this->createMock(Telegram::class);
        $this->resultJsonMock = $this->createMock(Json::class);

        $this->resultJsonFactoryMock->expects($this->any())
            ->method('create')
            ->willReturn($this->resultJsonMock);

        $objectManager = new ObjectManager($this);
        $this->controller = $objectManager->getObject(
            Test::class,
            [
                'context' => $this->contextMock,
                'resultJsonFactory' => $this->resultJsonFactoryMock,
                'telegramHelper' => $this->telegramHelperMock
            ]
        );
    }

    /**
     * Test execute method with notifications disabled
     */
    public function testExecuteWithNotificationsDisabled()
    {
        $this->telegramHelperMock->expects($this->once())
            ->method('isNotificationsEnabled')
            ->willReturn(false);

        $this->resultJsonMock->expects($this->once())
            ->method('setData')
            ->with([
                'success' => false,
                'message' => 'Telegram notifications are disabled in the configuration.'
            ])
            ->willReturnSelf();

        $this->assertSame($this->resultJsonMock, $this->controller->execute());
    }

    /**
     * Test execute method with invalid token
     */
    public function testExecuteWithInvalidToken()
    {
        $this->telegramHelperMock->expects($this->once())
            ->method('isNotificationsEnabled')
            ->willReturn(true);

        $this->telegramHelperMock->expects($this->once())
            ->method('getBotToken')
            ->willReturn('invalid-token');

        $this->telegramHelperMock->expects($this->once())
            ->method('isBotTokenValid')
            ->with('invalid-token')
            ->willReturn(false);

        $this->resultJsonMock->expects($this->once())
            ->method('setData')
            ->with([
                'success' => false,
                'message' => 'The Telegram bot token is invalid.'
            ])
            ->willReturnSelf();

        $this->assertSame($this->resultJsonMock, $this->controller->execute());
    }

    /**
     * Test execute method with valid token but empty chat IDs
     */
    public function testExecuteWithValidTokenButEmptyChatIds()
    {
        $validToken = '1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789';

        $this->telegramHelperMock->expects($this->once())
            ->method('isNotificationsEnabled')
            ->willReturn(true);

        $this->telegramHelperMock->expects($this->once())
            ->method('getBotToken')
            ->willReturn($validToken);

        $this->telegramHelperMock->expects($this->once())
            ->method('isBotTokenValid')
            ->with($validToken)
            ->willReturn(true);

        $this->telegramHelperMock->expects($this->once())
            ->method('getChatIds')
            ->willReturn('');

        $this->resultJsonMock->expects($this->once())
            ->method('setData')
            ->with([
                'success' => false,
                'message' => 'The Telegram chat ID is empty.'
            ])
            ->willReturnSelf();

        $this->assertSame($this->resultJsonMock, $this->controller->execute());
    }

    /**
     * Test execute method with successful test message
     */
    public function testExecuteWithSuccessfulTestMessage()
    {
        $validToken = '1234567890:ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789';
        $chatIds = '123456789';

        $this->telegramHelperMock->expects($this->once())
            ->method('isNotificationsEnabled')
            ->willReturn(true);

        $this->telegramHelperMock->expects($this->once())
            ->method('getBotToken')
            ->willReturn($validToken);

        $this->telegramHelperMock->expects($this->once())
            ->method('isBotTokenValid')
            ->with($validToken)
            ->willReturn(true);

        $this->telegramHelperMock->expects($this->once())
            ->method('getChatIds')
            ->willReturn($chatIds);

        $this->telegramHelperMock->expects($this->once())
            ->method('sendTestMessage')
            ->with($validToken, $chatIds)
            ->willReturn(true);

        $this->resultJsonMock->expects($this->once())
            ->method('setData')
            ->with([
                'success' => true,
                'message' => 'Test message sent successfully!'
            ])
            ->willReturnSelf();

        $this->assertSame($this->resultJsonMock, $this->controller->execute());
    }
}
