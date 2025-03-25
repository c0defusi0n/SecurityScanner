<?php
namespace C0defusi0n\SecurityScanner\Test\Unit\Console\Command;

use C0defusi0n\SecurityScanner\Console\Command\ScanCommand;
use C0defusi0n\SecurityScanner\Cron\SecurityScan;
use Magento\Framework\TestFramework\Unit\Helper\ObjectManager;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Tester\CommandTester;

class ScanCommandTest extends TestCase
{
    /**
     * @var CommandTester
     */
    private $commandTester;

    /**
     * @var SecurityScan|\PHPUnit\Framework\MockObject\MockObject
     */
    private $securityScanMock;

    /**
     * Set up the test
     */
    protected function setUp(): void
    {
        $this->securityScanMock = $this->createMock(SecurityScan::class);

        $objectManager = new ObjectManager($this);
        $commandObj = $objectManager->getObject(
            ScanCommand::class,
            ['securityScan' => $this->securityScanMock]
        );

        $this->commandTester = new CommandTester($commandObj);
    }

    /**
     * Test the execute method
     */
    public function testExecute()
    {
        $this->securityScanMock->expects($this->once())
            ->method('execute');

        $this->commandTester->execute([]);
        $output = $this->commandTester->getDisplay();
        
        $this->assertStringContainsString('Security scan completed successfully', $output);
    }

    /**
     * Test execute with an exception
     */
    public function testExecuteWithException()
    {
        $exceptionMessage = 'Test exception';
        
        $this->securityScanMock->expects($this->once())
            ->method('execute')
            ->willThrowException(new \Exception($exceptionMessage));

        $this->commandTester->execute([]);
        $output = $this->commandTester->getDisplay();
        
        $this->assertStringContainsString('Security scan failed', $output);
        $this->assertStringContainsString($exceptionMessage, $output);
    }
}
