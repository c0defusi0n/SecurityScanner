<?php
namespace C0defusi0n\SecurityScanner\Console\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use C0defusi0n\SecurityScanner\Cron\SecurityScan;

class ScanCommand extends Command
{
    /**
     * @param SecurityScan $securityScan
     */
    public function __construct(
        private SecurityScan $securityScan
    ) {
        parent::__construct();
    }

    /**
     * Configure command
     *
     * @return void
     */
    protected function configure()
    {
        $this->setName('c0defusi0n:security:scan')
            ->setDescription('Executes a security scan to detect malicious code');

        parent::configure();
    }

    /**
     * Execute command
     *
     * @param InputInterface $input
     * @param OutputInterface $output
     * @return int
     */
    protected function execute(InputInterface $input, OutputInterface $output)
    {
        try {
            $output->writeln('<info>Starting security scan...</info>');

            $this->securityScan->execute();

            $output->writeln('<info>Security scan completed successfully.</info>');
            $output->writeln('<info>Check system logs for detailed results.</info>');

            return \Magento\Framework\Console\Cli::RETURN_SUCCESS;
        } catch (\Exception $e) {
            $output->writeln('<error>Erreur pendant le scan de sécurité: ' . $e->getMessage() . '</error>');
            return \Magento\Framework\Console\Cli::RETURN_FAILURE;
        }
    }
}
