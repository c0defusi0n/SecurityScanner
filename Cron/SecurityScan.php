<?php
namespace C0defusi0n\SecurityScanner\Cron;

use Magento\Cms\Model\ResourceModel\Block\CollectionFactory as BlockCollectionFactory;
use Psr\Log\LoggerInterface;
use Magento\Framework\Notification\NotifierInterface;
use Magento\Framework\Mail\Template\TransportBuilder;
use Magento\Store\Model\StoreManagerInterface;
use Magento\Framework\Translate\Inline\StateInterface;
use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\HTTP\Client\Curl;
use Magento\Framework\App\State;
use Magento\Framework\ObjectManagerInterface;
use Magento\Framework\App\ProductMetadataInterface;
use Magento\Framework\Filesystem;
use Magento\Framework\App\Filesystem\DirectoryList;
use Magento\Cms\Model\ResourceModel\Page\CollectionFactory as PageCollectionFactory;
use Magento\Framework\FlagManager;
use C0defusi0n\SecurityScanner\Helper\Webhook as WebhookHelper;
use C0defusi0n\SecurityScanner\Helper\AiScanner as AiScannerHelper;
use C0defusi0n\SecurityScanner\Helper\Signatures as SignaturesHelper;

class SecurityScan
{
    /**
     * Flag code storing the signatures of findings already alerted on, so the same
     * issue is not re-notified every scan.
     */
    const FLAG_SEEN_FINDINGS = 'c0defusi0n_security_scanner_seen_findings';

    /**
     * Upper bound (bytes) on content fed to the regex engine. Mirrors the AI path's
     * mb_substr cap and prevents a single oversized CMS value from OOM-ing the scan.
     */
    const MAX_SCAN_BYTES = 2097152;

    /**
     * Config paths holding admin-editable HTML — classic Magecart JS injection points.
     */
    protected $injectableConfigPaths = [
        'design/head/includes' => 'Head: Miscellaneous HTML',
        'design/footer/absolute_footer' => 'Footer: Miscellaneous HTML',
        'design/header/welcome' => 'Header welcome message',
    ];

    /**
     * @var array
     */

    /**
     * @var array
     */
    protected $maliciousPatterns = [
        // Scripts suspects
        '/\<script.*?src\s*=\s*[\'"]https?:\/\/(?!www\.paypal\.com|www\.googleapis\.com|code\.jquery\.com)[^\'"]+[\'"].*?\>/i',
        '/\<img.*?onload\s*=\s*[\'"].*?(createElement\s*\(\s*[\'"]script[\'"]\)).*?[\'"].*?\>/i',
        '/document\.write\s*\(\s*[\'"].*?<script.*?[\'"].*?\)/i',
        '/eval\s*\(/i',
        '/base64_decode\s*\(/i',

        // Redirections suspectes
        '/window\.location\s*=\s*[\'"]https?:\/\/(?!www\.paypal\.com|www\.googleapis\.com|www\.google\.com)[^\'"]+[\'"].*?\>/i',

        // Fonctions dangereuses de PHP (si utilisées de manière inhabituelle)
        '/\bexec\s*\(/i',
        '/\bshell_exec\s*\(/i',
        '/\bsystem\s*\(/i',
        '/\bpassthru\s*\(/i',
        '/\bproc_open\s*\(/i',
        '/\bpopen\s*\(/i',

        // Webshells : packers et exécution dynamique
        '/\bgzinflate\s*\(/i',
        '/\bgzuncompress\s*\(/i',
        '/\bstr_rot13\s*\(/i',
        '/\bassert\s*\(/i',
        '/\bcreate_function\s*\(/i',
        '/preg_replace\s*\(\s*[\'"][^\'"]*\/e/i',           // modificateur /e (RCE)

        // Entrée utilisateur passée directement à un sink dangereux
        '/\b(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
        '/\bcall_user_func(_array)?\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
        '/\$_(GET|POST|REQUEST|COOKIE|SERVER|FILES)\s*\[[^\]]*\]\s*\(/i',   // fonction variable sur superglobale

        // Écriture d'un fichier PHP (drop de backdoor)
        '/\bfile_put_contents\s*\([^)]*\.ph/i',
        '/\bfwrite\s*\([^)]*\.ph/i',

        // Injection de HTML invisible
        '/\<div.*?style\s*=\s*[\'"]display\s*:\s*none.*?[\'"].*?\>/i',

        ];

    /**
     * @param BlockCollectionFactory $blockCollectionFactory
     * @param LoggerInterface $logger
     * @param NotifierInterface $notifier
     * @param TransportBuilder $transportBuilder
     * @param StoreManagerInterface $storeManager
     * @param StateInterface $inlineTranslation
     * @param ScopeConfigInterface $scopeConfig
     * @param Curl $curl
     * @param State $appState
     * @param ObjectManagerInterface $objectManager
     */
    public function __construct(
        protected BlockCollectionFactory $blockCollectionFactory,
        protected LoggerInterface $logger,
        protected NotifierInterface $notifier,
        protected TransportBuilder $transportBuilder,
        protected StoreManagerInterface $storeManager,
        protected StateInterface $inlineTranslation,
        protected ScopeConfigInterface $scopeConfig,
        protected Curl $curl,
        protected State $appState,
        protected ObjectManagerInterface $objectManager,
        protected ProductMetadataInterface $productMetadata,
        protected Filesystem $filesystem,
        protected PageCollectionFactory $pageCollectionFactory,
        protected FlagManager $flagManager,
        protected WebhookHelper $webhookHelper,
        protected AiScannerHelper $aiScanner,
        protected SignaturesHelper $signatures
    ) {}

    /**
     * Executes the security scan
     *
     * @return void
     */
    public function execute()
    {
        // Check if the module is enabled
        if (!$this->isModuleEnabled()) {
            return;
        }

        $this->logger->info('Starting C0defusi0n Security Scanner scan');
        $findings = [];

        // Add custom patterns from configuration, then the remote signature DB (if enabled).
        $this->addCustomPatterns();
        $this->addRemoteSignatures();

        // Collect findings across every source
        $this->scanCmsBlocks($findings);
        $this->scanCmsPages($findings);
        $this->scanConfigInjection($findings);
        $this->scanPolyshell($findings);

        // Drop anything matching the admin ignore-list (known false positives)
        $findings = $this->filterIgnored($findings);

        // Only notify on findings not already alerted on a previous scan
        ['new' => $newFindings, 'current' => $seen] = $this->extractNewFindings($findings);

        if (!empty($newFindings)) {
            // If every enabled external channel failed to deliver, keep the new findings out of
            // the "seen" set so the next scan re-alerts them instead of silently dropping them.
            if (!$this->handleSuspiciousCode($newFindings)) {
                foreach ($newFindings as $finding) {
                    unset($seen[self::findingSignature($finding)]);
                }
            }
        } elseif (empty($findings)) {
            $this->logger->info('Security scan completed: no malicious code detected');
            $this->sendCleanReports();
        } else {
            $this->logger->info(sprintf(
                'Security scan completed: %d finding(s), none new since the last scan',
                count($findings)
            ));
        }

        // Persist the seen-set only now, after delivery, so an undelivered finding is retried.
        $this->flagManager->saveFlag(self::FLAG_SEEN_FINDINGS, $seen);
    }

    /**
     * Scans CMS pages for malicious code.
     *
     * @param array $findings
     * @return void
     */
    protected function scanCmsPages(&$findings)
    {
        foreach ($this->pageCollectionFactory->create() as $page) {
            $content = (string) $page->getContent();
            $matches = $this->findMaliciousPatterns($content);
            // A — only ask the AI about pages the regex did not already flag.
            if (empty($matches) && ($ai = $this->aiScanner->analyze($content, 'cms_page:' . $page->getIdentifier()))) {
                $matches[] = $ai;
            }
            if (empty($matches)) {
                continue;
            }
            $findings[] = [
                'type' => 'cms_page',
                'id' => $page->getId(),
                'identifier' => $page->getIdentifier(),
                'title' => $page->getTitle(),
                'matches' => $matches,
            ];
            $this->logger->warning(sprintf(
                'Suspicious code detected in CMS page #%s (%s)',
                $page->getId(),
                $page->getIdentifier()
            ));
        }
    }

    /**
     * Scans admin-editable HTML config (head/footer includes, welcome message) — the
     * #1 place Magecart skimmers inject JavaScript on a compromised store.
     *
     * @param array $findings
     * @return void
     */
    protected function scanConfigInjection(&$findings)
    {
        $seen = [];
        foreach ($this->storeManager->getStores() as $store) {
            foreach ($this->injectableConfigPaths as $path => $label) {
                $value = $this->scopeConfig->getValue(
                    $path,
                    \Magento\Store\Model\ScopeInterface::SCOPE_STORE,
                    $store->getId()
                );
                if (empty($value)) {
                    continue;
                }
                $matches = $this->findMaliciousPatterns($value);
                // A — only ask the AI about config values the regex did not already flag.
                if (empty($matches) && ($ai = $this->aiScanner->analyze($value, 'config:' . $path))) {
                    $matches[] = $ai;
                }
                if (empty($matches)) {
                    continue;
                }
                // Collapse identical values inherited across stores into one finding.
                $key = $path . '|' . md5($value);
                if (isset($seen[$key])) {
                    continue;
                }
                $seen[$key] = true;
                $findings[] = [
                    'type' => 'config',
                    'id' => '-',
                    'identifier' => $path,
                    'title' => $label,
                    'matches' => $matches,
                ];
                $this->logger->critical('Suspicious code detected in config: ' . $path);
            }
        }
    }

    /**
     * Removes findings whose identifier matches an entry of the admin ignore-list.
     *
     * @param array $findings
     * @return array
     */
    protected function filterIgnored($findings)
    {
        $raw = (string) $this->scopeConfig->getValue('security_scanner/general/ignore_list');
        $patterns = array_filter(array_map('trim', explode("\n", $raw)), 'strlen');
        if (empty($patterns)) {
            return $findings;
        }

        $kept = [];
        foreach ($findings as $finding) {
            if (self::isIgnored($finding['identifier'], $patterns)) {
                $this->logger->info('Ignored finding (ignore-list): ' . $finding['identifier']);
                continue;
            }
            $kept[] = $finding;
        }
        return $kept;
    }

    /**
     * Returns the findings not seen on the previous scan, and persists the current
     * set of signatures so persisting issues are not re-alerted every run.
     *
     * @param array $findings
     * @return array{new: array, current: array} new findings, plus the full current signature set
     */
    protected function extractNewFindings($findings)
    {
        $previous = (array) ($this->flagManager->getFlagData(self::FLAG_SEEN_FINDINGS) ?: []);

        $current = [];
        $new = [];
        foreach ($findings as $finding) {
            $sig = self::findingSignature($finding);
            $current[$sig] = true;
            if (!isset($previous[$sig])) {
                $new[] = $finding;
            }
        }

        // Pure: the caller persists $current AFTER notifications succeed, so a finding that
        // could not be delivered is not prematurely marked "seen".
        return ['new' => $new, 'current' => $current];
    }

    /**
     * Stable signature of a finding (type + location + matched strings). Pure.
     *
     * @param array $item
     * @return string
     */
    public static function findingSignature($item)
    {
        $matched = array_map(
            function ($m) { return $m['match'] ?? ''; },
            $item['matches'] ?? []
        );
        sort($matched);
        return md5(($item['type'] ?? '') . '|' . ($item['identifier'] ?? '') . '|' . implode("\x1f", $matched));
    }

    /**
     * True if $identifier contains any of the ignore-list entries. Pure.
     *
     * @param string $identifier
     * @param string[] $patterns
     * @return bool
     */
    public static function isIgnored($identifier, array $patterns)
    {
        foreach ($patterns as $pattern) {
            if ($pattern !== '' && strpos($identifier, $pattern) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * Parses an AI model reply into a verdict. Tolerates code fences and surrounding
     * prose by extracting the first {...} JSON object. Pure.
     *
     * @param string $text
     * @return array{malicious: bool, reason: string}
     */
    public static function parseAiVerdict($text)
    {
        if (preg_match('/\{.*\}/s', (string) $text, $m)) {
            $data = json_decode($m[0], true);
            if (is_array($data) && array_key_exists('malicious', $data)) {
                return [
                    'malicious' => (bool) $data['malicious'],
                    'reason' => trim((string) ($data['reason'] ?? '')),
                ];
            }
        }
        return ['malicious' => false, 'reason' => ''];
    }

    /**
     * Checks if the module is enabled
     *
     * @return bool
     */
    protected function isModuleEnabled()
    {
        return $this->scopeConfig->isSetFlag(
            'security_scanner/general/enabled',
            \Magento\Store\Model\ScopeInterface::SCOPE_STORE
        );
    }

    /**
     * Adds custom patterns from configuration
     */
    protected function addCustomPatterns()
    {
        $customPatterns = $this->scopeConfig->getValue(
            'security_scanner/malicious_patterns/custom_patterns',
            \Magento\Store\Model\ScopeInterface::SCOPE_STORE
        );

        if (!empty($customPatterns)) {
            $patterns = explode("\n", $customPatterns);
            foreach ($patterns as $pattern) {
                $pattern = trim($pattern);
                if (empty($pattern)) {
                    continue;
                }
                // An invalid regex makes preg_match_all() return false and break the whole scan; skip it.
                if (@preg_match($pattern, '') === false) {
                    $this->logger->warning('Invalid custom security pattern ignored: ' . $pattern);
                    continue;
                }
                $this->maliciousPatterns[] = $pattern;
            }
        }
    }

    /**
     * Merges the remote signature database (if enabled) on top of the built-in and custom
     * patterns. Patterns are already validated by the helper; a remote outage is a no-op.
     *
     * @return void
     */
    protected function addRemoteSignatures()
    {
        $remote = $this->signatures->getPatterns();
        if (!empty($remote)) {
            $this->maliciousPatterns = array_merge($this->maliciousPatterns, $remote);
            $this->logger->info(sprintf('Loaded %d remote signature pattern(s)', count($remote)));
        }
    }

    /**
     * Analyzes CMS blocks to detect malicious code
     *
     * @param array $suspiciousBlocks
     * @return void
     */
    protected function scanCmsBlocks(&$suspiciousBlocks)
    {
        $blockCollection = $this->blockCollectionFactory->create();
        foreach ($blockCollection as $block) {
            $content = $block->getContent();
            $matches = $this->findMaliciousPatterns($content);
            // A — the AI is a second opinion for what the regex missed; skip it when already flagged.
            if (empty($matches) && ($ai = $this->aiScanner->analyze($content, 'cms_block:' . $block->getIdentifier()))) {
                $matches[] = $ai;
            }

            if (!empty($matches)) {
                $suspiciousBlocks[] = [
                    'type' => 'cms_block',
                    'id' => $block->getId(),
                    'identifier' => $block->getIdentifier(),
                    'title' => $block->getTitle(),
                    'matches' => $matches
                ];

                $this->logger->warning(
                    sprintf(
                        'Suspicious code detected in CMS block #%s (%s): %s',
                        $block->getId(),
                        $block->getIdentifier(),
                        json_encode($matches)
                    )
                );
            }
        }
    }

    /**
     * Searches for malicious patterns in content
     *
     * @param string $content
     * @return array
     */
    protected function findMaliciousPatterns($content)
    {
        $matches = [];

        // Bound memory: a single oversized CMS/config value (mediumtext is ~16MB) run through
        // ~25 patterns can exhaust the cron/CLI process. ponytail: 2MB is far above any real
        // value; a payload past the cap is missed, but an OOM that aborts the scan misses everything.
        $content = (string) $content;
        if (strlen($content) > self::MAX_SCAN_BYTES) {
            $this->logger->warning(sprintf(
                'Scan content truncated to %d of %d bytes; content beyond the cap is not scanned',
                self::MAX_SCAN_BYTES,
                strlen($content)
            ));
            $content = substr($content, 0, self::MAX_SCAN_BYTES);
        }

        foreach ($this->maliciousPatterns as $pattern) {
            $found = [];
            $count = preg_match_all($pattern, $content, $found);
            // preg_match_all returns false (not 0) when PCRE bails out — e.g. backtrack/recursion
            // limit on crafted input. Treating that as "no match" lets an attacker evade detection
            // by forcing the engine to give up on their payload, so surface it as suspicious instead.
            if ($count === false) {
                $this->logger->warning(
                    'PCRE error (' . preg_last_error() . ') evaluating a detection pattern; flagging content as suspicious: ' . $pattern
                );
                $matches[] = [
                    'pattern' => $pattern,
                    'match' => '[scan error: content could not be evaluated against a detection pattern]',
                ];
                continue;
            }
            foreach ($found[0] as $match) {
                $matches[] = [
                    'pattern' => $pattern,
                    'match' => $match
                ];
            }
        }

        return $matches;
    }

    /**
     * Scans for PolyShell (APSB25-94) exposure: a potentially vulnerable Magento
     * version, plus executable/polyglot files dropped under pub/media (the
     * custom_options upload zone is the documented drop point, but backdoors such
     * as accesson.php spread across writable media, so the whole tree is swept).
     *
     * The PolyShell threat model and detection ideas here are inspired by
     * aregowe/magento2-module-polyshell-protection
     * (https://github.com/aregowe/magento2-module-polyshell-protection). That module
     * *blocks* the attack via framework plugins; this scanner only detects and alerts.
     *
     * @param array $findings
     * @return void
     */
    protected function scanPolyshell(&$findings)
    {
        // 1. Vulnerable version exposure
        $version = $this->productMetadata->getVersion();
        if (self::isVulnerableToPolyshell($version)) {
            $findings[] = [
                'type' => 'polyshell_version',
                'id' => '-',
                'identifier' => 'magento-version',
                'title' => 'APSB25-94 (PolyShell) – unrestricted file upload',
                'matches' => [[
                    'pattern' => 'version_compare < 2.4.9',
                    'match' => "Magento {$version} is potentially vulnerable to APSB25-94 (PolyShell). "
                        . "Confirm the isolated security patch is applied."
                ]],
            ];
            $this->logger->critical("PolyShell: Magento {$version} potentially vulnerable to APSB25-94");
        }

        // 2. Malicious files in pub/media
        try {
            $mediaRoot = $this->filesystem->getDirectoryRead(DirectoryList::MEDIA)->getAbsolutePath();
        } catch (\Exception $e) {
            $this->logger->error('PolyShell: cannot read media directory: ' . $e->getMessage());
            return;
        }
        if (!is_dir($mediaRoot)) {
            return;
        }

        foreach ($this->findMaliciousMediaFiles($mediaRoot) as $rel) {
            $findings[] = [
                'type' => 'malicious_file',
                'id' => '-',
                'identifier' => 'media/' . $rel,
                'title' => 'Executable/polyglot file in media directory',
                'matches' => [['pattern' => 'media-scan', 'match' => $rel]],
            ];
            $this->logger->critical('PolyShell: malicious file in media: ' . $rel);
        }
    }

    /**
     * Walks pub/media and returns relative paths of malicious files: any file with
     * an executable PHP extension (incl. double-extension like shell.php.jpg), and
     * any non-PHP file that embeds a PHP open tag (polyglot upload).
     *
     * @param string $mediaRoot
     * @return string[]
     */
    protected function findMaliciousMediaFiles($mediaRoot)
    {
        $hits = [];
        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($mediaRoot, \FilesystemIterator::SKIP_DOTS)
            );
        } catch (\Exception $e) {
            return $hits;
        }

        // ponytail: extension check runs on the whole tree (free, no false positives on images);
        // content/polyglot scanning is restricted to the upload drop zones, because scanning every
        // product image for a PHP tag flags legit JPEGs whose random bytes contain "<?". Widen
        // $dropZones if uploads land elsewhere. Edge read: first+last 64KB (header / appended EOF).
        $dropZones = ['/custom_options/', '/customer_address/'];
        foreach ($iterator as $fileInfo) {
            if (!$fileInfo->isFile()) {
                continue;
            }
            $path = $fileInfo->getPathname();
            $name = $fileInfo->getFilename();

            // Extension check everywhere (catches accesson.php, shell.php.jpg, *.phtml ...).
            if (self::mediaFileIsMalicious($name)) {
                $hits[] = ltrim(str_replace($mediaRoot, '', $path), '/');
                continue;
            }

            // Polyglot content check only inside upload drop zones.
            $inDropZone = false;
            foreach ($dropZones as $zone) {
                if (strpos($path, $zone) !== false) {
                    $inDropZone = true;
                    break;
                }
            }
            if ($inDropZone && self::mediaFileIsMalicious($name, $this->readFileEdges($path, 65536))) {
                $hits[] = ltrim(str_replace($mediaRoot, '', $path), '/');
            }
        }

        return $hits;
    }

    /**
     * Reads up to $bytes from the start and $bytes from the end of a file.
     *
     * @param string $path
     * @param int $bytes
     * @return string
     */
    protected function readFileEdges($path, $bytes)
    {
        $size = @filesize($path);
        if ($size === false) {
            return '';
        }
        if ($size <= $bytes * 2) {
            return (string) @file_get_contents($path);
        }
        $head = (string) @file_get_contents($path, false, null, 0, $bytes);
        $tail = (string) @file_get_contents($path, false, null, $size - $bytes, $bytes);
        return $head . $tail;
    }

    /**
     * True if a media file is an executable PHP file (incl. double extension) or a
     * polyglot embedding a PHP open tag. Pure for testability.
     *
     * @param string $filename
     * @param string $content first/last bytes of the file (empty for a name-only check)
     * @return bool
     */
    public static function mediaFileIsMalicious($filename, $content = '')
    {
        // No server-side PHP belongs in pub/media; catches shell.php and shell.php.jpg.
        if (preg_match('/\.(php|phtml|phar|pht|phps|php[3457])(\.|$)/i', $filename)) {
            return true;
        }
        // Polyglot: a media file (image, css, js...) that embeds a PHP open tag.
        // Full "<?php" only — "<?" / "<?=" occur as random bytes in real JPEGs (false positives),
        // and a polyglot still needs "<?php" to execute. "<?xml" (SVG) is intentionally not matched.
        if ($content !== '' && preg_match('/<\?php\b/i', $content)) {
            return true;
        }
        return false;
    }

    /**
     * Heuristic: is this Magento version potentially exposed to APSB25-94 (PolyShell)?
     *
     * @param string $version
     * @return bool
     */
    public static function isVulnerableToPolyshell($version)
    {
        // ponytail: APSB25-94 affects up to 2.4.9-alpha2; isolated patches on older
        // lines don't change the version string, hence the "potentially" wording on alerts.
        return version_compare($version, '2.4.9', '<');
    }

    /**
     * Handles detected suspicious blocks
     *
     * @param array $suspiciousBlocks
     * @return bool true if delivered (or nothing to deliver to); false if every enabled
     *              external channel failed — the caller then re-arms the findings for retry.
     */
    protected function handleSuspiciousCode($suspiciousBlocks)
    {
        // Logging
        $this->logger->critical(
            sprintf(
                'Security scan completed: %d new finding(s) detected',
                count($suspiciousBlocks)
            )
        );

        // Persistent in-admin notification — always delivered, independent of external channels.
        $this->notifier->addCritical(
            'Security Alert',
            sprintf(
                '%d new security finding(s) detected by C0defusi0n Security Scanner. Please check the log for more details.',
                count($suspiciousBlocks)
            )
        );

        // Each channel returns null (disabled), true (delivered) or false (enabled but failed).
        $results = [
            $this->sendEmailNotification($suspiciousBlocks),
            $this->sendTelegramNotification($suspiciousBlocks),
            $this->sendWebhookNotification($suspiciousBlocks),
        ];
        $attempted = array_filter($results, function ($r) { return $r !== null; });

        // Nothing enabled: the admin notification stands and there is nothing to retry.
        // Otherwise count it delivered only if at least one enabled channel succeeded.
        return empty($attempted) || in_array(true, $attempted, true);
    }

    /**
     * Sends an alert to the generic webhook (Slack, Discord, Teams, Mattermost...)
     *
     * @param array $suspiciousBlocks
     * @return bool|null null if disabled, true if delivered, false if it failed
     */
    protected function sendWebhookNotification($suspiciousBlocks)
    {
        if (!$this->scopeConfig->isSetFlag('security_scanner/webhook_notification/enabled')) {
            return null;
        }

        $storeName = $this->storeManager->getStore()->getName();
        $message = "🚨 SECURITY ALERT — {$storeName}\n"
            . count($suspiciousBlocks) . " suspicious item(s) detected:\n\n"
            . $this->generateDetailedReport($suspiciousBlocks);

        return $this->postWebhook($message);
    }

    /**
     * POSTs a plain-text message to the configured webhook URL.
     *
     * @param string $message
     * @return bool true on a 2xx response
     */
    protected function postWebhook($message)
    {
        $url = $this->scopeConfig->getValue('security_scanner/webhook_notification/url');
        return $this->webhookHelper->send($url, $message);
    }

    /**
     * Sets the area code for email sending operations
     */
    protected function setAreaCode()
    {
        try {
            $this->appState->setAreaCode(\Magento\Framework\App\Area::AREA_ADMINHTML);
        } catch (\Exception $e) {
            // Area code is already defined, no need to do anything
        }
    }

    /**
     * Sends an alert email
     *
     * @param array $suspiciousBlocks
     * @return void
     */
    /**
     * Sends an alert email
     *
     * @param array $suspiciousBlocks
     * @return void
     */
    protected function sendEmailNotification($suspiciousBlocks)
    {
        // Check if email notifications are enabled
        if (!$this->scopeConfig->isSetFlag('security_scanner/email_notification/enabled')) {
            return null;
        }

        $sent = false;
        try {
            // Set the area code to avoid the "Area code is not set" error
            $this->setAreaCode();

            $storeId = $this->storeManager->getStore()->getId();
            $recipients = $this->scopeConfig->getValue(
                'security_scanner/email_notification/recipients',
                \Magento\Store\Model\ScopeInterface::SCOPE_STORE,
                $storeId
            );

            if (empty($recipients)) {
                $this->logger->warning('No email recipient configured. Alert email will not be sent.');
                return false;
            }

            // Additional verification to ensure recipients are valid
            $validRecipients = false;
            $emailRecipients = explode(',', $recipients);
            foreach ($emailRecipients as $recipient) {
                $recipient = trim($recipient);
                if (!empty($recipient) && filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
                    $validRecipients = true;
                    break;
                }
            }

            if (!$validRecipients) {
                $this->logger->warning('No valid email address found in configuration. Alert email will not be sent.');
                return false;
            }

            $this->inlineTranslation->suspend();

            $detailedReport = $this->generateDetailedReport($suspiciousBlocks);
            $emailSender = $this->scopeConfig->getValue(
                'security_scanner/email_notification/email_sender',
                \Magento\Store\Model\ScopeInterface::SCOPE_STORE,
                $storeId
            );

            if (empty($emailSender)) {
                $emailSender = 'general';
            }

            foreach ($emailRecipients as $recipient) {
                $recipient = trim($recipient);
                if (empty($recipient) || !filter_var($recipient, FILTER_VALIDATE_EMAIL)) {
                    continue;
                }

                try {
                    $transport = $this->transportBuilder
                        ->setTemplateIdentifier('security_scan_alert')
                        ->setTemplateOptions([
                            'area' => \Magento\Framework\App\Area::AREA_ADMINHTML,
                            'store' => $storeId
                        ])
                        ->setTemplateVars([
                            'count' => count($suspiciousBlocks),
                            'details' => $detailedReport,
                            'store_name' => $this->storeManager->getStore()->getName()
                        ])
                        ->setFromByScope($emailSender, $storeId)  // Utiliser setFromByScope au lieu de setFrom
                        ->addTo($recipient)
                        ->getTransport();

                    $transport->sendMessage();
                    $sent = true;
                    $this->logger->info('Security alert email sent to ' . $recipient);
                } catch (\Exception $e) {
                    $this->logger->error('Error sending email to ' . $recipient . ': ' . $e->getMessage());
                }
            }

            $this->inlineTranslation->resume();
        } catch (\Exception $e) {
            $this->logger->error('Error sending alert emails: ' . $e->getMessage());
        }

        return $sent;
    }

    /**
     * Sends a Telegram notification
     *
     * @param array $suspiciousBlocks
     * @return void
     */
    protected function sendTelegramNotification($suspiciousBlocks)
    {
        // Check if Telegram notifications are enabled
        if (!$this->scopeConfig->isSetFlag('security_scanner/telegram_notification/enabled')) {
            return null;
        }

        $botToken = $this->scopeConfig->getValue('security_scanner/telegram_notification/bot_token');
        $chatIds = $this->scopeConfig->getValue('security_scanner/telegram_notification/chat_id');

        if (empty($botToken) || empty($chatIds)) {
            $this->logger->warning('Incomplete Telegram configuration: missing token or chat ID');
            return false;
        }

        $storeName = $this->storeManager->getStore()->getName();
        $scanDate = date('Y-m-d H:i:s');

        // Main message with alert
        $message = "🚨 *SECURITY ALERT* 🚨\n\n";
        $message .= "Store: *{$storeName}*\n";
        $message .= "Date: *{$scanDate}*\n";
        $message .= "Detection: *" . count($suspiciousBlocks) . " new security finding(s)*\n\n";

        // Summary of detected elements
        foreach ($suspiciousBlocks as $index => $item) {
            if ($index >= 5) {
                $message .= "_(and " . (count($suspiciousBlocks) - 5) . " other blocks...)_\n";
                break;
            }

            $message .= "• " . $this->findingLabel($item) . ": *" . self::escapeTelegramMarkdown($item['identifier']) . "*\n";
        }

        $message .= "\nCheck the administration for more details.";

        // Send the main message; its delivery is what we report back for retry logic.
        $mainOk = $this->sendTelegramMessage($botToken, $chatIds, $message);

        // Create a second message with details of the malicious code
        foreach ($suspiciousBlocks as $index => $item) {
            $detailMessage = "📋 *DETECTION DETAILS* 📋\n\n";
            $detailMessage .= $this->findingLabel($item) . ": *" . self::escapeTelegramMarkdown($item['identifier']) . "*\n";
            $detailMessage .= "Title: *" . self::escapeTelegramMarkdown($item['title']) . "*\n\n";
            $detailMessage .= "*Malicious code detected:*\n";

            foreach ($item['matches'] as $matchIdx => $match) {
                // Escape special Markdown characters
                $escapedCode = self::escapeTelegramMarkdown($match['match']);

                // Limit length to avoid issues with Telegram
                if (strlen($escapedCode) > 800) {
                    $escapedCode = substr($escapedCode, 0, 800) . "...";
                }

                $detailMessage .= "```\n" . $escapedCode . "\n```\n";

                // Limit to 1 code example per block to avoid overloading
                if ($matchIdx >= 0) {
                    break;
                }
            }

            // Send the detailed message
            $this->sendTelegramMessage($botToken, $chatIds, $detailMessage);

            // Limit to 1 detailed block to avoid overloading
            if ($index >= 0) {
                break;
            }
        }

        return $mainOk;
    }

    /**
     * Sends a message via the Telegram API
     *
     * @param string $botToken
     * @param string $chatIds
     * @param string $message
     * @return bool true if delivered to at least one chat
     */
    protected function sendTelegramMessage($botToken, $chatIds, $message)
    {
        // Send to all configured chats
        $chatIdList = explode(',', $chatIds);
        $anyOk = false;
        foreach ($chatIdList as $chatId) {
            $chatId = trim($chatId);
            if (empty($chatId)) {
                continue;
            }

            try {
                $url = "https://api.telegram.org/bot{$botToken}/sendMessage";
                $this->curl->addHeader('Content-Type', 'application/json');
                $this->curl->post($url, json_encode([
                    'chat_id' => $chatId,
                    'text' => $message,
                    'parse_mode' => 'Markdown'
                ]));

                $response = json_decode($this->curl->getBody(), true);
                if (isset($response['ok']) && $response['ok']) {
                    $anyOk = true;
                    $this->logger->info('Telegram message successfully sent to ' . $chatId);
                } else {
                    $this->logger->error('Error sending Telegram message: ' . json_encode($response));
                }
            } catch (\Exception $e) {
                $this->logger->error('Exception when sending Telegram message: ' . $e->getMessage());
            }
        }

        return $anyOk;
    }

    /**
     * Human-readable label for a finding, by type.
     *
     * @param array $item
     * @return string
     */
    protected function findingLabel($item)
    {
        switch ($item['type'] ?? 'cms_block') {
            case 'polyshell_version':
                return 'Vulnerability';
            case 'malicious_file':
                return 'Media file';
            case 'cms_page':
                return 'CMS Page #' . $item['id'];
            case 'config':
                return 'Config';
            default:
                return 'CMS Block #' . $item['id'];
        }
    }

    /**
     * Generates a detailed report
     *
     * @param array $suspiciousBlocks
     * @return string
     */
    protected function generateDetailedReport($suspiciousBlocks)
    {
        $report = "Details of detected items:\n\n";

        foreach ($suspiciousBlocks as $item) {
            // identifier/title come from attacker-influenceable CMS fields (block/page title,
            // media file path) and land in an HTML email rendered with {{var details|raw}}.
            // Escape them as HTML, exactly like $match below, so the |raw sink stays safe.
            $report .= $this->findingLabel($item)
                . ' (' . htmlspecialchars((string) $item['identifier']) . '): '
                . htmlspecialchars((string) $item['title']) . "\n";

            foreach ($item['matches'] as $match) {
                $report .= "- Suspicious code: " . htmlspecialchars($match['match']) . "\n";
            }

            $report .= "\n";
        }

        return $report;
    }

    /**
     * Escapes the Telegram (legacy Markdown) control characters so attacker-influenced
     * finding fields cannot inject links/formatting or break the message parse. Pure.
     *
     * @param string $s
     * @return string
     */
    public static function escapeTelegramMarkdown($s)
    {
        return str_replace(
            ['_', '*', '`', '[', ']'],
            ['\_', '\*', '\`', '\[', '\]'],
            (string) $s
        );
    }

    /**
     * Sends clean reports if configured
     *
     * @return void
     */
    protected function sendCleanReports()
    {
        // Check for email
        if ($this->scopeConfig->isSetFlag('security_scanner/email_notification/enabled') &&
            $this->scopeConfig->isSetFlag('security_scanner/email_notification/send_clean_report')) {

            $this->sendCleanEmailReport();
        }

        // Check for Telegram
        if ($this->scopeConfig->isSetFlag('security_scanner/telegram_notification/enabled') &&
            $this->scopeConfig->isSetFlag('security_scanner/telegram_notification/send_clean_report')) {

            $this->sendCleanTelegramReport();
        }

        // Check for Webhook
        if ($this->scopeConfig->isSetFlag('security_scanner/webhook_notification/enabled') &&
            $this->scopeConfig->isSetFlag('security_scanner/webhook_notification/send_clean_report')) {

            $storeName = $this->storeManager->getStore()->getName();
            $this->postWebhook("✅ SECURITY REPORT — {$storeName}\nNo malicious code detected during this scan.");
        }
    }

    /**
     * Sends a clean report by email
     *
     * @return void
     */
    protected function sendCleanEmailReport()
    {
        try {
            // Set the area code to avoid the "Area code is not set" error
            $this->setAreaCode();

            $storeId = $this->storeManager->getStore()->getId();
            $recipients = $this->scopeConfig->getValue(
                'security_scanner/email_notification/recipients',
                \Magento\Store\Model\ScopeInterface::SCOPE_STORE,
                $storeId
            );

            if (empty($recipients)) {
                return;
            }

            $this->inlineTranslation->suspend();

            $storeName = $this->storeManager->getStore()->getName();
            $scanDate = date('Y-m-d H:i:s');

            $emailRecipients = explode(',', $recipients);
            foreach ($emailRecipients as $recipient) {
                $recipient = trim($recipient);
                if (empty($recipient)) {
                    continue;
                }

                $transport = $this->transportBuilder
                    ->setTemplateIdentifier('security_scan_clean')
                    ->setTemplateOptions([
                        'area' => \Magento\Framework\App\Area::AREA_ADMINHTML,
                        'store' => $storeId
                    ])
                    ->setTemplateVars([
                        'store_name' => $storeName,
                        'scan_date' => $scanDate
                    ])
                    ->setFromByScope('general', $storeId)  // Use setFromByScope instead of setFrom
                    ->addTo($recipient)
                    ->getTransport();

                $transport->sendMessage();
            }

            $this->inlineTranslation->resume();

            $this->logger->info('Clean security report sent by email to ' . $recipients);
        } catch (\Exception $e) {
            $this->logger->error('Error sending clean report by email: ' . $e->getMessage());
        }
    }

    /**
     * Sends a clean report by Telegram
     *
     * @return void
     */
    protected function sendCleanTelegramReport()
    {
        $botToken = $this->scopeConfig->getValue('security_scanner/telegram_notification/bot_token');
        $chatIds = $this->scopeConfig->getValue('security_scanner/telegram_notification/chat_id');

        if (empty($botToken) || empty($chatIds)) {
            $this->logger->warning('Incomplete Telegram configuration: missing token or chat ID');
            return;
        }

        $storeName = $this->storeManager->getStore()->getName();
        $scanDate = date('Y-m-d H:i:s');

        $message = "✅ *SECURITY REPORT* ✅\n\n";
        $message .= "Store: *{$storeName}*\n";
        $message .= "Scan date: *{$scanDate}*\n\n";
        $message .= "No malicious code detected during this scan.";

        // Send to all configured chats
        $chatIdList = explode(',', $chatIds);
        foreach ($chatIdList as $chatId) {
            $chatId = trim($chatId);
            if (empty($chatId)) {
                continue;
            }

            try {
                $url = "https://api.telegram.org/bot{$botToken}/sendMessage";
                $this->curl->addHeader('Content-Type', 'application/json');
                $this->curl->post($url, json_encode([
                    'chat_id' => $chatId,
                    'text' => $message,
                    'parse_mode' => 'Markdown'
                ]));

                $this->logger->info('Clean security report sent by Telegram to ' . $chatId);
            } catch (\Exception $e) {
                $this->logger->error('Error sending clean report by Telegram: ' . $e->getMessage());
            }
        }
    }
}
