<?php
namespace C0defusi0n\SecurityScanner\Helper;

use Magento\Framework\App\Helper\AbstractHelper;
use Magento\Framework\App\Helper\Context;
use Magento\Framework\HTTP\Client\Curl;
use Magento\Framework\Filesystem;
use Magento\Framework\App\Filesystem\DirectoryList;
use Psr\Log\LoggerInterface;

/**
 * Downloads a JSON document (remote signature DB, vulnerability feed...) and caches it as a
 * flat, date-stamped file under var/securityscanner/. A conditional GET (ETag / If-Modified-Since)
 * means the body is NOT re-downloaded while the source has not changed; an interval throttles how
 * often we even hit the network. Any failure falls back to the last good cached copy, so the
 * scanner never breaks because GitHub is unreachable.
 *
 * The patterns/items fetched are treated as DATA, never code: callers validate each regex before
 * use, the URL must be HTTPS, the body size is capped, and the on-disk filename is built from the
 * fetch date (never from remote-controlled content) to avoid path traversal.
 */
class RemoteFetcher extends AbstractHelper
{
    const CACHE_SUBDIR = 'securityscanner';
    const MAX_BYTES = 1048576;   // 1 MB ceiling on a remote document
    const KEEP_FILES = 3;        // dated copies to retain before pruning

    /**
     * @param Context $context
     * @param Curl $curl
     * @param Filesystem $filesystem
     * @param LoggerInterface $logger
     */
    public function __construct(
        Context $context,
        protected Curl $curl,
        protected Filesystem $filesystem,
        protected LoggerInterface $logger
    ) {
        parent::__construct($context);
    }

    /**
     * Fetches and caches $url. Honours the interval and a conditional GET; returns the decoded
     * array, the last cached copy on any failure, or null when nothing is available.
     *
     * @param string $url
     * @param string $name internal cache key (e.g. 'signatures', 'vuln_feed'); not user input
     * @param int $intervalHours minimum time between network checks
     * @return array|null
     */
    public function fetch($url, $name, $intervalHours)
    {
        $url = trim((string) $url);
        if ($url === '') {
            return null;
        }
        // Remote definition sources must be HTTPS: integrity matters for code-as-data.
        if (strtolower((string) parse_url($url, PHP_URL_SCHEME)) !== 'https') {
            $this->logger->warning("SecurityScanner: refusing non-HTTPS remote source ({$name})");
            return $this->readCached($name);
        }

        try {
            $var = $this->filesystem->getDirectoryWrite(DirectoryList::VAR_DIR);
            $meta = $this->readMeta($var, $name);

            // Within the interval and a cached file exists -> use it, no network call at all.
            if ($this->cacheFresh($var, $meta, (int) $intervalHours)) {
                return $this->decode($var->readFile($meta['file']));
            }

            $this->curl->setHeaders([]);   // avoid header bleed across calls on a shared client
            $this->curl->setOptions([CURLOPT_TIMEOUT => 20, CURLOPT_CONNECTTIMEOUT => 10]);
            if (!empty($meta['etag'])) {
                $this->curl->addHeader('If-None-Match', $meta['etag']);
            }
            if (!empty($meta['last_modified'])) {
                $this->curl->addHeader('If-Modified-Since', $meta['last_modified']);
            }
            $this->curl->get($url);
            $status = $this->curl->getStatus();

            // Not modified -> keep the cached file, just record that we checked.
            if ($status === 304 && !empty($meta['file']) && $var->isExist($meta['file'])) {
                $meta['last_check'] = time();
                $this->writeMeta($var, $name, $meta);
                return $this->decode($var->readFile($meta['file']));
            }
            if ($status < 200 || $status >= 300) {
                $this->logger->warning("SecurityScanner: remote fetch '{$name}' returned HTTP {$status}");
                return $this->readCached($name);
            }

            $body = (string) $this->curl->getBody();
            if (strlen($body) > self::MAX_BYTES) {
                $this->logger->warning("SecurityScanner: remote '{$name}' exceeds size cap; ignored");
                return $this->readCached($name);
            }
            $data = $this->decode($body);
            if ($data === null) {
                $this->logger->warning("SecurityScanner: remote '{$name}' is not valid JSON; ignored");
                return $this->readCached($name);
            }

            // Persist as a date-stamped flat file. The name uses the fetch date only — never any
            // value from the (untrusted) response body — so a hostile document cannot traverse paths.
            $var->create(self::CACHE_SUBDIR);
            $file = self::CACHE_SUBDIR . '/' . $name . '_' . date('Ymd') . '.json';
            $var->writeFile($file, $body);

            $headers = array_change_key_case($this->curl->getHeaders() ?: [], CASE_LOWER);
            $this->writeMeta($var, $name, [
                'file' => $file,
                'etag' => $headers['etag'] ?? '',
                'last_modified' => $headers['last-modified'] ?? '',
                'last_check' => time(),
            ]);
            $this->prune($var, $name, $file);

            return $data;
        } catch (\Exception $e) {
            $this->logger->error("SecurityScanner: remote fetch '{$name}' failed: " . $e->getMessage());
            return $this->readCached($name);
        }
    }

    /**
     * Reads the last cached document for $name WITHOUT any network call. Used by the admin display
     * paths (system message / inbox) so rendering an admin page never blocks on HTTP.
     *
     * @param string $name
     * @return array|null
     */
    public function readCached($name)
    {
        try {
            $var = $this->filesystem->getDirectoryWrite(DirectoryList::VAR_DIR);
            $meta = $this->readMeta($var, $name);
            if (!empty($meta['file']) && $var->isExist($meta['file'])) {
                return $this->decode($var->readFile($meta['file']));
            }
        } catch (\Exception $e) {
            $this->logger->error("SecurityScanner: reading cached '{$name}' failed: " . $e->getMessage());
        }
        return null;
    }

    /**
     * @param \Magento\Framework\Filesystem\Directory\WriteInterface $var
     * @param array|null $meta
     * @param int $intervalHours
     * @return bool
     */
    private function cacheFresh($var, $meta, $intervalHours)
    {
        return $meta
            && !empty($meta['file'])
            && $var->isExist($meta['file'])
            && isset($meta['last_check'])
            && (time() - (int) $meta['last_check']) < max(1, $intervalHours) * 3600;
    }

    /**
     * @param string $s
     * @return array|null decoded array, or null if not a JSON object/array
     */
    private function decode($s)
    {
        $data = json_decode((string) $s, true);
        return is_array($data) ? $data : null;
    }

    /**
     * @param string $name
     * @return string
     */
    private function metaPath($name)
    {
        return self::CACHE_SUBDIR . '/' . $name . '.meta.json';
    }

    /**
     * @param \Magento\Framework\Filesystem\Directory\WriteInterface $var
     * @param string $name
     * @return array|null
     */
    private function readMeta($var, $name)
    {
        $path = $this->metaPath($name);
        if (!$var->isExist($path)) {
            return null;
        }
        return $this->decode($var->readFile($path));
    }

    /**
     * @param \Magento\Framework\Filesystem\Directory\WriteInterface $var
     * @param string $name
     * @param array $meta
     * @return void
     */
    private function writeMeta($var, $name, array $meta)
    {
        $var->create(self::CACHE_SUBDIR);
        $var->writeFile($this->metaPath($name), json_encode($meta));
    }

    /**
     * Keeps at most KEEP_FILES dated files in total (the freshly written one plus the most
     * recent previous copies); older copies are deleted.
     *
     * @param \Magento\Framework\Filesystem\Directory\WriteInterface $var
     * @param string $name
     * @param string $current
     * @return void
     */
    private function prune($var, $name, $current)
    {
        try {
            $files = $var->search(self::CACHE_SUBDIR . '/' . $name . '_*.json');
            rsort($files);
            // Compare basenames: search() may return paths with a different prefix than $current,
            // and we must never delete the file we just wrote.
            $currentBase = basename($current);
            $kept = 0;
            foreach ($files as $f) {
                if (basename($f) === $currentBase) {
                    continue;
                }
                if (++$kept >= self::KEEP_FILES && $var->isExist($f)) {
                    $var->delete($f);
                }
            }
        } catch (\Exception $e) {
            // Pruning is best-effort; a leftover file is harmless.
        }
    }
}
