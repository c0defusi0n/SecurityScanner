# Security Scanner for Magento 2

[![Latest Stable Version](https://img.shields.io/packagist/v/c0defusi0n/security-scanner.svg)](https://packagist.org/packages/c0defusi0n/security-scanner)
[![Total Downloads](https://img.shields.io/packagist/dt/c0defusi0n/security-scanner.svg)](https://packagist.org/packages/c0defusi0n/security-scanner)
[![License](https://img.shields.io/packagist/l/c0defusi0n/security-scanner.svg)](https://github.com/c0defusi0n/security-scanner/blob/master/LICENSE)

The Security Scanner module for Magento 2 helps you automatically detect potentially malicious code in your Magento CMS blocks. It can alert you via email and Telegram notifications when suspicious code patterns are detected, enhancing your store's security posture.

## Features

- Scheduled security scans across CMS blocks, CMS pages and admin-editable HTML config (head/footer includes, welcome message — the usual Magecart injection points)
- Webshell/backdoor signature detection (eval, packers, request-to-sink, /e modifier, ...)
- **PolyShell (APSB25-94) detection**: flags vulnerable Magento versions and malicious files in `pub/media`
- Alert de-duplication: the same finding is reported once, not on every scan
- Ignore-list to silence known false positives
- Configurable scan frequency (hourly, daily, weekly, etc.)
- Email notifications for security alerts
- Telegram bot integration for instant notifications
- Generic webhook channel — send alerts anywhere (Slack, Discord, Teams, Mattermost, ntfy.sh, ...)
- Customizable malicious code detection patterns
- Admin panel for easy configuration
- Command line interface for manual scans

## Installation

### Via Composer (Recommended)

```bash
composer require c0defusi0n/security-scanner
bin/magento module:enable C0defusi0n_SecurityScanner
bin/magento setup:upgrade
bin/magento setup:di:compile
bin/magento setup:static-content:deploy
bin/magento cache:flush
```

### Manual Installation

1. Download the ZIP file from the [GitHub repository](https://github.com/c0defusi0n/security-scanner/)
2. Extract the contents into `app/code/C0defusi0n/SecurityScanner/` directory
3. Run the following commands:

```bash
bin/magento module:enable C0defusi0n_SecurityScanner
bin/magento setup:upgrade
bin/magento setup:di:compile
bin/magento setup:static-content:deploy
bin/magento cache:flush
```

## Configuration

1. Go to **Stores > Configuration > Security Scanner**
2. Configure the following options:

### General Configuration

- **Enable Scanner**: Enable or disable the security scanner
- **Scan Frequency**: Set how often the scanner should run
- **Ignore List**: One entry per line; any finding whose location (CMS identifier, config path, media path) contains an entry is skipped — use to silence known false positives

### Email Notifications

- **Enable Email Notifications**: Turn on/off email alerts
- **Email Sender**: Configure the sender of email notifications
- **Email Recipients**: Set the email addresses to receive notifications (comma separated)
- **Send Clean Reports**: Option to receive reports even when no issues are detected

### Telegram Notifications

- **Enable Telegram Notifications**: Turn on/off Telegram alerts
- **Telegram Bot Token**: Set your Telegram bot API token
- **Telegram Chat ID**: Set the chat ID where notifications should be sent
- **Test Telegram Connection**: Test button to verify your Telegram configuration

### Webhook Notifications

Send alerts to any incoming webhook — no service-specific integration needed.

- **Enable Webhook Notifications**: Turn on/off webhook alerts
- **Webhook URL**: The URL to POST notifications to
- **Send Clean Reports**: Option to post a report even when no issues are detected
- **Test Webhook**: Button to send a test message to the configured URL

The message is POSTed as JSON `{"text": ..., "content": ...}`, which Slack, Microsoft Teams,
Mattermost, Google Chat (`text`) and Discord (`content`) all accept. If the URL points at
**ntfy.sh** (or a self-hosted ntfy), the message is sent as a plain-text body instead, with
`Title` and `Tags` headers — e.g. `https://ntfy.sh/your-topic`.

### Malicious Code Detection Patterns

- **Custom Patterns**: Add your own regular expressions to extend detection capabilities

## Usage

### Automatic Scans

Once configured, the module will automatically scan your CMS blocks based on the frequency settings you've specified. If suspicious code is detected, you'll receive notifications via the channels you've enabled.

### Manual Scan via CLI

You can also trigger a security scan manually using the command line:

```bash
bin/magento c0defusi0n:security:scan
```

## PolyShell (APSB25-94) detection

Each scan also checks for exposure to the PolyShell unrestricted file upload vulnerability
([APSB25-94](https://helpx.adobe.com/security/products/magento/apsb25-94.html)):

- **Version check** — warns if the running Magento version is potentially affected (< 2.4.9).
  Versions are not enough to confirm a fix, since the patch ships as an isolated security patch;
  the alert tells you to verify it is applied.
- **Media scan** — sweeps `pub/media` for executable PHP files anywhere (e.g. `accesson.php`,
  double extensions like `shell.php.jpg`) and for polyglot uploads (a media file embedding a
  `<?php` tag) inside the upload drop zones (`custom_options/`, `customer_address/`).

The PolyShell threat model and detection approach were inspired by
[aregowe/magento2-module-polyshell-protection](https://github.com/aregowe/magento2-module-polyshell-protection).
That module *blocks* the attack at the framework level; this scanner only *detects and alerts*,
so the two are complementary.

## Customization

### Adding Custom Detection Patterns

You can add your own regular expressions to detect specific patterns of malicious code through the admin configuration or by extending the module.

### Extending Email Templates

The module includes customizable email templates for security alerts and clean reports, which can be modified through the Magento admin panel under **Marketing > Email Templates**.

## Internationalization

The module supports multiple languages through Magento's translation system. English translations are included by default, and French translations are available.

## Requirements

- PHP 8.1 or higher
- Magento 2.4.x

## Support

For bug reports and feature requests, please use the [GitHub issue tracker](https://github.com/c0defusi0n/security-scanner/issues).

## License

This module is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributors

- [c0defusi0n](https://github.com/c0defusi0n) - *Initial work*

## Changelog

### 1.1.0
- Encrypted storage for the Telegram bot token (`obscure` field)
- Invalid custom regex patterns are now skipped instead of breaking the scan
- Expanded webshell/backdoor detection patterns
- Scan coverage extended to CMS pages and admin-editable HTML config (head/footer includes, welcome message)
- PolyShell (APSB25-94) detection: vulnerable version check + `pub/media` malicious file scan
- Generic webhook notification channel (Slack/Discord/Teams/Mattermost/ntfy.sh/...) with admin test button
- Alert de-duplication: findings are reported once, not on every scan
- Ignore-list to silence known false positives
- Added a standalone detection test (`Test/patterns_test.php`)

### 1.0.0
- Initial release
- Added CMS block scanning
- Added email and Telegram notifications
- Added admin configuration
- Added CLI command
