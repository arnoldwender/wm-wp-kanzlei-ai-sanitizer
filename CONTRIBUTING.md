# Contributing to WM Kanzlei AI Sanitizer

Thank you for your interest in contributing to **WM Kanzlei AI Sanitizer**.

---

## Zero Support & Issue Scope

**Zero technical, configuration, or private support is provided.** See [SUPPORT.md](SUPPORT.md):

- Report reproducible code defects **exclusively** via public [GitHub Issues](https://github.com/arnoldwender/wm-wp-kanzlei-ai-sanitizer/issues).
- **Do not** contact the author privately via email, `arnoldwender.com`, or direct messages — private inquiries are never answered.
- Issues and pull requests carry no response or maintenance SLA, and the software is provided strictly **"AS IS"** without warranty or liability.

---

## Core Development Standards

1. **PHP 8.2+ strict typing:** every PHP file under `includes/` starts with `declare(strict_types=1);` and a direct-access guard.
2. **No outbound requests** and no assets from other hosts.
3. **No compliance claims:** no text says the plugin or its output is compliant, anonymised or certified.
4. **Detection changes** add a case to test group 1 (found and not found) and update the "not detected" lists.
5. **Fail closed:** errors return errors, never partial results; audit rows are never rewritten to make the chain verify.
6. **Docs measured against the code:** README.md, DEVELOPERS.md and CHANGELOG.md change in the same pull request.

---

## Development Workflow

```bash
git clone https://github.com/arnoldwender/wm-wp-kanzlei-ai-sanitizer.git
cd wm-kanzlei-ai-sanitizer

php tests/test-suite.php
bash tests/run-mutations.sh
composer install && vendor/bin/phpunit
```

---

## Commit Conventions

- Format: `[Feature] ...`, `[Fix] ...`, `[Security] ...`, `[Docs] ...`.
- A fix adds an assertion to `tests/test-suite.php` that fails without it and an entry in `tests/mutations.php`.

For support and liability rules, read [SUPPORT.md](SUPPORT.md).
