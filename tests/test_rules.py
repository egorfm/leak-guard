from git_leak_guard.rules import RuleEngine, mask_secret
from git_leak_guard.models import Severity


def test_mask_secret():
    assert mask_secret("short") == "*****"
    masked_mid = mask_secret("1234567890")
    assert masked_mid.startswith("12") and masked_mid.endswith("90")
    assert "*" in masked_mid

    prefix = "sk-proj-"
    suffix = "abcdefghijklmnopqrstuvwxyz1234567890"
    long_token = prefix + suffix
    masked_long = mask_secret(long_token)
    assert masked_long.startswith("sk-p")
    assert masked_long.endswith("7890")
    assert "****" in masked_long


def test_openai_key_detection():
    engine = RuleEngine()
    fake_token = "sk-proj-" + "abcde12345FGHIJ67890klmno12345PQRST67890uvwxyz12345"
    test_line = f'openai_api_key = "{fake_token}"'
    findings = engine.scan_text(test_line, file_path="config.py")

    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "OPENAI_API_KEY"
    assert f.severity == Severity.CRITICAL


def test_aws_key_detection():
    engine = RuleEngine()
    fake_key = "AKIA" + "1234567890ABCDEF"
    test_real_line = f'export AWS_ACCESS_KEY_ID="{fake_key}"'
    findings = engine.scan_text(test_real_line, file_path="deploy.sh")

    assert len(findings) == 1
    assert findings[0].rule_id == "AWS_ACCESS_KEY"
    assert findings[0].severity == Severity.CRITICAL


def test_database_uri_detection():
    engine = RuleEngine()
    test_line = 'DATABASE_URL="postgres://admin:SuperSecretPass123!@db.internal.net:5432/production"'
    findings = engine.scan_text(test_line, file_path="settings.py")

    assert len(findings) == 1
    assert findings[0].rule_id == "DATABASE_URI"
    assert findings[0].severity == Severity.CRITICAL


def test_telegram_bot_token():
    engine = RuleEngine()
    fake_tg = "123456789:" + "ABCdefGHIjklMNOpqrSTUvwxYZ123456789"
    test_line = f'bot_token = "{fake_tg}"'
    findings = engine.scan_text(test_line, file_path="bot.py")

    assert len(findings) == 1
    assert findings[0].rule_id == "TELEGRAM_BOT_TOKEN"


def test_false_positive_suppression():
    engine = RuleEngine()
    test_line = 'api_key = "YOUR_API_KEY_HERE"'
    findings = engine.scan_text(test_line, file_path="example.py")
    assert len(findings) == 0


def test_sensitive_filenames():
    engine = RuleEngine()
    f1 = engine.scan_filename(".env")
    assert f1 is not None
    assert f1.severity == Severity.HIGH

    f2 = engine.scan_filename("serviceAccountKey.json")
    assert f2 is not None
    assert f2.severity == Severity.CRITICAL

    f3 = engine.scan_filename("regular_script.py")
    assert f3 is None
