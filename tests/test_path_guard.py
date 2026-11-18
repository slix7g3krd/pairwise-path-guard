from security.path_guard import (
    normalize_path,
    is_safe_path,
    safe_join,
    strip_null,
    is_symlink_escape
)


def test_normalize():
    assert normalize_path('/a/../b') == '/b'

def test_safe():
    assert is_safe_path('/data/file', '/data') is True

def test_dotdot():
    assert is_safe_path('/data/../etc', '/data') is False

def test_encoded():
    assert is_safe_path('/data%2f..%2fetc', '/data') is False

def test_absolute():
    assert is_safe_path('/etc/passwd', '/data') is False

def test_windows():
    assert is_safe_path('C:\\data\\x', '/data') is False

def test_prefix():
    assert is_safe_path('/data-evil/x', '/data') is False

def test_null():
    assert strip_null('a\x00b') == 'a'

def test_join():
    assert safe_join('/data', 'x') == '/data/x'

def test_join_bad():
    assert safe_join('/data', '../x') is None

def test_symlink():
    assert is_symlink_escape('/data/link', '/etc/passwd') is True

def test_empty():
    assert is_safe_path('', '/data') is False

def test_trailing():
    assert normalize_path('/a/') == '/a'

def test_unicode():
    assert normalize_path('/a/./b') == '/a/b'

def test_double():
    assert is_safe_path('%252e%252e%252fetc', '/data') is False
