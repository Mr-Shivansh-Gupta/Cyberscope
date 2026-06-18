"""Unit tests for configuration."""

import pytest
from config.settings import Settings, URLValidator, load_config, ConfigurationError


class TestURLValidator:
    """Test URL validation."""
    
    def test_valid_http_url(self):
        """Test valid HTTP URL."""
        assert URLValidator.validate("http://example.com") is True
    
    def test_valid_https_url(self):
        """Test valid HTTPS URL."""
        assert URLValidator.validate("https://example.com") is True
    
    def test_invalid_url_no_scheme(self):
        """Test URL without scheme."""
        assert URLValidator.validate("example.com") is False
    
    def test_invalid_url_empty(self):
        """Test empty URL."""
        assert URLValidator.validate("") is False
    
    def test_invalid_url_none(self):
        """Test None URL."""
        assert URLValidator.validate(None) is False
    
    def test_normalize_url_no_scheme(self):
        """Test URL normalization without scheme."""
        normalized = URLValidator.normalize("example.com")
        assert normalized.startswith("http://")
    
    def test_normalize_url_removes_trailing_slash(self):
        """Test URL normalization removes trailing slash."""
        normalized = URLValidator.normalize("http://example.com/")
        assert normalized == "http://example.com"


class TestSettings:
    """Test Settings configuration."""
    
    def test_settings_creation(self):
        """Test settings creation."""
        settings = Settings()
        
        assert settings.timeout == 10
        assert settings.threads == 5
        assert settings.retries == 3
    
    def test_validate_timeout_valid(self):
        """Test valid timeout validation."""
        settings = Settings()
        settings.validate_timeout(15)
        
        assert settings.timeout == 15
    
    def test_validate_timeout_invalid_low(self):
        """Test timeout validation with invalid low value."""
        settings = Settings()
        
        with pytest.raises(ConfigurationError):
            settings.validate_timeout(0)
    
    def test_validate_timeout_invalid_high(self):
        """Test timeout validation with invalid high value."""
        settings = Settings()
        
        with pytest.raises(ConfigurationError):
            settings.validate_timeout(400)
    
    def test_validate_threads_valid(self):
        """Test valid threads validation."""
        settings = Settings()
        settings.validate_threads(10)
        
        assert settings.threads == 10
    
    def test_validate_threads_invalid(self):
        """Test threads validation with invalid value."""
        settings = Settings()
        
        with pytest.raises(ConfigurationError):
            settings.validate_threads(100)
    
    def test_validate_log_level_valid(self):
        """Test valid log level validation."""
        settings = Settings()
        settings.validate_log_level("DEBUG")
        
        assert settings.log_level == "DEBUG"
    
    def test_validate_log_level_invalid(self):
        """Test log level validation with invalid value."""
        settings = Settings()
        
        with pytest.raises(ConfigurationError):
            settings.validate_log_level("INVALID")
    
    def test_validate_target_url_valid(self):
        """Test valid target URL validation."""
        settings = Settings()
        settings.validate_target_url("http://example.com")
        
        assert settings.target_url == "http://example.com"
    
    def test_validate_target_url_invalid(self):
        """Test target URL validation with invalid URL."""
        settings = Settings()
        
        with pytest.raises(ConfigurationError):
            settings.validate_target_url("invalid")
    
    def test_set_ignore_links_list(self):
        """Test setting ignore links as list."""
        settings = Settings()
        settings.set_ignore_links(["/logout", "/admin"])
        
        assert len(settings.ignore_links) == 2
    
    def test_set_ignore_links_string(self):
        """Test setting ignore links as comma-separated string."""
        settings = Settings()
        settings.set_ignore_links("/logout,/admin")
        
        assert len(settings.ignore_links) == 2
        assert "/logout" in settings.ignore_links
    
    def test_set_authentication_valid(self):
        """Test authentication setup."""
        settings = Settings()
        settings.set_authentication(
            "http://example.com/login",
            "user",
            "password"
        )
        
        assert settings.auth_required is True
        assert settings.auth_url == "http://example.com/login"
    
    def test_set_authentication_invalid_url(self):
        """Test authentication with invalid URL."""
        settings = Settings()
        
        with pytest.raises(ConfigurationError):
            settings.set_authentication("invalid", "user", "password")
    
    def test_set_authentication_empty_credentials(self):
        """Test authentication with empty credentials."""
        settings = Settings()
        
        with pytest.raises(ConfigurationError):
            settings.set_authentication("http://example.com/login", "", "password")
    
    def test_settings_to_dict(self):
        """Test settings to dictionary."""
        settings = Settings()
        settings.validate_timeout(20)
        
        settings_dict = settings.to_dict()
        
        assert settings_dict['timeout'] == 20
        assert 'target_url' in settings_dict


class TestLoadConfig:
    """Test config file loading."""
    
    def test_load_config_no_file(self):
        """Test loading config with no file."""
        settings = load_config("nonexistent.yaml")
        
        assert settings.timeout == 10
        assert settings.threads == 5
    
    def test_load_config_empty_file(self, tmp_path):
        """Test loading empty config file."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("")
        
        settings = load_config(str(config_file))
        
        assert settings.timeout == 10
