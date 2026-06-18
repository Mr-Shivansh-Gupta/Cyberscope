"""Setup configuration for Cyberscope package."""

from setuptools import setup, find_packages
import os

# Read README
def read_file(filename):
    """Read file content."""
    filepath = os.path.join(os.path.dirname(__file__), filename)
    if os.path.exists(filepath):
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    return ""


setup(
    name="Cyberscope",
    version="2.0.0",
    description="Professional Web Vulnerability Scanner - XSS, SQL Injection, CSRF Detection",
    long_description=read_file("README.md"),
    long_description_content_type="text/markdown",
    author="Cyberscope Contributors",
    author_email="developers@Cyberscope.dev",
    url="https://github.com/anomalyco/Cyberscope",
    license="MIT",
    
    # Package configuration
    packages=find_packages(exclude=["tests", "tests.*"]),
    include_package_data=True,
    
    # Python version requirement
    python_requires=">=3.8",
    
    # Dependencies
    install_requires=[
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.2",
        "lxml>=4.9.3",
        "pyyaml>=6.0.1",
        "jinja2>=3.1.2",
        "colorama>=0.4.6",
    ],
    
    # Optional dependencies
    extras_require={
        "dev": [
            "pytest>=7.4.3",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
            "sphinx>=7.0.0",
        ],
        "test": [
            "pytest>=7.4.3",
            "pytest-cov>=4.1.0",
            "pytest-mock>=3.12.0",
        ],
    },
    
    # Console script entry point
    entry_points={
        "console_scripts": [
            "Cyberscope=Cyberscope:main",
        ],
    },
    
    # Classifiers
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Security",
        "Topic :: Software Development :: Testing",
    ],
    
    # Keywords
    keywords=[
        "security",
        "vulnerability-scanner",
        "xss",
        "sql-injection",
        "csrf",
        "web-security",
        "penetration-testing",
    ],
    
    # Project URLs
    project_urls={
        "Bug Reports": "https://github.com/anomalyco/Cyberscope/issues",
        "Source": "https://github.com/anomalyco/Cyberscope",
        "Documentation": "https://github.com/anomalyco/Cyberscope/wiki",
    },
    
    # Zip safe
    zip_safe=False,
)
