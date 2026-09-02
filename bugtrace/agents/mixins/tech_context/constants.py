"""Inference constants for TechContextMixin."""

from __future__ import annotations

# =============================================================================
# DATABASE INFERENCE RULES
# =============================================================================

# Framework → Likely Database mapping
FRAMEWORK_TO_DB = {
    # PHP ecosystem
    "php": "MySQL",
    "laravel": "MySQL",
    "symfony": "MySQL",
    "wordpress": "MySQL",
    "drupal": "MySQL",
    "joomla": "MySQL",
    "codeigniter": "MySQL",
    "yii": "MySQL",
    "cakephp": "MySQL",

    # Python ecosystem
    "django": "PostgreSQL",
    "flask": "PostgreSQL",
    "fastapi": "PostgreSQL",

    # Java ecosystem
    "spring": "PostgreSQL",
    "struts": "Oracle",
    "hibernate": "PostgreSQL",

    # .NET ecosystem
    "asp.net": "MSSQL",
    ".net": "MSSQL",
    "dotnet": "MSSQL",

    # Ruby ecosystem
    "rails": "PostgreSQL",
    "ruby on rails": "PostgreSQL",
    "sinatra": "PostgreSQL",

    # Node.js ecosystem
    "express": "MongoDB",  # Often NoSQL but can vary
    "nextjs": "PostgreSQL",
    "nestjs": "PostgreSQL",

    # CMS
    "magento": "MySQL",
    "prestashop": "MySQL",
    "opencart": "MySQL",
}

# Server → Likely Language mapping
SERVER_TO_LANG = {
    "apache": "PHP",
    "nginx": "varies",  # Need framework hint
    "iis": "ASP.NET",
    "tomcat": "Java",
    "jetty": "Java",
    "gunicorn": "Python",
    "uvicorn": "Python",
    "puma": "Ruby",
    "unicorn": "Ruby",
}

# Tech tags that hint at database types
TAG_TO_DB = {
    "mysql": "MySQL",
    "mariadb": "MySQL",
    "postgresql": "PostgreSQL",
    "postgres": "PostgreSQL",
    "mssql": "MSSQL",
    "sqlserver": "MSSQL",
    "oracle": "Oracle",
    "sqlite": "SQLite",
    "mongodb": "MongoDB",
    "redis": "Redis",
}


