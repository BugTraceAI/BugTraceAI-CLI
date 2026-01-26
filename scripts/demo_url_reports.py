#!/usr/bin/env python3
"""
Demo script to generate example URL reports.

Creates sample reports showing the structure described in the architecture.
"""
import asyncio
from pathlib import Path
from datetime import datetime

from bugtrace.reporting.url_reporter import URLReporter


async def generate_example_reports():
    """Generate example URL reports to demonstrate the structure."""
    
    # Create base report directory
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base_dir = Path(f"reports/demo_target_{timestamp}")
    base_dir.mkdir(parents=True, exist_ok=True)
    
    print(f"📁 Creating demo reports in: {base_dir}")
    
    # Initialize URL Reporter
    url_reporter = URLReporter(str(base_dir))
    
    # Example 1: URL with SQL Injection
    print("\n1️⃣ Creating report for URL with SQL Injection...")
    url1 = "http://testphp.vulnweb.com/listproducts.php?cat=1"
    
    analysis1 = {
        'dast': {
            'status': 'COMPLETED',
            'confidence': 95,
            'findings': [
                {
                    'type': 'SQLi',
                    'description': 'SQL error message detected in response'
                }
            ]
        },
        'sast': {
            'patterns': [
                {
                    'name': 'Unsafe SQL Query',
                    'risk_level': 'HIGH',
                    'details': 'Direct parameter interpolation without sanitization'
                }
            ]
        },
        'overall_risk': 'HIGH',
        'recommendations': [
            'Use parameterized queries',
            'Implement input validation',
            'Add WAF protection'
        ]
    }
    
    vulns1 = [
        {
            'type': 'SQL Injection',
            'parameter': 'cat',
            'payload': "1' OR '1'='1",
            'confidence': 95,
            'severity': 'HIGH',
            'validated': True,
            'details': 'SQL error message: "You have an error in your SQL syntax"'
        }
    ]
    
    metadata1 = {
        'params': {'cat': '1'},
        'tech_stack': ['PHP', 'MySQL', 'Apache'],
        'response_time': 234
    }
    
    report1 = url_reporter.create_url_report(
        url=url1,
        analysis_results=analysis1,
        vulnerabilities=vulns1,
        metadata=metadata1
    )
    print(f"   ✅ Report created: {report1}")
    
    # Example 2: URL with XSS
    print("\n2️⃣ Creating report for URL with XSS...")
    url2 = "http://testphp.vulnweb.com/search.php?searchFor=test"
    
    analysis2 = {
        'dast': {
            'status': 'COMPLETED',
            'confidence': 90,
            'findings': [
                {
                    'type': 'XSS',
                    'description': 'Unescaped user input reflected in response'
                }
            ]
        },
        'sast': {
            'patterns': [
                {
                    'name': 'Missing Output Encoding',
                    'risk_level': 'HIGH',
                    'details': 'User input directly echoed without escaping'
                }
            ]
        },
        'overall_risk': 'HIGH',
        'recommendations': [
            'Implement output encoding (htmlspecialchars)',
            'Use Content Security Policy',
            'Sanitize user inputs'
        ]
    }
    
    vulns2 = [
        {
            'type': 'Cross-Site Scripting (XSS)',
            'parameter': 'searchFor',
            'payload': '<script>alert(1)</script>',
            'confidence': 90,
            'severity': 'HIGH',
            'validated': True,
            'details': 'Alert box executed successfully in browser',
            'screenshot': 'screenshots/xss_proof.png'  # Would be actual path
        }
    ]
    
    metadata2 = {
        'params': {'searchFor': 'test'},
        'tech_stack': ['PHP', 'Apache'],
        'response_time': 189
    }
    
    report2 = url_reporter.create_url_report(
        url=url2,
        analysis_results=analysis2,
        vulnerabilities=vulns2,
        metadata=metadata2
    )
    print(f"   ✅ Report created: {report2}")
    
    # Example 3: Clean URL (no vulnerabilities)
    print("\n3️⃣ Creating report for clean URL...")
    url3 = "http://testphp.vulnweb.com/about.php"
    
    analysis3 = {
        'dast': {
            'status': 'COMPLETED',
            'confidence': 100,
            'findings': []
        },
        'sast': {
            'patterns': []
        },
        'overall_risk': 'NONE',
        'recommendations': [
            'Continue implementing security best practices'
        ]
    }
    
    vulns3 = []
    
    metadata3 = {
        'params': {},
        'tech_stack': ['PHP', 'Apache'],
        'response_time': 145
    }
    
    report3 = url_reporter.create_url_report(
        url=url3,
        analysis_results=analysis3,
        vulnerabilities=vulns3,
        metadata=metadata3
    )
    print(f"   ✅ Report created: {report3}")
    
    # Example 4: URL with multiple vulnerabilities
    print("\n4️⃣ Creating report for URL with multiple issues...")
    url4 = "http://testphp.vulnweb.com/admin/login.php"
    
    analysis4 = {
        'dast': {
            'status': 'COMPLETED',
            'confidence': 85,
            'findings': [
                {'type': 'SQLi', 'description': 'Potential SQL injection'},
                {'type': 'Weak Auth', 'description': 'No rate limiting on login'}
            ]
        },
        'sast': {
            'patterns': [
                {
                    'name': 'Weak Authentication',
                    'risk_level': 'MEDIUM',
                    'details': 'No account lockout mechanism'
                },
                {
                    'name': 'SQL Injection Risk',
                    'risk_level': 'HIGH',
                    'details': 'User credentials not properly validated'
                }
            ]
        },
        'overall_risk': 'CRITICAL',
        'recommendations': [
            'Implement rate limiting',
            'Add CAPTCHA after failed attempts',
            'Use parameterized queries',
            'Enable account lockout'
        ]
    }
    
    vulns4 = [
        {
            'type': 'SQL Injection',
            'parameter': 'username',
            'payload': "admin' OR '1'='1' --",
            'confidence': 85,
            'severity': 'CRITICAL',
            'validated': True,
            'details': 'Authentication bypass successful'
        },
        {
            'type': 'Weak Authentication',
            'parameter': 'N/A',
            'payload': '',
            'confidence': 100,
            'severity': 'MEDIUM',
            'validated': True,
            'details': 'No rate limiting detected after 100 failed login attempts'
        }
    ]
    
    metadata4 = {
        'params': {},
        'tech_stack': ['PHP', 'MySQL', 'Apache'],
        'response_time': 312
    }
    
    report4 = url_reporter.create_url_report(
        url=url4,
        analysis_results=analysis4,
        vulnerabilities=vulns4,
        metadata=metadata4
    )
    print(f"   ✅ Report created: {report4}")
    
    # Generate master index
    print("\n📊 Generating master index...")
    index_path = url_reporter.generate_master_index()
    print(f"   ✅ Master index created: {index_path}")
    
    print(f"\n🎉 Demo complete! View reports at: {base_dir / 'url_reports'}")
    print(f"   📖 Start with: {index_path}")
    
    return base_dir


if __name__ == "__main__":
    asyncio.run(generate_example_reports())
