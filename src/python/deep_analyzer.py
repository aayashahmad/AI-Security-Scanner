#!/usr/bin/env python3

import json
import sys
import os
from typing import Dict, List, Any
import re


class DeepSecurityAnalyzer:
    """Advanced security analyzer that uses AI techniques to provide deeper insights"""
    
    def __init__(self):
        self.patterns = {
            'sql_injection': r'(\b(select|update|delete|insert|drop|alter)\b.*\b(from|table|where|set)\b)|(\'\s*or\s*\'\s*=\s*\')|(\'\s*;\s*--\s*)',
            'xss_vulnerability': r'(<script[^>]*>|javascript:|\bon\w+\s*=|\beval\s*\()',
            'sensitive_data': r'(password|passwd|pwd|secret|api[_\-]?key|access[_\-]?token|auth[_\-]?token)',
            'path_traversal': r'(\.\./|\.\.\\|/etc/passwd|/etc/shadow|c:\\windows\\system32)',
            'open_redirect': r'(url=|redirect=|return=|next=|redir=|r=|destination=)'
        }
        self.severity_mapping = {
            'sql_injection': 'critical',
            'xss_vulnerability': 'high',
            'sensitive_data': 'high',
            'path_traversal': 'critical',
            'open_redirect': 'medium'
        }
    
    def analyze_content(self, url: str, content: str) -> List[Dict[str, Any]]:
        """Analyze page content for deeper security issues"""
        issues = []
        
        for issue_type, pattern in self.patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                context = content[max(0, match.start() - 30):min(len(content), match.end() + 30)]
                issues.append({
                    'id': f'deep_{issue_type}',
                    'severity': self.severity_mapping.get(issue_type, 'medium'),
                    'details': f'Potential {issue_type.replace("_", " ")} detected',
                    'context': context.strip(),
                    'url': url,
                    'position': match.start()
                })
        
        return issues
    
    def analyze_headers(self, url: str, headers: Dict[str, str]) -> List[Dict[str, Any]]:
        """Analyze HTTP headers for security issues"""
        issues = []
        
        # Check for insecure cookie settings
        if 'set-cookie' in headers and ('secure' not in headers['set-cookie'].lower() or 'httponly' not in headers['set-cookie'].lower()):
            issues.append({
                'id': 'deep_insecure_cookie',
                'severity': 'high',
                'details': 'Cookies set without Secure or HttpOnly flags',
                'context': headers['set-cookie'],
                'url': url
            })
        
        # Check for server information disclosure
        if 'server' in headers and len(headers['server']) > 0:
            issues.append({
                'id': 'deep_server_disclosure',
                'severity': 'medium',
                'details': 'Server header reveals software information',
                'context': headers['server'],
                'url': url
            })
        
        return issues
    
    def generate_recommendations(self, issues: List[Dict[str, Any]]) -> List[str]:
        """Generate specific recommendations based on discovered issues"""
        recommendations = []
        issue_types = set(issue['id'] for issue in issues)
        
        if 'deep_sql_injection' in issue_types:
            recommendations.append("Implement parameterized queries or prepared statements for all database operations. Never concatenate user input directly into SQL queries.")
        
        if 'deep_xss_vulnerability' in issue_types:
            recommendations.append("Implement context-specific output encoding and use Content Security Policy (CSP) to mitigate XSS attacks. Consider using modern frameworks that automatically escape output.")
        
        if 'deep_sensitive_data' in issue_types:
            recommendations.append("Remove sensitive data from client-side code. Store API keys and credentials securely using environment variables or a secure vault solution.")
        
        if 'deep_path_traversal' in issue_types:
            recommendations.append("Validate and sanitize all file paths. Use whitelisting approaches and avoid passing user input directly to filesystem operations.")
        
        if 'deep_open_redirect' in issue_types:
            recommendations.append("Implement a whitelist of allowed redirect destinations or use relative path redirects. Always validate redirect URLs against a list of allowed domains.")
        
        if 'deep_insecure_cookie' in issue_types:
            recommendations.append("Set the Secure, HttpOnly, and SameSite flags on all cookies containing sensitive information. Consider implementing token-based authentication instead of cookie-based authentication.")
        
        if 'deep_server_disclosure' in issue_types:
            recommendations.append("Configure your web server to remove or obfuscate the Server header to prevent information disclosure about your technology stack.")
        
        return recommendations
    
    def analyze_scan_results(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Analyze the complete scan results and provide enhanced insights"""
        all_issues = []
        all_urls = set()
        
        # Extract and process all issues
        for result in results:
            url = result.get('url', '')
            all_urls.add(url)
            
            # Add existing issues
            all_issues.extend(result.get('issues', []))
            
            # Add deep analysis issues if content is available
            if 'content' in result:
                content_issues = self.analyze_content(url, result['content'])
                all_issues.extend(content_issues)
            
            # Add header analysis issues if headers are available
            if 'headers' in result:
                header_issues = self.analyze_headers(url, result['headers'])
                all_issues.extend(header_issues)
        
        # Generate recommendations
        recommendations = self.generate_recommendations(all_issues)
        
        # Count issues by severity
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for issue in all_issues:
            severity = issue.get('severity', 'low')
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        # Calculate risk score (0-100)
        # Higher weights for critical and high issues
        risk_score = min(100, (
            severity_counts['critical'] * 25 + 
            severity_counts['high'] * 10 + 
            severity_counts['medium'] * 5 + 
            severity_counts['low'] * 1
        ))
        
        # Determine risk level
        risk_level = 'low'
        if risk_score > 75:
            risk_level = 'critical'
        elif risk_score > 50:
            risk_level = 'high'
        elif risk_score > 25:
            risk_level = 'medium'
        
        return {
            'enhanced_issues': all_issues,
            'recommendations': recommendations,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'severity_counts': severity_counts,
            'urls_analyzed': len(all_urls)
        }


def main():
    """Main function to process input and return results"""
    try:
        # Read input from stdin
        input_data = json.loads(sys.stdin.read())
        
        # Initialize analyzer
        analyzer = DeepSecurityAnalyzer()
        
        # Process the data
        results = analyzer.analyze_scan_results(input_data)
        
        # Output the results
        print(json.dumps(results, indent=2))
        
    except Exception as e:
        error_result = {
            'error': str(e),
            'status': 'failed'
        }
        print(json.dumps(error_result, indent=2))
        sys.exit(1)


if __name__ == "__main__":
    main()