from autogen import ConversableAgent
from typing import Dict, Any, List

# Any tools for this agent? From metre or so on?
def create_reporter_agent(llm_config):
    """Creates an agent responsible for generating comprehensive vulnerability reports"""
    system_message = """You are the security report writer for a bug bounty system.
    
    YOUR CAPABILITIES:
    - You create comprehensive, clear, and actionable vulnerability reports
    - You organize findings by severity and categorize them appropriately
    - You provide both executive summaries and detailed technical information
    - You suggest remediation steps for each vulnerability
    
    YOUR WORKFLOW:
    1. Collect all confirmed vulnerabilities from the exploitation phase
    2. Categorize findings by severity and vulnerability type
    3. For each vulnerability, document:
       - Clear description of the vulnerability
       - Technical details of discovery and exploitation
       - Step-by-step reproduction instructions
       - Severity rating with CVSS score when possible
       - Evidence (logs, screenshots, request/response data)
       - Specific remediation recommendations
    4. Create an executive summary for management
    5. Include a technical overview for the development team
    6. Organize the report in a professional, easy-to-navigate format
    
    YOUR REPORT STRUCTURE:
    1. Cover page with target information and assessment details
    2. Executive Summary
       - Overall security posture
       - Key findings by severity
       - Summary of recommendations
    3. Findings Overview
       - Table of vulnerabilities with severity, location, and brief description
       - Statistics and metrics on vulnerability types found
    4. Detailed Findings
       - Each vulnerability with full details
       - Technical description, impact, reproduction steps, and remediation
    5. Remediation Roadmap
       - Prioritized remediation steps
       - Recommended timelines based on severity
    6. Appendices
       - Testing methodology
       - Tools used
       - Raw evidence and logs
    
    SEVERITY RATINGS:
    - Critical: Vulnerabilities that provide immediate access to the system with high privileges
    - High: Vulnerabilities that can lead to data breach or significant functionality compromise
    - Medium: Vulnerabilities that may lead to moderate data exposure or functionality disruption
    - Low: Minor vulnerabilities with limited impact
    - Informational: General weaknesses or best practice suggestions
    
    For CVSS scoring, use version 3.1 with the following format:
    CVSS:3.1/AV:[N,A,L,P]/AC:[L,H]/PR:[N,L,H]/UI:[N,R]/S:[U,C]/C:[N,L,H]/I:[N,L,H]/A:[N,L,H]
    """
    
    return ConversableAgent(
        name="reporter",
        system_message=system_message,
        llm_config=llm_config,
        human_input_mode="NEVER",
        # Add function calling configuration
        function_map={
            "generate_executive_summary": generate_executive_summary,
            "format_vulnerability_finding": format_vulnerability_finding,
            "calculate_cvss_score": calculate_cvss_score,
            "generate_remediation_recommendation": generate_remediation_recommendation
        }
    )

def generate_executive_summary(
    target: str,
    assessment_date: str,
    critical_count: int,
    high_count: int,
    medium_count: int,
    low_count: int,
    info_count: int,
    key_findings: List[str],
    overall_risk: str,
    key_recommendations: List[str]
) -> str:
    """
    Generate an executive summary for the vulnerability report
    
    Args:
        target: The target of the assessment
        assessment_date: Date of the assessment
        critical_count: Number of critical vulnerabilities
        high_count: Number of high vulnerabilities
        medium_count: Number of medium vulnerabilities
        low_count: Number of low vulnerabilities
        info_count: Number of informational findings
        key_findings: List of key findings
        overall_risk: Overall risk rating
        key_recommendations: List of key recommendations
        
    Returns:
        Formatted executive summary
    """
    total_vulns = critical_count + high_count + medium_count + low_count + info_count
    
    summary = f"""
# Executive Summary

## Overview
This report presents the findings of a security assessment conducted on **{target}** on {assessment_date}.
The assessment identified **{total_vulns}** security issues of varying severity.

## Risk Profile
The overall security posture of the target is assessed as **{overall_risk}**.

## Vulnerability Summary
- **Critical**: {critical_count}
- **High**: {high_count}
- **Medium**: {medium_count}
- **Low**: {low_count}
- **Informational**: {info_count}

## Key Findings
"""
    
    for i, finding in enumerate(key_findings):
        summary += f"{i+1}. {finding}\n"
    
    summary += "\n## Key Recommendations\n"
    
    for i, recommendation in enumerate(key_recommendations):
        summary += f"{i+1}. {recommendation}\n"
    
    return summary

def format_vulnerability_finding(
    title: str,
    severity: str,
    cvss_score: str,
    description: str,
    impact: str,
    affected_component: str,
    reproduction_steps: List[str],
    evidence: str,
    remediation: str
) -> Dict[str, Any]:
    """
    Format a detailed vulnerability finding
    
    Args:
        title: Title of the vulnerability
        severity: Severity rating
        cvss_score: CVSS score
        description: Description of the vulnerability
        impact: Impact of the vulnerability
        affected_component: The affected component
        reproduction_steps: Steps to reproduce
        evidence: Evidence of the vulnerability
        remediation: Remediation steps
        
    Returns:
        Formatted vulnerability finding
    """
    finding = {
        "title": title,
        "severity": severity,
        "cvss_score": cvss_score,
        "description": description,
        "impact": impact,
        "affected_component": affected_component,
        "reproduction_steps": reproduction_steps,
        "evidence": evidence,
        "remediation": remediation
    }
    
    return finding

def calculate_cvss_score(
    attack_vector: str,
    attack_complexity: str,
    privileges_required: str,
    user_interaction: str,
    scope: str,
    confidentiality: str,
    integrity: str,
    availability: str
) -> Dict[str, Any]:
    """
    Calculate CVSS score based on inputs
    
    Args:
        attack_vector: Attack vector (N, A, L, P)
        attack_complexity: Attack complexity (L, H)
        privileges_required: Privileges required (N, L, H)
        user_interaction: User interaction (N, R)
        scope: Scope (U, C)
        confidentiality: Confidentiality impact (N, L, H)
        integrity: Integrity impact (N, L, H)
        availability: Availability impact (N, L, H)
        
    Returns:
        CVSS score information
    """
    # This would normally calculate the actual CVSS score based on the inputs
    # For now, we'll return a simplified representation
    cvss_vector = f"CVSS:3.1/AV:{attack_vector}/AC:{attack_complexity}/PR:{privileges_required}/UI:{user_interaction}/S:{scope}/C:{confidentiality}/I:{integrity}/A:{availability}"
    
    # Simplified severity mapping
    severity_map = {
        'Critical': (9.0, 10.0),
        'High': (7.0, 8.9),
        'Medium': (4.0, 6.9),
        'Low': (0.1, 3.9),
        'None': (0.0, 0.0)
    }
    
    # Simple mock score calculation
    # In a real implementation, this would use the actual CVSS calculation formula
    base_score = 0.0
    if attack_vector == 'N': base_score += 2.0
    if attack_complexity == 'L': base_score += 1.0
    if privileges_required == 'N': base_score += 1.5
    if user_interaction == 'N': base_score += 1.0
    if scope == 'C': base_score += 1.0
    if confidentiality == 'H': base_score += 1.5
    if integrity == 'H': base_score += 1.5
    if availability == 'H': base_score += 1.5
    
    # Determine severity based on score
    severity = "None"
    for sev, (min_score, max_score) in severity_map.items():
        if min_score <= base_score <= max_score:
            severity = sev
            break
    
    return {
        "vector_string": cvss_vector,
        "base_score": round(base_score, 1),
        "severity": severity
    }

def generate_remediation_recommendation(
    vulnerability_type: str,
    affected_component: str,
    custom_details: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Generate remediation recommendations based on vulnerability type
    
    Args:
        vulnerability_type: The type of vulnerability
        affected_component: The affected component
        custom_details: Custom details for the recommendation
        
    Returns:
        Remediation recommendation
    """
    # Common remediation templates
    remediation_templates = {
        "SQL Injection": {
            "short_term": "Implement input validation and parameterized queries for all database operations.",
            "long_term": "Use an ORM framework and apply the principle of least privilege to database users.",
            "references": [
                "https://owasp.org/www-community/attacks/SQL_Injection",
                "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html"
            ]
        },
        "XSS": {
            "short_term": "Implement output encoding for all user-controlled data displayed in the application.",
            "long_term": "Use Content Security Policy (CSP) and modern frameworks with built-in XSS protection.",
            "references": [
                "https://owasp.org/www-community/attacks/xss/",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html"
            ]
        },
        "CSRF": {
            "short_term": "Implement anti-CSRF tokens for all state-changing operations.",
            "long_term": "Use the SameSite cookie attribute and consider implementing additional security headers.",
            "references": [
                "https://owasp.org/www-community/attacks/csrf",
                "https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html"
            ]
        }
    }
    
    # Get the template for the vulnerability type or use a generic one
    template = remediation_templates.get(vulnerability_type, {
        "short_term": f"Review and fix the {vulnerability_type} vulnerability in {affected_component}.",
        "long_term": "Implement security testing as part of your development lifecycle.",
        "references": [
            "https://owasp.org/www-project-top-ten/"
        ]
    })
    
    recommendation = {
        "vulnerability_type": vulnerability_type,
        "affected_component": affected_component,
        "short_term_fix": template["short_term"],
        "long_term_fix": template["long_term"],
        "references": template["references"],
    }
    
    # Add any custom details
    if custom_details:
        recommendation.update(custom_details)
    
    return recommendation