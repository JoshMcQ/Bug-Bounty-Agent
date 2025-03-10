from autogen import ConversableAgent
from typing import Dict, Any, List, Optional

# Check if tool is registered 
# Need execution agent too
def create_scanner_agent(llm_config):
    """
    Creates the scanner agent responsible for reconnaissance with enhanced capabilities
    for tool usage and structured information gathering.
    """
    system_message = """You are the reconnaissance agent for a bug bounty system.
    
    YOUR CAPABILITIES:
    - You gather comprehensive information about target systems using various scanning tools
    - You use Nmap for port and service discovery
    - You use web tools for directory enumeration, header analysis, and content discovery
    - You use browser automation to explore web applications
    - You can execute parallel scanning tasks on different components of a target
    
    YOUR WORKFLOW:
    1. First, understand the scope of the assessment (target domain/IP)
    2. Plan your reconnaissance approach based on the target type
    3. For web applications:
       - Check for subdomains and exposed directories
       - Analyze HTTP headers and security configurations
       - Identify technologies and software versions
       - Map the attack surface (forms, APIs, parameters)
    4. For network targets:
       - Perform port scanning to identify open services
       - Enumerate service versions and configurations
       - Look for known vulnerabilities in discovered services
    5. Document all findings in a structured format
    6. Identify potential vulnerability points for exploitation agents
    
    YOUR OUTPUT:
    When reporting findings, organize them in this structure:
    - Target information (domain, IP addresses)
    - Open ports and services
    - Web technologies identified
    - Directory structure and interesting files
    - Potential vulnerabilities categorized by type
    - Recommendations for exploitation focus
    
    When you identify potential vulnerabilities, specify:
    1. The vulnerability type (e.g., SQL Injection, XSS)
    2. The exact location (URL, parameter, port/service)
    3. Evidence that suggests the vulnerability
    4. Severity estimate (Critical, High, Medium, Low)
    
    Hand off to the coordinator agent when reconnaissance is complete or when you've identified high-value targets for immediate exploitation.
    """
    
    return ConversableAgent(
        name="scanner",
        system_message=system_message,
        llm_config=llm_config,
        human_input_mode="NEVER",
        # Add function calling configuration
        function_map={
            "report_scan_findings": report_scan_findings,
            "identify_vulnerability": identify_vulnerability
        }
    )

def report_scan_findings(
    target: str,
    ip_addresses: List[str],
    open_ports: Dict[str, str],
    web_technologies: List[str],
    directories: List[str],
    interesting_files: List[str],
    potential_vulnerabilities: List[Dict[str, Any]]
) -> str:
    """
    Format and report scan findings in a structured way
    
    Args:
        target: The target domain or IP
        ip_addresses: List of discovered IP addresses
        open_ports: Dictionary of open ports and their services
        web_technologies: List of identified web technologies
        directories: List of discovered directories
        interesting_files: List of interesting files found
        potential_vulnerabilities: List of potential vulnerabilities
        
    Returns:
        Formatted scan report
    """
    # Format the report
    report = f"## Reconnaissance Report for {target}\n\n"
    
    # Target information
    report += "### Target Information\n"
    report += f"- Target: {target}\n"
    report += f"- IP Addresses: {', '.join(ip_addresses)}\n\n"
    
    # Open ports and services
    report += "### Open Ports and Services\n"
    for port, service in open_ports.items():
        report += f"- Port {port}: {service}\n"
    report += "\n"
    
    # Web technologies
    if web_technologies:
        report += "### Web Technologies\n"
        for tech in web_technologies:
            report += f"- {tech}\n"
        report += "\n"
    
    # Directories and files
    if directories or interesting_files:
        report += "### Web Content Discovery\n"
        
        if directories:
            report += "#### Directories\n"
            for directory in directories:
                report += f"- {directory}\n"
            report += "\n"
            
        if interesting_files:
            report += "#### Interesting Files\n"
            for file in interesting_files:
                report += f"- {file}\n"
            report += "\n"
    
    # Potential vulnerabilities
    if potential_vulnerabilities:
        report += "### Potential Vulnerabilities\n"
        
        for vuln in potential_vulnerabilities:
            report += f"#### {vuln['type']} ({vuln['severity']})\n"
            report += f"- Location: {vuln['location']}\n"
            report += f"- Evidence: {vuln['evidence']}\n"
            if vuln.get('details'):
                report += f"- Details: {vuln['details']}\n"
            report += "\n"
    
    # Recommendations
    report += "### Recommendations\n"
    if potential_vulnerabilities:
        high_priority = [v for v in potential_vulnerabilities if v['severity'] in ['Critical', 'High']]
        if high_priority:
            report += "Priority exploitation targets:\n"
            for vuln in high_priority:
                report += f"- {vuln['type']} at {vuln['location']}\n"
        else:
            report += "- Continue with exploitation of identified potential vulnerabilities\n"
    else:
        report += "- Expand scanning to additional subdomains or paths\n"
        report += "- Consider deeper inspection of identified services\n"
    
    return report

def identify_vulnerability(
    vulnerability_type: str,
    location: str,
    evidence: str,
    severity: str,
    details: Optional[str] = None
) -> Dict[str, Any]:
    """
    Format a vulnerability finding
    
    Args:
        vulnerability_type: Type of vulnerability (e.g., "SQL Injection")
        location: Where the vulnerability was found
        evidence: Evidence supporting the vulnerability
        severity: Severity rating (Critical, High, Medium, Low)
        details: Additional details (optional)
        
    Returns:
        Formatted vulnerability dictionary
    """
    vuln = {
        "type": vulnerability_type,
        "location": location,
        "evidence": evidence,
        "severity": severity
    }
    
    if details:
        vuln["details"] = details
    
    return vuln