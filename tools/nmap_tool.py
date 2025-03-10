from autogen.tools import ToolUser
from autogen.interop import Interoperability
from langchain_community.tools import NmapScanTool

def create_nmap_tool(executor_agent, scanner_agent):
    """Creates and registers the Nmap scanning tool using cross-framework integration"""
    
    # Initialize interoperability for cross-framework integration
    interop = Interoperability()
    
    # Create a LangChain NmapScanTool
    langchain_nmap_tool = NmapScanTool()
    
    # Convert LangChain's tool to AG2 compatible tool
    ag2_nmap_tool = interop.convert_tool(tool=langchain_nmap_tool, type="langchain")
    
    # Register the converted tool with the executor agent for execution
    ag2_nmap_tool.register_for_execution(executor_agent)
    
    # Register the tool with the scanner agent for usage
    ag2_nmap_tool.register_for_llm(scanner_agent)
    
    # Define additional nmap tool specification for extended functionality
    nmap_vuln_scan_spec = {
        "name": "nmap_vuln_scan",
        "description": "Perform vulnerability scanning using Nmap scripts",
        "parameters": {
            "type": "object",
            "properties": {
                "target": {
                    "type": "string",
                    "description": "The target IP address or domain to scan"
                },
                "script": {
                    "type": "string",
                    "description": "The Nmap script to run (e.g., 'vuln', 'http-vuln*', etc.)"
                }
            },
            "required": ["target", "script"]
        }
    }
    
    # Implementation for the extended vulnerability scanning
    def nmap_vuln_scan_impl(target, script):
        """Implementation of the Nmap vulnerability scan tool"""
        
        # Construct the nmap command with script
        nmap_command = f"nmap --script={script} {target} -oX vuln_scan_results.xml"
        
        # Execute the command
        result = f"Running: {nmap_command}\n"
        result += "```\n"
        result += f"# This would execute the nmap vulnerability scan in a real environment\n"
        
        # Simulate output for development purposes
        if script == "vuln":
            result += """
Host is up (0.015s latency).
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Apache httpd 2.4.41
|_http-csrf: Couldn't find any CSRF vulnerabilities.
|_http-dombased-xss: Couldn't find any DOM based XSS.
| http-enum: 
|_  /admin/: Possible admin folder
| http-sql-injection: 
|   Possible sqli for queries:
|     http://target.com/search.php?q=test%27%20OR%20%271
|_    http://target.com/index.php?id=1%27%20OR%20%271
            """
        elif script == "http-vuln*":
            result += """
Host is up (0.015s latency).
PORT     STATE SERVICE       VERSION
80/tcp   open  http          Apache httpd 2.4.41
| http-vuln-cve2017-8917: 
|   VULNERABLE:
|   Drupal Core 8 PECL YAML parser inline string reflection vulnerability
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-8917
|     Risk factor: High
|       Drupal 8's PECL YAML parser does not handle inline strings securely, allowing
|       a malicious user to impact availability of the server.
|     Disclosure date: 2017-05-17
|     References:
|       https://www.drupal.org/node/2882364
|_      https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-8917
            """
        
        result += "```\n"
        return result
    
    # Create an additional tool for vulnerability scanning
    nmap_vuln_tool = ToolUser(
        function_map={"nmap_vuln_scan": nmap_vuln_scan_impl},
        tool_name_to_spec={"nmap_vuln_scan": nmap_vuln_scan_spec},
        user_name="nmap_vuln_tool"
    )
    
    # Register the vulnerability scanning tool
    nmap_vuln_tool.register_for_execution(executor_agent)
    nmap_vuln_tool.register_for_llm(scanner_agent)
    
    return {
        "basic_nmap": ag2_nmap_tool,
        "vuln_nmap": nmap_vuln_tool
    }