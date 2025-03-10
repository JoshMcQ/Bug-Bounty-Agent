from autogen.tools import ToolUser
from autogen.interop import Interoperability
from crewai_tools import WebsiteSearchTool
from langchain_community.tools import ArxivQueryRun, RequestsGetTool

# Can use tools like gobuster/dirbuster for hidden files, or llm can analyze HTML/JS for hidden clues
def register_web_tools(scanner_agent, executor_agent):
    """Creates and registers web-specific testing tools with cross-framework integration"""
    
    # Initialize interoperability for cross-framework tool integration
    interop = Interoperability()
    
    # Create CrewAI website search tool
    website_search_tool = WebsiteSearchTool()
    
    # Convert CrewAI tool to AG2 compatible tool
    ag2_website_search = interop.convert_tool(tool=website_search_tool, type="crewai")
    
    # Create LangChain RequestsGetTool
    requests_get_tool = RequestsGetTool()
    
    # Convert LangChain tool to AG2 compatible tool
    ag2_requests_get = interop.convert_tool(tool=requests_get_tool, type="langchain")
    
    # Create LangChain ArxivQueryRun for research on vulnerabilities
    arxiv_tool = ArxivQueryRun()
    
    # Convert ArxivQueryRun to AG2 compatible tool
    ag2_arxiv_tool = interop.convert_tool(tool=arxiv_tool, type="langchain")
    
    # Register cross-framework tools with agents
    ag2_website_search.register_for_execution(executor_agent)
    ag2_website_search.register_for_llm(scanner_agent)
    
    ag2_requests_get.register_for_execution(executor_agent)
    ag2_requests_get.register_for_llm(scanner_agent)
    
    ag2_arxiv_tool.register_for_execution(executor_agent)
    ag2_arxiv_tool.register_for_llm(scanner_agent)
    
    # Define additional custom web tool specifications
    web_tool_specs = {
        "directory_scan": {
            "name": "directory_scan",
            "description": "Scan for common directories and files on a web server",
            "parameters": {
                "type": "object",
                "properties": {
                    "base_url": {
                        "type": "string",
                        "description": "The base URL to scan"
                    },
                    "wordlist": {
                        "type": "string",
                        "description": "The wordlist to use (common, large, custom)",
                        "enum": ["common", "large", "custom"]
                    },
                    "extensions": {
                        "type": "string",
                        "description": "File extensions to check (comma-separated)"
                    }
                },
                "required": ["base_url"]
            }
        },
        "check_headers": {
            "name": "check_headers",
            "description": "Analyze security headers of a web page",
            "parameters": {
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "The URL to check"
                    }
                },
                "required": ["url"]
            }
        }
    }
    
    # Define implementation functions
    def directory_scan_impl(base_url, wordlist="common", extensions="php,html,txt"):
        """Implementation for the directory_scan tool"""
        result = f"Scanning directories at: {base_url}\n"
        result += f"Using wordlist: {wordlist}\n"
        result += f"Checking extensions: {extensions}\n"
        
        result += "```\n"
        result += f"# This would perform a directory and file scan on {base_url}\n"
        
        # Simulate scan results
        result += """
Scanning...
Found (200): /admin/
Found (200): /login.php
Found (200): /images/
Found (403): /config/
Found (200): /api/
Found (200): /docs/
Found (500): /debug.php
Found (200): /backup/index.html
        """
        
        result += "```\n"
        return result
    
    def check_headers_impl(url):
        """Implementation for the check_headers tool"""
        result = f"Analyzing security headers for: {url}\n"
        
        result += "```\n"
        result += f"# This would analyze HTTP security headers for {url}\n"
        
        # Simulate header analysis
        result += """
Security headers analysis:

✓ Strict-Transport-Security: max-age=31536000; includeSubDomains
✓ X-Content-Type-Options: nosniff
✓ X-Frame-Options: DENY
✗ Content-Security-Policy: Missing
✗ X-XSS-Protection: Missing
✓ Referrer-Policy: same-origin

Overall assessment: Moderate
Missing important security headers that could improve site security.
        """
        
        result += "```\n"
        return result
    
    # Create the custom web tools with implementations
    custom_web_tools = ToolUser(
        function_map={
            "directory_scan": directory_scan_impl,
            "check_headers": check_headers_impl
        },
        tool_name_to_spec={
            "directory_scan": web_tool_specs["directory_scan"],
            "check_headers": web_tool_specs["check_headers"]
        },
        user_name="custom_web_tools"
    )
    
    # Register the custom tools with the executor agent for execution
    custom_web_tools.register_for_execution(executor_agent)
    
    # Register the custom tools with the scanner agent for usage
    custom_web_tools.register_for_llm(scanner_agent)
    
    # Return all tools
    return {
        "website_search": ag2_website_search,
        "requests_get": ag2_requests_get,
        "arxiv_query": ag2_arxiv_tool,
        "custom_web_tools": custom_web_tools
    }