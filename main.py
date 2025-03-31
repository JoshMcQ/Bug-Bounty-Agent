import os
from dotenv import load_dotenv
import autogen
from autogen import UserProxyAgent

# Local imports
from config.llm_config import get_llm_config
from agents.scanner import create_scanner_agent
from agents.exploiter import create_sql_injection_agent, create_xss_agent, create_generic_exploiter_agent
from agents.reporter import create_reporter_agent
from tools.browser_tool import create_browser_tool
from data.vulnerability_db.setup_db import create_vulnerability_db
from orchestration.group_chat import create_exploit_groupchat

def add_query_methods_to_agent(agent, query_engine):
    """
    Adds methods to an agent to query the Neo4j vulnerability knowledge graph.
    """
    def query_vulnerability(vulnerability_name):
        try:
            cypher_query = f'''
            MATCH (v:Vulnerability)
            WHERE v.name CONTAINS "{vulnerability_name}" OR v.cveID = "{vulnerability_name}"
            RETURN v
            LIMIT 1
            '''
            result = query_engine.graph_query(cypher_query)
            if result and len(result) > 0:
                return result[0]["v"]
            return f"No information found about vulnerability: {vulnerability_name}"
        except Exception as e:
            return f"Error querying vulnerability: {e}"
    
    def query_exploit_techniques(vulnerability_name):
        try:
            cypher_query = f'''
            MATCH (v:Vulnerability)-[:EXPLOITED_BY]->(e:Exploit)
            WHERE v.name CONTAINS "{vulnerability_name}" OR v.cveID = "{vulnerability_name}"
            RETURN e
            '''
            result = query_engine.graph_query(cypher_query)
            if result and len(result) > 0:
                return [item["e"] for item in result]
            return f"No exploitation techniques found for: {vulnerability_name}"
        except Exception as e:
            return f"Error querying exploitation techniques: {e}"
    
    agent.query_vulnerability = query_vulnerability
    agent.query_exploit_techniques = query_exploit_techniques

def main():
    # Load environment variables from .env file
    from dotenv import load_dotenv
    load_dotenv()
    
    # Ensure the required API key is loaded
    if not os.environ.get("OPENAI_API_KEY"):
        raise ValueError("OPENAI_API_KEY environment variable must be set")
    
    # Get LLM configuration
    llm_config = get_llm_config()
    
    # Create agents (Note: coordinator is removed; generic exploiter is created as 'generic_exploiter')
    scanner_agent = create_scanner_agent(llm_config)
    sqli_agent = create_sql_injection_agent(llm_config)
    xss_agent = create_xss_agent(llm_config)
    generic_exploiter = create_generic_exploiter_agent(llm_config)
    reporter_agent = create_reporter_agent(llm_config)
    
    # Create executor agent for tool execution (using simplified executor configuration)
    executor_agent = UserProxyAgent(
        name="executor",
        human_input_mode="ALWAYS",
        code_execution_config={
            "work_dir": "execution",
            "use_docker": True,
        }
    )
    
    # Create user proxy for human interaction
    user_proxy = UserProxyAgent(
        name="user_proxy",
        human_input_mode="ALWAYS",
        code_execution_config=False
    )
    
    # Setup Neo4j vulnerability knowledge graph integration
    try:
        print("Connecting to Neo4j vulnerability knowledge graph...")
        query_engine = create_vulnerability_db()
        for agent in [sqli_agent, xss_agent, generic_exploiter]:
            add_query_methods_to_agent(agent, query_engine)
            current_system_message = agent.system_message
            rag_addition = """

You have access to a knowledge graph containing information about vulnerabilities and exploitation techniques.
You can use these methods to query the knowledge graph:
- query_vulnerability(name): Get details about a specific vulnerability by name or CVE ID.
- query_exploit_techniques(name): Get exploitation techniques for a vulnerability by name or CVE ID.
"""
            if "knowledge graph" not in agent.system_message:
                agent.system_message = current_system_message + rag_addition
        print("Successfully connected to vulnerability knowledge graph")
    except Exception as e:
        print(f"Warning: Could not set up Neo4j database connection: {e}")
        print("Continuing without knowledge graph capabilities...")
    
    # Create and register tools (nmap tool is commented out)
    try:
        print("Setting up security testing tools...")
        create_browser_tool(
            llm_config,
            executor_agent,
            [sqli_agent, xss_agent, generic_exploiter]
        )
        print("Tools configured successfully")
    except Exception as e:
        print(f"Warning: Error setting up tools: {e}")
    
    # Create a unified GroupChatManager for the entire process
    agents = [
        scanner_agent,
        sqli_agent,
        xss_agent,
        generic_exploiter,
        reporter_agent,
        executor_agent
    ]
    groupchat_manager = create_exploit_groupchat(agents, llm_config)
    
    # Get target from user
    target = input("Enter target domain or IP to assess (e.g., example.com): ")
    
    # Initiate the group chat using the manager
    updated_context = groupchat_manager.initiate_chat(
        recipient=groupchat_manager,
        message=f"Perform security assessment on {target}"
    )
    
    # Display results summary
    print("\n=== Bug Bounty Assessment Complete ===")
    print(f"Target: {target}")
    confirmed = updated_context.get("confirmed_vulnerabilities", [])
    print(f"Vulnerabilities found: {len(confirmed)}")
    if updated_context.get("report_generated", False):
        print("Report has been generated successfully.")
    
    return updated_context

if __name__ == "__main__":
    main()
