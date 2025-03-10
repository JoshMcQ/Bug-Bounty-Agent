import os
import autogen
from autogen import UserProxyAgent, ConversableAgent
from autogen.agentchat.contrib.graph_rag.falkor_graph_rag_capability import FalkorGraphRagCapability

# Local imports
from config.llm_config import get_llm_config
from agents.coordinator import create_coordinator_agent
from agents.scanner import create_scanner_agent
from agents.exploiter import create_sql_injection_agent, create_xss_agent, create_generic_exploiter_agent
from agents.reporter import create_reporter_agent
from tools.nmap_tool import create_nmap_tool
from tools.browser_tool import create_browser_tool
from tools.web_tools import register_web_tools
from data.vulnerability_db.setup_db import create_vulnerability_db
from orchestration.swarm import setup_bug_bounty_swarm, run_bug_bounty_swarm
from orchestration.group_chat import create_exploit_groupchat

def main():
    # Ensure environment variables are set
    if not os.environ.get("OPENAI_API_KEY"):
        raise ValueError("OPENAI_API_KEY environment variable must be set")
    
    # Get LLM configuration
    llm_config = get_llm_config()
    
    # Create agents
    coordinator_agent = create_coordinator_agent(llm_config)
    scanner_agent = create_scanner_agent(llm_config)
    sqli_agent = create_sql_injection_agent(llm_config)
    xss_agent = create_xss_agent(llm_config)
    generic_exploiter_agent = create_generic_exploiter_agent(llm_config)
    reporter_agent = create_reporter_agent(llm_config)
    
    # Create executor agent for tool execution
    executor_agent = UserProxyAgent(
        name="executor",
        human_input_mode="NEVER",
        code_execution_config={
            "work_dir": "execution",
            "use_docker": True,  # Set to True if Docker is available
        }
    )
    
    # Create user proxy for human interaction
    user_proxy = UserProxyAgent(
        name="user_proxy",
        human_input_mode="ALWAYS",
        code_execution_config=False
    )
    
    # Setup RAG for vulnerability knowledge
    try:
        query_engine = create_vulnerability_db()
        graph_rag_capability = FalkorGraphRagCapability(query_engine)
        # Add RAG capability to exploitation agents
        for agent in [sqli_agent, xss_agent, generic_exploiter_agent]:
            graph_rag_capability.add_to_agent(agent)
    except Exception as e:
        print(f"Warning: Could not set up RAG database: {e}")
        print("Continuing without RAG capabilities...")
    
    # Create and register tools
    nmap_tool = create_nmap_tool(executor_agent, scanner_agent)
    browser_tool = create_browser_tool(
        llm_config, 
        executor_agent, 
        [sqli_agent, xss_agent, generic_exploiter_agent]
    )
    register_web_tools(scanner_agent, executor_agent)
    
    # Setup exploit GroupChat for complex exploitation scenarios
    exploit_agents = [coordinator_agent, scanner_agent, sqli_agent, 
                     xss_agent, generic_exploiter_agent, executor_agent]
    exploit_manager = create_exploit_groupchat(exploit_agents, llm_config)
    
    # Setup swarm workflow
    exploitation_agents = [
        (sqli_agent, "Potential SQL injection vulnerability detected"),
        (xss_agent, "Potential XSS vulnerability detected"),
        (generic_exploiter_agent, "Potential vulnerability detected"),
        (exploit_manager, "Multiple vulnerabilities detected, need coordinated exploitation")
    ]
    
    setup_bug_bounty_swarm(coordinator_agent, scanner_agent, exploitation_agents, reporter_agent)
    
    # Get target from user
    target = input("Enter target domain or IP to assess (e.g., example.com): ")
    
    # Run the bug bounty swarm
    all_agents = [coordinator_agent, scanner_agent, sqli_agent, xss_agent, 
                 generic_exploiter_agent, reporter_agent, executor_agent, exploit_manager]
    
    chat_result, updated_context = run_bug_bounty_swarm(
        coordinator_agent, all_agents, user_proxy, target
    )
    
    # Display results summary
    print("\n=== Bug Bounty Assessment Complete ===")
    print(f"Target: {target}")
    print(f"Vulnerabilities found: {len(updated_context['confirmed_vulnerabilities'])}")
    if updated_context["report_generated"]:
        print("Report has been generated successfully.")
    
    return updated_context

if __name__ == "__main__":
    main()