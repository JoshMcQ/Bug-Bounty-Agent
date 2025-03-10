import asyncio
from typing import List, Dict, Any, Optional
import time

async def run_parallel_scans(user_proxy, scanner_agents, targets):
    """
    Runs parallel scanning tasks using multiple scanner agents.
    
    This function implements AG2's asynchronous workflows by initiating
    multiple parallel chats for different scanning targets.
    
    Args:
        user_proxy: The UserProxyAgent to initiate chats.
        scanner_agents: List of scanner agents to use for tasks.
        targets: List of targets or scanning tasks.
        
    Returns:
        Dict with results from all parallel tasks.
    """
    # Prepare the chat configurations
    chat_configs = []
    
    for i, (agent, target) in enumerate(zip(scanner_agents, targets)):
        chat_configs.append({
            "chat_id": i + 1,
            "recipient": agent,
            "message": target,
            "summary_method": "reflection_with_llm",
            "max_turns": 10
        })
    
    # Initiate parallel chats
    print(f"Starting {len(chat_configs)} parallel scanning tasks...")
    start_time = time.time()
    
    chat_results = await user_proxy.a_initiate_chats(chat_configs)
    
    end_time = time.time()
    print(f"All scanning tasks completed in {end_time - start_time:.2f} seconds")
    
    # Process and compile results
    compiled_results = {}
    
    for i, result in enumerate(chat_results):
        chat_id = i + 1
        summary = result.get("summary", "No summary available")
        messages = result.get("messages", [])
        
        # Extract the last message for result data
        last_message = messages[-1]["content"] if messages else "No result message"
        
        compiled_results[chat_id] = {
            "task": targets[i],
            "agent": scanner_agents[i].name,
            "summary": summary,
            "result": last_message
        }
    
    return compiled_results

async def run_multi_step_exploitation(coordinator, exploit_manager, target, vulnerabilities, user_proxy=None):
    """
    Runs a multi-step exploitation workflow using asynchronous tasks.
    
    Args:
        coordinator: The coordinator agent.
        exploit_manager: The GroupChatManager for exploitation.
        target: The target to exploit.
        vulnerabilities: List of vulnerabilities to exploit.
        user_proxy: Optional UserProxyAgent for human interaction.
        
    Returns:
        Results of the exploitation process.
    """
    # Initialize results tracking
    exploitation_results = {
        "target": target,
        "vulnerabilities_found": len(vulnerabilities),
        "exploitation_attempts": 0,
        "successful_exploits": 0,
        "exploitation_details": {}
    }
    
    # Define exploitation tasks for each vulnerability
    exploitation_tasks = []
    
    for i, vuln in enumerate(vulnerabilities):
        task_message = f"Exploit the {vuln['type']} vulnerability found at {vuln['location']} on {target}"
        exploitation_tasks.append({
            "chat_id": f"exploit_{i+1}",
            "recipient": exploit_manager,
            "message": task_message,
            "summary_method": "reflection_with_llm",
            "max_turns": 15
        })
    
    # Execute exploitation tasks asynchronously if there are any
    if exploitation_tasks:
        print(f"Starting exploitation of {len(exploitation_tasks)} vulnerabilities...")
        
        # If user_proxy is provided, use it to initiate chats
        if user_proxy:
            results = await user_proxy.a_initiate_chats(exploitation_tasks)
        else:
            # Placeholder for direct execution without user_proxy
            results = await asyncio.gather(*[
                coordinator.a_initiate_chat(
                    exploit_manager,
                    message=task["message"],
                    max_turns=task["max_turns"]
                ) for task in exploitation_tasks
            ])
        
        # Process results
        for i, result in enumerate(results):
            vuln_id = f"exploit_{i+1}" if user_proxy else i
            vuln = vulnerabilities[i]
            
            # Extract success status from result
            if isinstance(result, dict) and "messages" in result:
                messages = result["messages"]
                last_message = messages[-1]["content"] if messages else ""
                success = "successfully exploited" in last_message.lower() or "exploitation successful" in last_message.lower()
            else:
                last_message = str(result)
                success = "successfully exploited" in last_message.lower() or "exploitation successful" in last_message.lower()
            
            # Update statistics
            exploitation_results["exploitation_attempts"] += 1
            if success:
                exploitation_results["successful_exploits"] += 1
            
            # Store detailed results
            exploitation_results["exploitation_details"][vuln_id] = {
                "vulnerability": vuln,
                "success": success,
                "details": last_message[:500] + "..." if len(last_message) > 500 else last_message
            }
    
    return exploitation_results

async def async_vulnerability_scan(user_proxy, scanner_agent, targets):
    """
    Performs an asynchronous vulnerability scan on multiple targets.
    
    Example of how to use AG2's asynchronous workflows for parallel scanning.
    
    Args:
        user_proxy: The UserProxyAgent.
        scanner_agent: The scanner agent to use.
        targets: List of targets to scan.
        
    Returns:
        Scan results for all targets.
    """
    # Create scan tasks
    scan_tasks = []
    
    for i, target in enumerate(targets):
        scan_tasks.append({
            "chat_id": f"scan_{i+1}",
            "recipient": scanner_agent,
            "message": f"Perform a vulnerability scan on {target}",
            "summary_method": "reflection_with_llm",
        })
    
    # Initiate asynchronous chats
    print(f"Starting async vulnerability scans on {len(targets)} targets...")
    
    try:
        scan_results = await user_proxy.a_initiate_chats(scan_tasks)
        return scan_results
    except Exception as e:
        print(f"Error during async scanning: {e}")
        return {"error": str(e)}