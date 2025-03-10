from autogen import GroupChat, GroupChatManager
from typing import List, Dict, Any, Optional

def custom_speaker_selection(last_speaker, groupchat):
    """
    Control the conversation flow in the exploitation phase based on context
    
    This function implements a sophisticated conversation flow control system
    that determines which agent should speak next based on the current context,
    the last speaker, and the content of the messages.
    
    Args:
        last_speaker: The agent that spoke last
        groupchat: The GroupChat instance
        
    Returns:
        The next agent to speak or selection method
    """
    messages = groupchat.messages
    
    # Extract agent names for easier reference
    agent_names = {agent.name: agent for agent in groupchat.agents}
    
    # Identify agents by role
    coordinator = next((a for a in groupchat.agents if a.name == "coordinator"), None)
    scanner = next((a for a in groupchat.agents if a.name == "scanner"), None)
    sql_specialist = next((a for a in groupchat.agents if a.name == "sql_injection_specialist"), None)
    xss_specialist = next((a for a in groupchat.agents if a.name == "xss_specialist"), None)
    generic_exploiter = next((a for a in groupchat.agents if a.name == "generic_exploiter"), None)
    executor = next((a for a in groupchat.agents if a.name == "executor"), None)
    
    # Check if this is the first message (from user)
    if len(messages) == 1:
        return coordinator
    
    # Get the last message content
    last_message = messages[-1]["content"].lower()
    
    # Define keywords for different vulnerability types
    sqli_keywords = ["sql", "database", "injection", "query", "mysql", "postgresql", "oracle", "sqlite", "union", "select"]
    xss_keywords = ["xss", "cross-site", "javascript", "script", "alert", "dom", "html", "payload", "reflected", "stored"]
    recon_keywords = ["scan", "reconnaissance", "discovery", "mapping", "enumeration", "information gathering"]
    execution_keywords = ["execute", "run", "tool", "perform", "automate", "test", "verify", "check", "exploit"]
    
    # After scanning, coordinator decides what to do
    if last_speaker is scanner:
        return coordinator
        
    # Coordinator delegates to appropriate exploit agent
    elif last_speaker is coordinator:
        # Count the occurrences of keywords to determine the most relevant specialist
        sqli_count = sum(1 for keyword in sqli_keywords if keyword in last_message)
        xss_count = sum(1 for keyword in xss_keywords if keyword in last_message)
        recon_count = sum(1 for keyword in recon_keywords if keyword in last_message)
        execution_count = sum(1 for keyword in execution_keywords if keyword in last_message)
        
        # Determine the next speaker based on keyword relevance
        if execution_count > 0 and execution_count >= sqli_count and execution_count >= xss_count:
            return executor
        elif recon_count > 0 and recon_count >= sqli_count and recon_count >= xss_count:
            return scanner
        elif sqli_count > xss_count:
            return sql_specialist
        elif xss_count > 0:
            return xss_specialist
        else:
            return generic_exploiter
    
    # After any exploit agent speaks, let executor run tools if needed
    elif last_speaker in [sql_specialist, xss_specialist, generic_exploiter]:
        if any(keyword in last_message for keyword in execution_keywords):
            return executor
        else:
            return coordinator
    
    # After executor runs tools, return to the appropriate specialist based on context
    elif last_speaker is executor:
        # Analyze the last few messages to determine the vulnerability context
        context_window = min(5, len(messages))
        recent_messages = [msg["content"].lower() for msg in messages[-context_window:]]
        recent_content = " ".join(recent_messages)
        
        sqli_relevance = sum(1 for keyword in sqli_keywords if keyword in recent_content)
        xss_relevance = sum(1 for keyword in xss_keywords if keyword in recent_content)
        
        if "sql" in recent_content and sqli_relevance > xss_relevance:
            return sql_specialist
        elif "xss" in recent_content or "script" in recent_content and xss_relevance > 0:
            return xss_specialist
        elif any(keyword in recent_content for keyword in ["vulnerable", "vulnerability", "exploit"]):
            return generic_exploiter
        else:
            return coordinator
    
    # Default fallback to coordinator
    return coordinator

def create_exploit_groupchat(agents, llm_config):
    """
    Creates a GroupChat for complex exploitation scenarios with advanced speaker selection
    
    This function sets up a GroupChat with custom speaker selection logic that 
    intelligently controls the flow of conversation based on context, ensuring
    that the right specialist speaks at the right time.
    
    Args:
        agents: List of agents to include in the GroupChat
        llm_config: LLM configuration for the GroupChatManager
        
    Returns:
        GroupChatManager instance
    """
    # Create the GroupChat with custom speaker selection
    groupchat = GroupChat(
        agents=agents,
        messages=[],
        max_round=50,
        speaker_selection_method=custom_speaker_selection,
        allow_repeat_speaker=False
    )
    
    # Create the GroupChatManager with enhanced system message
    system_message = """You are the exploitation team manager for a bug bounty system.
    
    YOUR CAPABILITIES:
    - You coordinate the collaborative exploitation of identified vulnerabilities
    - You ensure methodical and structured approaches to exploitation
    - You can leverage multiple specialist agents working together
    - You maintain context and goal-orientation throughout the process
    
    YOUR WORKFLOW:
    1. Guide the exploitation team through a structured approach:
       - First understand the vulnerability type and attack surface
       - Plan the exploitation approach with appropriate specialists
       - Execute tests systematically using the executor agent
       - Document all findings and exploitation steps
       - Verify and confirm successful exploitation
    
    YOUR RESPONSIBILITIES:
    - Keep the conversation focused on the current vulnerability
    - Ensure methodical testing rather than random attempts
    - Delegate to specialists based on their expertise
    - Prevent agents from going off-topic or making unfounded assumptions
    - Step in when the conversation is not making progress
    - Summarize findings and next steps at key points
    
    You maintain a clear structure to exploitation:
    1. RECONNAISSANCE - Understand the attack surface
    2. PLANNING - Determine approach and tools needed
    3. EXECUTION - Methodical testing and exploitation
    4. VALIDATION - Confirm actual vulnerabilities
    5. DOCUMENTATION - Record findings and evidence
    """
    
    # Create the GroupChatManager
    manager = GroupChatManager(
        groupchat=groupchat,
        llm_config=llm_config,
        system_message=system_message,
        is_termination_msg=is_termination_message,
        human_input_mode="NEVER"
    )
    
    return manager

def is_termination_message(message: Dict[str, Any]) -> bool:
    """
    Determines if a message should terminate the GroupChat
    
    Args:
        message: The message to check
        
    Returns:
        True if the GroupChat should terminate, False otherwise
    """
    content = message.get("content", "").lower()
    
    # Check for explicit termination signals
    if any(phrase in content for phrase in [
        "exploitation complete",
        "all vulnerabilities tested",
        "no further exploitation possible",
        "completed all exploitation tasks",
        "finalize findings",
        "exploitation phase concluded"
    ]):
        return True
    
    # Check for a successful exploitation with documentation
    if "successfully exploited" in content and "documented" in content:
        return True
    
    # Check for a clear determination that no vulnerabilities exist
    if "no vulnerabilities found" in content and "confirm" in content:
        return True
    
    return False