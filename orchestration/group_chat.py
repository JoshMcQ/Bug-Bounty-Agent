from autogen import GroupChat, GroupChatManager

# Find what agents is in main
def create_exploit_groupchat(agents, llm_config):
    """
    Creates a GroupChatManager with AG2's default ("auto") speaker selection.
    
    Args:
        agents: List of ConversableAgent instances to include in the group chat.
        llm_config: LLM configuration for the GroupChatManager.
        
    Returns:
        A GroupChatManager instance.
    """
    groupchat = GroupChat(
        agents=agents,
        messages=[],
        max_round=20,
        speaker_selection_method="auto",
        allow_repeat_speaker=False
    )
    
    system_message = (
        "You are the manager for the bug bounty system. Your role is to coordinate a team of specialized "
        "security testing agents in conducting a comprehensive vulnerability assessment of a target web application. "
        "Ensure that the conversation remains focused and methodical, guiding the team through these stages:\n\n"
        "1. Reconnaissance: Verify the target's attack surface by gathering information such as open ports, web "
        "technologies, and exposed directories.\n"
        "2. Planning: Determine which types of vulnerabilities to prioritize for exploitation.\n"
        "3. Exploitation: Delegate to the appropriate specialist agents (e.g., SQL Injection, XSS, or general "
        "exploitation) to test and confirm vulnerabilities.\n"
        "4. Reporting: Collect and consolidate the findings into a structured vulnerability report.\n\n"
        "Rely on the built-in automatic speaker selection to choose the next agent based on context. Ensure that "
        "each agent's contribution is clearly documented and that the conversation naturally flows toward a final, "
        "comprehensive report. Terminate the session once all critical vulnerabilities have been assessed and a final "
        "report is generated."
    ) 
    manager = GroupChatManager(
        groupchat=groupchat,
        llm_config=llm_config,
        system_message=system_message,
        human_input_mode="NEVER"
    )
    
    return manager
