from autogen import OnCondition, AfterWork, AfterWorkOption, register_hand_off, initiate_swarm_chat

def setup_bug_bounty_swarm(coordinator_agent, scanner_agent, exploitation_agents, reporter_agent):
    """Configures the swarm workflow for the bug bounty process"""
    # Register hand-offs from coordinator to specialized agents
    register_hand_off(
        agent=coordinator_agent,
        hand_to=[
            OnCondition(scanner_agent, "Need to perform reconnaissance on target"),
            *[OnCondition(agent, condition) for agent, condition in exploitation_agents],
            OnCondition(reporter_agent, "Exploitation complete, generate report"),
            AfterWork(AfterWorkOption.REVERT_TO_USER)  # Fallback to user if needed
        ],
    )
    
    # Register hand-offs from scanner back to coordinator
    register_hand_off(
        agent=scanner_agent,
        hand_to=[AfterWork(coordinator_agent)]
    )
    
    # Register hand-offs from exploitation agents back to coordinator
    for agent, _ in exploitation_agents:
        register_hand_off(
            agent=agent,
            hand_to=[AfterWork(coordinator_agent)]
        )
    
    # Register hand-off from reporter to terminate the swarm
    register_hand_off(
        agent=reporter_agent,
        hand_to=[AfterWork(AfterWorkOption.TERMINATE)]
    )

def run_bug_bounty_swarm(coordinator_agent, all_agents, user_proxy, target):
    """Runs the bug bounty swarm against a target"""
    # Define context variables
    context = {
        "target_scope": target,
        "scan_results": None,
        "confirmed_vulnerabilities": [],
        "report_generated": False
    }
    
    # Start the swarm
    chat_result, updated_context, last_agent = initiate_swarm_chat(
        initial_agent=coordinator_agent,
        agents=all_agents,
        user_agent=user_proxy,
        context_variables=context,
        messages=f"Perform security assessment on {target}",
        max_rounds=100,
    )
    
    return chat_result, updated_context