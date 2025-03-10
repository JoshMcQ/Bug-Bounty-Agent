from autogen import ConversableAgent

def create_coordinator_agent(llm_config):
    """Creates the coordinator agent that oversees the bug bounty process"""
    return ConversableAgent(
        name="coordinator",
        system_message="""You are the bug bounty coordinator. 
        Your role is to plan and oversee the security testing process.
        You determine which types of tests to run and delegate tasks to specialized agents.
        After scanning is complete, you decide which vulnerabilities to focus on exploiting.
        Once exploitation is complete, you request a detailed report.""",
        llm_config=llm_config
    )