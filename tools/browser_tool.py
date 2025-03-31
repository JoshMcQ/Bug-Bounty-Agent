from autogen.tools.experimental import BrowserUseTool

def create_browser_tool(llm_config, executor_agent, exploit_agents):
    """Creates and registers browser automation tools for web vulnerability testing
    using AG2's experimental browser tool capabilities"""
    
    # Initialize browser tool with experimental BrowserUseTool
    browser_use_tool = BrowserUseTool(
        llm_config=llm_config,
        browser_config={
            "headless": True,
        }
    )
    
    # Register the browser tool with the executor agent for execution
    browser_use_tool.register_for_execution(executor_agent)

    # Register the browser tool with each exploitation agent for usage
    for agent in exploit_agents:
        browser_use_tool.register_for_llm(agent)
    
    return browser_use_tool