from autogen.agentchat.contrib.graph_rag.falkor_graph_rag_capability import FalkorGraphRagCapability

def setup_rag_for_agents(query_engine, agents_list):
    """
    Integrates RAG capabilities with the specified agents.
    
    This function adds FalkorDB GraphRAG capability to the provided agents,
    enabling them to access and leverage the vulnerability knowledge graph.
    
    Args:
        query_engine: The FalkorGraphQueryEngine instance.
        agents_list: List of agents to enhance with RAG capability.
        
    Returns:
        The graph_rag_capability instance.
    """
    # Create the RAG capability with the provided query engine
    graph_rag_capability = FalkorGraphRagCapability(query_engine)
    
    # Add the capability to each agent in the list
    for agent in agents_list:
        graph_rag_capability.add_to_agent(agent)
        
        # Update the agent's system message to mention RAG capability
        current_system_message = agent.system_message
        rag_addition = """
        
You have access to a knowledge graph containing information about vulnerabilities and 
exploitation techniques. You can use this knowledge to better understand, identify,
and exploit security vulnerabilities during the bug bounty process.
        """
        
        # Only add the RAG message if it's not already there
        if "knowledge graph" not in agent.system_message:
            agent.system_message = current_system_message + rag_addition
    
    return graph_rag_capability

def create_rag_prompts():
    """
    Creates specialized prompts for RAG queries.
    
    These prompts help guide the RAG system to retrieve the most relevant
    information for different types of vulnerability queries.
    
    Returns:
        Dictionary of named prompts for different query types.
    """
    rag_prompts = {
        "vulnerability_details": """
        Find detailed information about the {vulnerability_name} vulnerability.
        Include description, severity, and common exploitation vectors.
        """,
        
        "exploit_techniques": """
        What are the most effective techniques for exploiting {vulnerability_name}?
        Include practical examples and detection methods.
        """,
        
        "remediation_advice": """
        What are the recommended remediation strategies for {vulnerability_name}?
        Include both quick fixes and comprehensive solutions.
        """,
        
        "related_vulnerabilities": """
        What other vulnerabilities are commonly found alongside {vulnerability_name}?
        Describe their relationships and how they might be chained together.
        """
    }
    
    return rag_prompts

def query_vulnerability_knowledge(agent, query_engine, vulnerability_name, query_type="vulnerability_details"):
    """
    Helper function for agents to query the vulnerability knowledge base.
    
    Args:
        agent: The agent making the query.
        query_engine: The FalkorGraphQueryEngine instance.
        vulnerability_name: Name of the vulnerability to query about.
        query_type: Type of query to perform (from create_rag_prompts keys).
        
    Returns:
        Query results as text.
    """
    # Get the prompts
    prompts = create_rag_prompts()
    
    # Select and format the appropriate prompt
    if query_type in prompts:
        prompt = prompts[query_type].format(vulnerability_name=vulnerability_name)
    else:
        # Default to general query
        prompt = f"Tell me about {vulnerability_name}"
    
    # Perform the query
    try:
        result = query_engine.query(prompt)
        return result
    except Exception as e:
        return f"Error querying knowledge base: {e}"