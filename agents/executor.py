from autogen import UserProxyAgent
from autogen.coding import DockerCommandLineCodeExecutor, LocalCommandLineCodeExecutor
import os
from typing import Dict, Any, Optional, List, Union
import tempfile
import logging

def create_executor_agent(
    name: str = "executor",
    human_input_mode: str = "NEVER",
    use_docker: bool = True,
    work_dir: Optional[str] = None,
    docker_image: str = "python:3.11-slim",
    system_message: Optional[str] = None,
    additional_docker_run_args: Optional[Dict[str, Any]] = None,
    default_auto_reply: Optional[str] = None,
    logging_level: int = logging.INFO
):
    """
    Creates an executor agent specialized for running security testing tools and code in the bug bounty system.
    
    Args:
        name: Name of the executor agent
        human_input_mode: How to handle human input ("NEVER", "ALWAYS", or "TERMINATE")
        use_docker: Whether to use Docker for code execution (more secure)
        work_dir: Working directory for code execution (will create temp dir if None)
        docker_image: Docker image to use (if use_docker is True)
        system_message: Custom system message for the agent
        additional_docker_run_args: Additional arguments for Docker run command
        default_auto_reply: Default reply when human input is required but not provided
        logging_level: Level of logging to use
        
    Returns:
        UserProxyAgent configured for code execution
    """
    # Configure logging
    logging.basicConfig(level=logging_level)
    logger = logging.getLogger("executor_agent")
    
    # Create a temporary directory if work_dir is not provided
    if work_dir is None:
        temp_dir = tempfile.TemporaryDirectory()
        work_dir = temp_dir.name
        logger.info(f"Created temporary directory for code execution: {work_dir}")
    else:
        # Ensure the directory exists
        os.makedirs(work_dir, exist_ok=True)
        logger.info(f"Using provided directory for code execution: {work_dir}")
    
    # Configure default Docker run arguments for security
    if additional_docker_run_args is None and use_docker:
        additional_docker_run_args = {
            # Limit resources for security
            "cpu_quota": 100000,  # 100% of one CPU core
            "memory": "2g",       # 2GB memory limit
            "read_only": False,   # Allow writing to mounted volumes
            "network": "bridge",  # Use bridge network for limited connectivity
            # Security settings
            "security_opt": ["no-new-privileges:true"],
            "cap_drop": ["ALL"],  # Drop all capabilities for security
            "cap_add": ["NET_RAW", "NET_ADMIN"],  # Add only necessary capabilities for network scanning
        }
    
    # Default system message if not provided
    if system_message is None:
        system_message = """You are the executor agent in a bug bounty system.
        
Your role is to execute code and run security tools in a controlled environment.
You receive code blocks and tool commands from other agents and execute them.
You then return the results to the requesting agent.

When executing code:
1. Check the code for potential security risks
2. Execute the code in a sandboxed environment
3. Capture all outputs, errors, and results
4. Return the complete results to the requesting agent

You can run:
- Network scanning tools
- Web testing tools
- Browser automation
- Security analysis scripts
- Data processing and analysis code

Always ensure that execution is performed safely and results are returned accurately.
"""
    
    # Create the appropriate code executor
    if use_docker:
        try:
            executor = DockerCommandLineCodeExecutor(
                work_dir=work_dir,
                image=docker_image,
                timeout=60,  # Default timeout of 60 seconds
                additional_docker_run_args=additional_docker_run_args
            )
            logger.info(f"Created Docker code executor using image {docker_image}")
        except Exception as e:
            logger.warning(f"Failed to create Docker executor: {e}. Falling back to local executor.")
            executor = LocalCommandLineCodeExecutor(
                work_dir=work_dir,
                timeout=60
            )
    else:
        executor = LocalCommandLineCodeExecutor(
            work_dir=work_dir,
            timeout=60
        )
        logger.info("Created local code executor")
    
    # If default auto reply is not provided, use a security-focused one
    if default_auto_reply is None:
        default_auto_reply = "I'll execute this code in a secure environment and return the results."
    
    # Create the UserProxyAgent for code execution
    executor_agent = UserProxyAgent(
        name=name,
        system_message=system_message,
        human_input_mode=human_input_mode,
        code_execution_config={
            "executor": executor,
            "last_n_messages": 3,  # Consider the last 3 messages for code extraction
            "work_dir": work_dir,
        },
        default_auto_reply=default_auto_reply,
        description="Executes code and security tools in a sandboxed environment and returns results."
    )
    
    logger.info(f"Created executor agent '{name}' with {human_input_mode} human input mode")
    
    # Add a reference to the temp_dir to prevent garbage collection
    if work_dir is None:
        executor_agent._temp_dir = temp_dir
    
    # Add a method for executing specific tools
    executor_agent.execute_tool = lambda tool_name, **kwargs: _execute_tool(executor_agent, tool_name, **kwargs)
    
    return executor_agent

def _execute_tool(agent, tool_name: str, **kwargs) -> str:
    """
    Executes a specific named tool with the given arguments.
    
    Args:
        agent: The executor agent
        tool_name: Name of the tool to execute
        **kwargs: Arguments to pass to the tool
        
    Returns:
        String with the execution results
    """
    # Map of tool names to Python code templates for executing them
    tool_templates = {
        "nmap": """
import subprocess
import json

target = "{target}"
options = "{options}"

# Construct and execute the nmap command
cmd = f"nmap {{options}} {{target}} -oX nmap_results.xml"
print(f"Executing: {{cmd}}")

try:
    result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
    print("Command output:")
    print(result.stdout)
    
    # Read the XML results
    with open("nmap_results.xml", "r") as f:
        xml_content = f.read()
    
    print(f"Scan completed successfully. Results saved to nmap_results.xml")
    # Return a portion of the XML for immediate analysis
    print(xml_content[:1000] + "..." if len(xml_content) > 1000 else xml_content)
except subprocess.CalledProcessError as e:
    print(f"Error executing nmap: {{e}}")
    print(e.stderr)
""",
        
        "dirsearch": """
import subprocess
import json

target = "{target}"
wordlist = "{wordlist}"
extensions = "{extensions}"

# Construct and execute the dirsearch command
cmd = f"dirsearch -u {{target}} -w {{wordlist}} -e {{extensions}} -o dirsearch_results.json -f json"
print(f"Executing: {{cmd}}")

try:
    result = subprocess.run(cmd, shell=True, check=True, capture_output=True, text=True)
    print("Command output:")
    print(result.stdout)
    
    # Read the JSON results
    with open("dirsearch_results.json", "r") as f:
        json_content = f.read()
        results = json.loads(json_content)
    
    print(f"Directory scan completed successfully. Results saved to dirsearch_results.json")
    print(json.dumps(results, indent=2))
except subprocess.CalledProcessError as e:
    print(f"Error executing dirsearch: {{e}}")
    print(e.stderr)
except FileNotFoundError:
    print("dirsearch not found. Please install it or check if it's in the PATH.")
""",
        
        "http_request": """
import requests
import json

url = "{url}"
method = "{method}"
headers = {headers}
data = {data}

# Make the HTTP request
print(f"Making {{method}} request to {{url}}")
try:
    response = requests.request(
        method=method,
        url=url,
        headers=headers,
        data=data,
        timeout=10,
        verify=False  # Warning: This disables SSL verification for testing purposes
    )
    
    print(f"Status code: {{response.status_code}}")
    print("Headers:")
    for key, value in response.headers.items():
        print(f"{{key}}: {{value}}")
    
    # Try to parse as JSON first
    try:
        json_response = response.json()
        print("\\nResponse body (JSON):")
        print(json.dumps(json_response, indent=2))
    except:
        # If not JSON, print as text
        print("\\nResponse body (text):")
        print(response.text[:1000] + "..." if len(response.text) > 1000 else response.text)
except Exception as e:
    print(f"Error making request: {{e}}")
"""
    }
    
    if tool_name not in tool_templates:
        return f"Error: Tool '{tool_name}' not found. Available tools: {', '.join(tool_templates.keys())}"
    
    # Format the code template with the provided arguments
    try:
        code = tool_templates[tool_name].format(**kwargs)
    except KeyError as e:
        return f"Error: Missing required argument {e} for tool '{tool_name}'"
    
    # Create a message with the code block
    message = f"Execute the following code to run the {tool_name} tool:\n```python\n{code}\n```"
    
    # Send the message to ourselves and get the response
    agent.send(message, agent)
    
    # The last message in our conversation should be the execution result
    result = agent.chat_messages[agent.name][-1]["content"]
    return result

def stop_executor_agent(agent):
    """
    Properly stop the executor agent and clean up resources.
    
    Args:
        agent: The executor agent to stop
    """
    # Stop the code executor if it exists
    if hasattr(agent, "_code_execution_config") and agent._code_execution_config:
        executor = agent._code_execution_config.get("executor")
        if executor:
            try:
                executor.stop()
                print(f"Stopped code executor for agent '{agent.name}'")
            except Exception as e:
                print(f"Error stopping code executor: {e}")
    
    # Clean up the temporary directory if it exists
    if hasattr(agent, "_temp_dir"):
        try:
            agent._temp_dir.cleanup()
            print(f"Cleaned up temporary directory for agent '{agent.name}'")
        except Exception as e:
            print(f"Error cleaning up temporary directory: {e}")