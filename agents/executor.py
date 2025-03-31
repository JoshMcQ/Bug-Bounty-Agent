import os
import tempfile
from autogen import ConversableAgent, LLMConfig
from autogen.coding import DockerCommandLineCodeExecutor

def create_executor_agent_simple(docker_image="python:3.12-slim", timeout=10):
    """
    Creates a simplified executor agent using the DockerCommandLineCodeExecutor.
    This agent will run code blocks in a Docker container and return the output.

    Args:
        docker_image: The Docker image to use for code execution.
        timeout: Timeout in seconds for each code execution.

    Returns:
        A ConversableAgent configured as an executor.
    """
    # Create a temporary directory for storing code files
    temp_dir = tempfile.TemporaryDirectory()
    work_dir = temp_dir.name

    # Create the Docker executor with default settings
    executor = DockerCommandLineCodeExecutor(
        work_dir=work_dir,
        image=docker_image,
        timeout=timeout
    )

    # Create the executor agent
    executor_agent = ConversableAgent(
        name="executor",
        llm_config=False,  # No LLM needed for direct code execution
        code_execution_config={
            "executor": executor,
            "work_dir": work_dir,
        },
        human_input_mode="ALWAYS",
        system_message=(
            "You are the executor agent in the bug bounty system. Your role is to run "
            "code blocks safely in a Docker container and return the results to the requesting agent."
        )
    )

    # Keep a reference to the temporary directory to avoid premature cleanup
    executor_agent._temp_dir = temp_dir

    return executor_agent