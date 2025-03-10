import os

def get_llm_config():
    """Returns the LLM configuration for agents"""
    config_list = [{"model": "gpt-4o", "api_key": os.environ.get("OPENAI_API_KEY")}]
    return {"config_list": config_list}