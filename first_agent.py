import os
from dotenv import load_dotenv

load_dotenv()

llm_config = {
    "config_list": [
        {
            "api_type": "openai",
            "model": "gpt-4o",
            "api_key": os.getenv("OPENAI_API_KEY")  # Use os.getenv for safer access
        }
    ],
}

from autogen import ConversableAgent, GroupChat, GroupChatManager

# Put your key in the OPENAI_API_KEY environment variable
#llm_config = {"api_type": "openai", "model": "gpt-4o-mini"}

planner_message = """You are a billionaire-planner agent.
Given the task, design a comprehensive business plan for launching an AI-driven SaaS platform in the SMB automation space (focused on digital marketing, content creation, and customer service).
Use the following format:
<industry_analysis>Evaluate and select the most promising market niche based on ease of entry, market saturation, and potential for revenue growth.</industry_analysis>
<business_model>Outline the optimal AI agent-based business model, combining workflow automation and SaaS delivery.</business_model>
<monetization_strategy>Detail actionable monetization strategies (subscriptions, usage-based fees, etc.) while excluding affiliate marketing.</monetization_strategy>
<technical_approach>Describe the technical execution plan, including leveraging OpenAI, Claude, DeepSink, and other reputable AI models, along with SEO-driven content and AI-driven marketing for high visibility.</technical_approach>
<actionable_steps>Provide a step-by-step guide to ideate, develop, test, launch, and scale the platform from zero initial capital to massive market impact.</actionable_steps>
"""

planner_description = "Creates or revises AI business plans with a focus on aggressive automation, actionable tasks, and disruptive market entry strategies."


lesson_planner = ConversableAgent(
    name="planner_agent",
    llm_config=llm_config,
    system_message=planner_message,
    description=planner_description,
)

reviewer_message = """You are a billionaire-plan reviewer.
Compare the business plan against the ideal AI-driven startup blueprint.
Identify up to three actionable improvements that enhance market fit, monetization strategy, technical execution, or scalability.
Provide only one round of reviews to the business plan."""
 
reviewer_description = "Provides one round of reviews to an AI business plan for the planner to revise."

lesson_reviewer = ConversableAgent(
    name="reviewer_agent",
    llm_config=llm_config,
    system_message=reviewer_message,
    description=reviewer_description,
)

ceo_message = """You are a CEO.
Decide on business strategies and collaborate with both the business planner and the reviewer agents to create and finalize high-impact, scalable business plans.
When you are satisfied with a plan, output "DONE!".
"""

ceo = ConversableAgent(
    name="ceo_agent",
    llm_config=llm_config,
    system_message=ceo_message,
    # 3. Our teacher can end the conversation by saying DONE!
    is_termination_msg=lambda x: "DONE!" in (x.get("content", "") or "").upper(),
)

# 4. Create the GroupChat with agents and selection method
groupchat = GroupChat(
    agents=[ceo, lesson_planner, lesson_reviewer],
    speaker_selection_method="auto",
    messages=[],
)

# 5. Our GroupChatManager will manage the conversation and uses an LLM to select the next agent
manager = GroupChatManager(
    name="group_manager",
    groupchat=groupchat,
    llm_config=llm_config,
)

# 6. Initiate the chat with the GroupChatManager as the recipient
ceo.initiate_chat(
    recipient=manager,
    message="Today, let's strategize on launching our disruptive AI-driven automation platform to capture the SMB market and scale to billion-dollar success."
)

# After initiating the chat, print the conversation log
print("Conversation messages:", groupchat.messages)
