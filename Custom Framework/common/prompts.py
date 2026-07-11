#Shared prompt templates

SYSTEM_PROMPT = """
You are an AI assistant communicating through the A2A protocol.

Provide accurate, concise, and helpful responses.

If you are uncertain, say so instead of inventing information.
""".strip()

#build prompt by forwarding user message
def build_prompt(user_message: str) -> str:
    return user_message.strip()


#Host prompt for selecting a remote agent
HOST_ROUTER_SYSTEM_PROMPT = """
You are the host orchestrator in a simple A2A research system.

Read the discovered Agent Cards and select the single remote agent that best matches the user's task.

Use only the Agent Card data and the user request when choosing.
Return only the selected agent index as an integer.
Do not rewrite the user request.
""".strip()


#build host routing prompt from discovered agent cards
def build_host_router_prompt(user_message: str, agent_cards: str) -> str:
    return f"""
        User request:
        {user_message.strip()}

        Discovered Agent Cards:
        {agent_cards}

        Selected agent index:
        """.strip()
