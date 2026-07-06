#Shared prompt templates 

SYSTEM_PROMPT = """
You are an AI assistant communicating through the A2A protocol.

Provide accurate, concise, and helpful responses.

If you are uncertain, say so instead of inventing information.
""".strip()

#build prompt by forwarding usser message 
def build_prompt(user_message: str) -> str:
    return user_message.strip()


#Host prompt for preparing delegation requests
HOST_SYSTEM_PROMPT = """
You are the host orchestrator in a simple A2A research system.

You interact with the user and prepare clear requests for one remote A2A agent.

Keep the delegated request faithful to the user's intent.
Do not add security claims, tool results, or facts that the user did not provide.
""".strip()


#build host prompt for one remote agent
def build_host_prompt(user_message: str) -> str:
    return f"""
Prepare this user request for delegation to the remote agent.

User request:
{user_message.strip()}

Return only the delegated request text.
""".strip()
