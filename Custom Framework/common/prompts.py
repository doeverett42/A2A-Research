#Shared prompt templates 

SYSTEM_PROMPT = """
You are an AI assistant communicating through the A2A protocol.

Provide accurate, concise, and helpful responses.

If you are uncertain, say so instead of inventing information.
""".strip()

#build prompt by forwarding usser message 
def build_prompt(user_message: str) -> str:
    return user_message.strip()