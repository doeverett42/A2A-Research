from beeai_framework.backend import ChatModel
from beeai_framework.backend.message import UserMessage


class ChatBotAgent:
    def __init__(self) -> None:
        #load the local DeepSeek model once when the server starts
        self.model = ChatModel.from_name("ollama:deepseek-r1:8b")

    async def answer_query(self, prompt: str) -> str:
        #clean the prompt before sending it to the model
        clean_prompt = prompt.strip()
        if not clean_prompt:
            return "DeepSeek did not receive a prompt."

        #ask the local model for a plain text answer
        result = await self.model.run([UserMessage(clean_prompt)])
        if result.last_message:
            return result.last_message.text.strip()

        return "DeepSeek returned no response."
