import os
import uvicorn
from dotenv import load_dotenv

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from a2a.server.apps import A2AStarletteApplication
from a2a.server.request_handlers import DefaultRequestHandler
from a2a.server.tasks import InMemoryTaskStore
from a2a.types import AgentCapabilities, AgentCard, AgentSkill, APIKeySecurityScheme, In
from remote.agent_executor import ChatBotAgentExecutor

#load environment variables 
load_dotenv() 

#these paths stay public so the host can discover the agent card
API_KEY_HEADER_NAME = "X-API-Key"
PUBLIC_AGENT_CARD_PATHS = {
    "/.well-known/agent-card.json",
    "/.well-known/agent.json",
}

#make API key middleware for custom security 
class APIKeyAuthMiddleware(BaseHTTPMiddleware): 
    def __init__(self, app, api_key: str): 
        super().__init__(app)
        self.api_key = api_key

    async def dispatch(self, request, call_next): 
        #leave public Agent Card open for A2A agentic discoverability 
        if request.url.path in PUBLIC_AGENT_CARD_PATHS: 
            return await call_next(request) 

        #block any requests without proper API key 
        provided_key = request.headers.get(API_KEY_HEADER_NAME)
        if not provided_key or provided_key != self.api_key: 
            return JSONResponse({"error": "Unauthorized: Invalid or missing API key"}, status_code=401)
        
        return await call_next(request) 
    
def main() -> None: 
    #read the remote server host and port from the environment
    PORT = int(os.environ.get("A2A_PORT"))
    HOST = os.environ.get("A2A_HOST")

    #define agent skills 
    skill = AgentSkill(
        id = "general_chat", 
        name = "General Chat", 
        description = "Provides helpful, straightforward answers to general questions.",
        tags = ["chat", "assistant"],
        examples = ["What is Python?"]
    )

    #define the auth scheme that client agents must match
    security_scheme_name = "api_key_auth"
    security_scheme = APIKeySecurityScheme(
        in_ = In.header,
        name = API_KEY_HEADER_NAME,
        description = "API key required in the X-API-Key header."
    )

    #declare the public agent card so clients can discover the remote agent
    agent_card = AgentCard(
        name = "GeneralChatAgent",
        description = "Remote DeepSeek-backed chatbot for general purpose",
        url = f"http://{HOST}:{PORT}/",
        version = "1.0.0",
        default_input_modes = ["text"],
        default_output_modes = ["text"], 
        capabilities = AgentCapabilities(streaming=False),
        skills = [skill],
        security_schemes = {
            security_scheme_name: security_scheme
        },
        security = [
            {
                security_scheme_name: []
            }
        ]
    )

    #route A2A protocol requests into the chatbot executor
    request_handler = DefaultRequestHandler(agent_executor=ChatBotAgentExecutor(), task_store=InMemoryTaskStore())

    server = A2AStarletteApplication(agent_card=agent_card, http_handler=request_handler) 

    #build the ASGI app and attach header validation
    app = server.build() 
    expected_api_key = os.environ.get("A2A_API_KEY")
    if not expected_api_key:
        raise RuntimeError("A2A_API_KEY must be set before starting the remote server.")
    app.add_middleware(APIKeyAuthMiddleware, api_key=expected_api_key)

    print(f"Starting native A2A server on http://{HOST}:{PORT}")
    uvicorn.run(app, host=HOST, port=PORT)  

if __name__ == "__main__":
    main() 
