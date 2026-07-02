from a2a.server.agent_execution import AgentExecutor, RequestContext
from a2a.server.events import EventQueue
from a2a.utils import new_agent_text_message
from remote.agent import ChatBotAgent

class ChatBotAgentExecutor(AgentExecutor): 
    #A2A compliant routing standard task events 
    def __init__(self): 
        #keep one chatbot instance behind the A2A executor
        self.agent = ChatBotAgent() 
    
    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None: 
        #extract user's input from the A2A JSON-RPC payload 
        prompt = context.get_user_input() 

        #pass task to internal agent logic 
        response = await self.agent.answer_query(prompt) 

        #enqueue the final artifact returned from chat bot to the client via A2A
        await event_queue.enqueue_event(new_agent_text_message(response))
    
    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None: 
        #A2A framework calls this if the server receives a signal that an ongoing task should be aborted 
        pass
