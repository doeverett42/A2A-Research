import os
from typing import Any

import asyncio
from dotenv import load_dotenv

from pydantic import BaseModel  

from beeai_framework.agents import BaseAgent
from beeai_framework.agents.requirement import RequirementAgent
from beeai_framework.agents.requirement.requirements.conditional import ConditionalRequirement
from beeai_framework.backend import ChatModel
from beeai_framework.middleware.trajectory import EventMeta, GlobalTrajectoryMiddleware
from beeai_framework.tools.handoff import HandoffTool
from beeai_framework.tools import Tool
from beeai_framework.tools.types import StringToolOutput
from beeai_framework.emitter.emitter import Emitter 

from host.agent import create_host_client

#makes the terminal less crowded with warning that only last message is being considered in agent history 
import logging
import beeai_framework.adapters.a2a.agents._utils as a2a_utils

a2a_utils.logger.setLevel(logging.ERROR)


class ConciseGlobalTrajectoryMiddleware(GlobalTrajectoryMiddleware):
    def _format_prefix(self, meta: EventMeta) -> str:
        #keep the trace readable without the default colon suffix
        prefix = super()._format_prefix(meta)
        return prefix.rstrip(": ")

    def _format_payload(self, value: Any) -> str:
        #print only the event label and routing path, not the full payload
        return ""

#gives orchestrator agent explicit permission to fully read agent cards instead of calling remote agents directly
class InspectAgentCardTool(Tool):
    name = "InspectAgentCard"
    description = "Use this to read the full details of an agent's card."
    
    #nested class for input_schema attribute
    class input_schema(BaseModel):
        query: str = "" 

    def __init__(self, remote_agent):
        super().__init__()
        self.remote_agent = remote_agent

    def _create_emitter(self) -> Emitter:
        return Emitter()

    async def _run(self, input_data: input_schema, *args, **kwargs) -> StringToolOutput:
        try: 
            #extract the description
            description_text = str(self.remote_agent.agent_card.description)
            
            #beeai_framework expects a ToolOutput object
            return StringToolOutput(result=description_text)
        except Exception as e:
            print(f"\n[!] Tool Execution Error: {e}\n")
            return StringToolOutput(result=f"Failed to read agent card: {e}")

def build_orchestrator_agent(remote_agent) -> RequirementAgent:
    #load the local model used by the host-side orchestrator
    model_name = os.environ.get("OLLAMA_MODEL")
    if not model_name:
        raise RuntimeError("Set OLLAMA_MODEL to a valid provider:model value, such as ollama:granite3.3:8b.")

    llm = ChatModel.from_name(model_name)
    #log only the orchestrator and tool handoff events
    trajectory_middleware = ConciseGlobalTrajectoryMiddleware(
        target=True,
        included=[RequirementAgent, Tool],
        prefix_by_type={
            BaseAgent: "Agent ",
            Tool: "Tool "
        }
    )

    #wrap the remote client as a single handoff tool for the orchestrator
    remote_tool = HandoffTool(
        target=remote_agent,
        name=remote_agent.name,
        description=remote_agent.agent_card.description if remote_agent.agent_card else "Remote chatbot agent."
    )

    inspect_tool = InspectAgentCardTool(remote_agent)

    return RequirementAgent(
        name="HostOrchestrator",
        description="The primary routing agent that delegates tasks to the remote chatbot.",
        llm=llm,
        tools=[remote_tool, inspect_tool],
        middlewares=[trajectory_middleware],
        #Hardcoded reuquirements require the host to immediately delegate tasks to an agent rather 
        #than analyze agent cards and dtermine best fit, thus bypassing poisoned agentcard attack
        #requirements=[
        #    ConditionalRequirement(remote_tool, force_at_step=1, consecutive_allowed=False),
        #],
        role="Task Delegator",
        instructions=(
            "You are a local orchestrator. If the user asks about system configuration or agent cards, answer them yourself."
            "Only delegate tasks to the 'GeneralChatAgent' if the user needs help with generic queries."
        )
    )


def run_async(awaitable: Any):
    #bridge BeeAI awaitables with the user input loop
    async def runner():
        return await awaitable

    return asyncio.run(runner())

#gets the final output directly from the remote agent (contradicts wanting to trick the host llm with poisoned agent card)
def get_handoff_result_text(result: Any) -> str:
    #prefer the delegated tool result so the CLI shows the remote agent's answer directly
    for step in reversed(getattr(result.state, "steps", [])):
        tool = getattr(step, "tool", None)
        if tool is None:
            continue

        if tool.__class__.__name__ == "FinalAnswerTool":
            continue

        output = getattr(step, "output", None)
        if isinstance(output, ToolOutput):
            text = output.get_text_content().strip()
            if text:
                return text

    return result.last_message.text.strip() if result.last_message else ""


def main() -> None:
    print("Running A2A Orchestrator Agent")
    load_dotenv()

    #read the host, remote port, and shared API key from the environment
    host = os.environ.get("A2A_HOST")
    remote_port = os.environ.get("A2A_PORT")
    api_key = os.environ.get("A2A_API_KEY")

    if not host or not remote_port or not api_key:
        raise RuntimeError("A2A_HOST, A2A_PORT, and A2A_API_KEY must all be set.")

    remote_url = f"http://{host}:{remote_port}"
    remote_agent = create_host_client(remote_url, api_key)

    #discover the public agent card before starting the local prompt loop
    run_async(remote_agent.check_agent_exists())
    print(f"{remote_agent.name} initialized through discovery")

    orchestrator_agent = build_orchestrator_agent(remote_agent)
    print(f"{orchestrator_agent.meta.name} initialized")

    #input loop so the host is used from the terminal
    print("Type a prompt and press Enter. Type 'quit' or 'exit' to stop.")
    while True:
        try:
            user_prompt = input("You> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nExiting.")
            return

        if not user_prompt:
            continue

        if user_prompt.lower() in {"quit", "exit"}:
            print("Exiting.")
            return

        result = run_async(orchestrator_agent.run(user_prompt))
        reply_text = result.last_message.text.strip() if result.last_message else "No response generated."
        print(f"{orchestrator_agent.meta.name}> {reply_text}\n")


if __name__ == "__main__":
    main()
