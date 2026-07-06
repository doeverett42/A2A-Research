# Skill definitions for DeepSeek agent.

from a2a.types import AgentSkill


def build_skills() -> list[AgentSkill]:
    return [
        AgentSkill(
            id="chat",
            name="General Chat",
            description = (
                "General conversational reasoning using DeepSeek-R1."
            ),
            tags=["chat", "reasoning", "assistant"],
            examples=[
                "Explain recursion",
                "Summarize this paper",
                "Write Python code",
            ],
            input_modes=["text/plain"],
            output_modes=["text/plain"],
        )
    ]
