#Skill definitions for the remote Ollama agent

from a2a.types import AgentSkill


def build_skills(model: str) -> list[AgentSkill]:
    model_tag = model.split(":")[0]
    return [
        AgentSkill(
            id = "chat",
            name = "General Chat",
            description = (
                f"General conversational reasoning using {model}."
            ),
            tags = ["chat", "reasoning", "assistant", model_tag],
            examples = [
                "Explain recursion",
                "Summarize this paper",
                "Write Python code"
            ],
            input_modes = ["text/plain"],
            output_modes = ["text/plain"]
        )
    ]
