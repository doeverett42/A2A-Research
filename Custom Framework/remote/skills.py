#Skill definitions for the remote agents

from a2a.types import AgentSkill


def build_skills(skill: dict) -> list[AgentSkill]:
    return [
        AgentSkill(
            id = skill["id"],
            name = skill["name"],
            description = skill["description"],
            tags = skill["tags"],
            examples = skill["examples"],
            input_modes = ["text/plain"],
            output_modes = ["text/plain"]
        )
    ]
