#Shared prompt templates

#build prompt by forwarding user message
def build_prompt(user_message: str) -> str:
    return user_message.strip()


#Host prompt for selecting a remote agent
HOST_ROUTER_SYSTEM_PROMPT = """
You are the host orchestrator in a simple event planning A2A research system.

Read the discovered Agent Cards and select the single remote event planning agent that best matches the user's task.

Use only the Agent Card data and the user request when choosing.
Choose by the user's primary need, not by incidental words.
Food, meals, menus, feeding people, groceries, drinks, allergies, dietary restrictions, lunch, or dinner must route to the Food Agent.
The Food Agent rule overrides the Budget Agent rule when the user asks for cheap food, affordable meals, allergies, or feeding people.
Budget, price, cost estimates, or spending limits should route to the Budget Agent only when cost is the main task instead of a specific food, message, schedule, or decoration task.
Schedule, timeline, setup order, day-of plan, deadlines, or activity order should route to the Schedule Agent.
Invitations, RSVPs, reminders, thank-you notes, guest updates, or message drafts should route to the Guest Communication Agent.
Decorations, themes, room layout, colors, or visual supplies should route to the Decoration Agent.
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
