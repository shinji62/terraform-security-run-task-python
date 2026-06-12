from dataclasses import dataclass
from pathlib import Path


from google.adk import Agent
from models.agents_output_sec import SecurityReport, SecurityStatus
from google.adk.runners import InMemoryRunner
from google.genai import types
from loguru import logger

APP_NAME = "adk_security_app"
USER_ID = "adk_security_runner"
STRUCTURE_KEY = "adk_security_structure"
PROMPT_PATH = Path(__file__).parent / "prompts" / "security.md"
# In a real application, this would be dynamic based on the authenticated user


@dataclass
class RunAgent:
    agent: Agent

    async def run(self, input_data: str) -> SecurityReport:
        runner = InMemoryRunner(
            agent=self.agent.root_agent,
            app_name=APP_NAME,
        )
        session = await runner.session_service.create_session(
            app_name=APP_NAME, user_id=USER_ID
        )
        user_content = types.Content(
            role="user",
            parts=[types.Part(text=f"Terraform Plan JSON:\n{input_data}\n\n")],
        )
        final_response_content = "No final response received."
        async for event in runner.run_async(
            user_id=USER_ID,
            session_id=session.id,
            new_message=user_content,
        ):
            if event.is_final_response() and event.content and event.content.parts:
                final_response_content = event.content.parts[0].text

        logger.info("Agent '{}' response: {}", self.agent.name, final_response_content)
        current_session = await runner.session_service.get_session(
            app_name=APP_NAME,
            user_id=USER_ID,
            session_id=session.id,
        )
        if current_session is None:
            return SecurityReport(
                status=SecurityStatus.FAILED,
                summary="Agent session was not available after execution.",
            )

        stored_output = current_session.state.get(STRUCTURE_KEY)

        if not stored_output:
            return SecurityReport(
                status=SecurityStatus.FAILED,
                summary="Agent failed to yield structured state output.",
            )

        return SecurityReport.model_validate(stored_output)


root_agent = Agent(
    model="gemini-3.5-flash",
    name="security_assessment_agent",
    description="An agent that performs security assessments on infrastructure.",
    instruction=PROMPT_PATH.read_text(),
    output_schema=SecurityReport,
    output_key=STRUCTURE_KEY,
)
