import os

import ngrok
import uvicorn


from fastapi import FastAPI, Request, Response
from contextlib import asynccontextmanager
from loguru import logger

from agents.agents import RunAgent, root_agent
from run_task import TEST_TOKEN, TaskRunHandler, format_output
from dotenv import load_dotenv
from models.run_task_handler import RunTaskRequest, TaskStatus

load_dotenv()

# Variables for signature verification and ngrok setup
HEADER_SIGNATURE_VALUE = os.getenv("HEADER_SIGNATURE_VALUE", "test")
NGROK_AUTH_TOKEN = os.getenv("NGROK_AUTH_TOKEN")
HEADER_SIGNATURE_NAME = "X-Tfc-Task-Signature"
APPLICATION_PORT = 8000


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Setting up ngrok Endpoint")
    set_auth_token = getattr(ngrok, "set_auth_token")
    set_auth_token(NGROK_AUTH_TOKEN)
    ngrok.forward(
        addr=APPLICATION_PORT,
    )
    yield
    logger.info("Tearing Down ngrok Endpoint")
    ngrok.disconnect()


app = FastAPI(lifespan=(lifespan if NGROK_AUTH_TOKEN is not None else None))
agent_runner = RunAgent(agent=root_agent)


@app.middleware("http")
async def check_auth_header(request: Request, call_next):
    if HEADER_SIGNATURE_NAME not in request.headers:
        return Response(content="Unauthorized", status_code=401)
    return await call_next(request)


@app.post("/run-task")
async def run_task(taskrun: RunTaskRequest, request: Request, response: Response):
    full_body = await request.body()
    task_run_handler = TaskRunHandler(
        header_signature_value=HEADER_SIGNATURE_VALUE,
        task_run_request=taskrun,
    )

    if not task_run_handler.verify_header_signature(
        request.headers.get(HEADER_SIGNATURE_NAME), full_body
    ):
        response.status_code = 401
        return {"message": "Signature verification failed."}

    if taskrun.access_token == TEST_TOKEN:
        logger.info("Test token received, skipping actual processing.")
        return {"message": "Run Task received and verified successfully!"}

    try:
        plan = await task_run_handler.download_plan_json()

    except Exception as e:
        logger.error(f"Error downloading plan JSON: {e}")
        response.status_code = 500
        await task_run_handler.send_failure_callback(
            message="Failed to download plan JSON."
        )
        return {"message": "Failed to download plan JSON."}

    try:
        output = await agent_runner.run(input_data=plan)
        formatted_output = format_output(output)
        await task_run_handler.send_callback(
            status_task=TaskStatus.PASSED, callback_request=formatted_output
        )
    except Exception as e:
        logger.error(f"Error running agent: {e}")
        response.status_code = 500
        await task_run_handler.send_failure_callback(message="Agent execution failed.")
        return {"message": "Agent execution failed."}

    return {}


def main():
    print("Hello from terraform-security-run-task-python!")


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=APPLICATION_PORT, reload=True)
