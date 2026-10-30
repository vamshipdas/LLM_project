import asyncio
import unittest
from types import SimpleNamespace

from app.services.rag_engine import SOCAgent


class FakeModel:
    def __init__(self, response):
        self.response = response
        self.messages = None

    async def ainvoke(self, messages):
        self.messages = messages
        return self.response


class SOCAgentTest(unittest.TestCase):
    def test_agent_uses_sop_tool_and_returns_citation(self):
        decision = SimpleNamespace(
            content="",
            tool_calls=[
                {
                    "name": "search_sops",
                    "args": {"query": "ransomware containment"},
                    "id": "call-1",
                }
            ],
        )
        agent = SOCAgent()
        agent._agent_model = FakeModel(decision)
        agent._llm = FakeModel(SimpleNamespace(content="Isolate the host.", tool_calls=[]))
        agent._search_sops = lambda _: [
            (
                {
                    "chunk_id": "CHK-1",
                    "sop_id": "SOP-SEC-02",
                    "section": "2.0 Containment",
                    "content": "Immediately isolate affected hosts via EDR.",
                },
                0.91,
            )
        ]

        response = asyncio.run(agent.chat("Investigate ticket", []))

        self.assertEqual(response.message, "Isolate the host.")
        self.assertEqual(response.sources[0]["sop_id"], "SOP-SEC-02")

    def test_agent_can_answer_without_retrieval(self):
        agent = SOCAgent()
        agent._agent_model = FakeModel(
            SimpleNamespace(content="Please provide the alert details.", tool_calls=[])
        )
        agent._llm = agent._agent_model
        agent._search_sops = lambda _: self.fail("SOP search should not run")

        response = asyncio.run(agent.chat("What can you help me investigate?", []))

        self.assertEqual(response.message, "Please provide the alert details.")
        self.assertEqual(response.sources, [])

    def test_greeting_never_searches_sops(self):
        agent = SOCAgent()
        agent._search_sops = lambda _: self.fail("Greeting must not search SOPs")

        response = asyncio.run(agent.chat("Hello!", []))

        self.assertIn("SOC investigation agent", response.message)
        self.assertEqual(response.sources, [])

    def test_muse_text_tool_envelope_is_executed(self):
        decision = SimpleNamespace(
            content=(
                'to=search_sops<|message|><atem:function_calls>'
                '<atem:invoke name="search_sops"><atem:parameter name="query">'
                'phishing containment</atem:parameter></atem:invoke></atem:function_calls>'
            ),
            tool_calls=[],
        )
        agent = SOCAgent()
        agent._agent_model = FakeModel(decision)
        agent._llm = FakeModel(SimpleNamespace(content="Purge the message.", tool_calls=[]))
        agent._search_sops = lambda query: [
            ({"chunk_id": "CHK-2", "sop_id": "SOP-SEC-01", "section": "Containment", "content": query}, 0.9)
        ]

        response = asyncio.run(agent.chat("Investigate phishing", []))

        self.assertEqual(response.message, "Purge the message.")
        self.assertEqual(response.sources[0]["sop_id"], "SOP-SEC-01")


if __name__ == "__main__":
    unittest.main()
