import json
import os
import sys
import urllib.request


class AIAgent:
    def __init__(self, name, api_url=None, api_model=None):
        self.name = name
        self.api_url = api_url or os.getenv("FREE_AI_API_URL")
        self.api_model = api_model or os.getenv("FREE_AI_API_MODEL", "google/flan-t5-small")

    def _call_free_api(self, prompt):
        if not self.api_url:
            return None

        payload = {
            "inputs": prompt,
            "parameters": {
                "max_new_tokens": 200,
                "temperature": 0.7,
                "do_sample": True,
            },
        }

        try:
            request = urllib.request.Request(
                self.api_url,
                data=json.dumps(payload).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(request, timeout=30) as response:
                raw = response.read().decode("utf-8")

            data = json.loads(raw)
            if isinstance(data, list) and data and isinstance(data[0], dict):
                return data[0].get("generated_text") or data[0].get("text")
            if isinstance(data, dict):
                if "generated_text" in data:
                    return data["generated_text"]
                if "text" in data:
                    return data["text"]
                if "error" in data:
                    raise RuntimeError(data["error"])
            return None
        except Exception:
            return None

    def _local_response(self, input_text, context=None):
        """Provide useful offline guidance when no model endpoint is configured."""
        context = context or {}
        incident = context.get("incident") or {}
        feed = context.get("feed") or {}
        prompt = input_text.lower()

        if incident:
            verdict = str(incident.get("verdict", "unknown")).upper()
            severity = str(incident.get("severity", "unknown")).upper()
            confidence = float(incident.get("confidence", 0))
            action = str(incident.get("action", "review")).replace("AUTO_", "").replace("_", " ")
            details = incident.get("details") or {}
            source = details.get("src_ip", "the reported source")
            target = details.get("target_host", "the affected host")

            if any(word in prompt for word in ("summar", "explain", "what happened", "analy")):
                return (
                    f"Incident summary: {verdict} activity was detected with {confidence:.0%} "
                    f"confidence and {severity.lower()} severity. The event involves {source} "
                    f"and {target}. The simulated policy recommends {action.lower()}. "
                    "Next safe step: verify the evidence, confirm the affected asset, and "
                    "approve containment only after analyst review."
                )
            if any(word in prompt for word in ("action", "respond", "next", "contain", "priorit")):
                return (
                    f"Recommended response: review the {severity.lower()} {verdict.lower()} event "
                    f"({confidence:.0%} confidence), validate {source} against the event details, "
                    f"then follow the simulated action '{action}'. No real infrastructure is changed."
                )

        event_count = int(feed.get("event_count", 0))
        threat_count = int(feed.get("threat_count", 0))
        if event_count:
            return (
                f"The current feed contains {event_count:,} events and {threat_count:,} detected "
                "threats. Prioritize high-severity, high-confidence events, then send uncertain "
                "detections to analyst review. All response actions in this demo are simulated."
            )
        return (
            "No incident telemetry is available yet. Start simulate_stream.py, refresh the feed, "
            "and ask again once events appear."
        )

    def respond(self, input_text, context=None):
        api_response = self._call_free_api(input_text)
        if api_response:
            return api_response.strip()
        return self._local_response(input_text, context)


if __name__ == "__main__":
    agent = AIAgent(
        "Auto-Coder",
        api_url=os.getenv("FREE_AI_API_URL"),
        api_model=os.getenv("FREE_AI_API_MODEL"),
    )

    if len(sys.argv) > 1:
        prompt = " ".join(sys.argv[1:])
    else:
        prompt = "Hello, how can I assist you today?"

    print(agent.respond(prompt))