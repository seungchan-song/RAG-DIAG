"""Step 4 sLLM verification for ambiguous NER findings."""

from __future__ import annotations

import os
import time
from typing import Any

from loguru import logger

from rag.pii.step3_ner import NERMatch


class SLLMVerifier:
  """Verify low-confidence Step 3 candidates with an sLLM."""

  VERIFICATION_PROMPT = """Decide whether the extracted span below is real personal information.

Entity: "{entity}"
NER tag: {tag}
Context: "{context}"

Reply with exactly one token:
- PII
- NOT_PII
"""

  def __init__(self, config: dict[str, Any]) -> None:
    pii_config = config.get("pii", {})
    runtime_config = pii_config.get("runtime", {})
    sllm_config = pii_config.get("sllm", {})

    self.enabled = bool(runtime_config.get("enable_step4", True))
    self.model = sllm_config.get("model", "gpt-4o-mini")
    self.max_retries = int(sllm_config.get("max_retries", 3))
    self.retry_backoff = int(sllm_config.get("retry_backoff", 2))
    self.mock_mode = self.enabled and not bool(os.getenv("OPENAI_API_KEY"))
    self.error_message = ""

    if not self.enabled:
      self.mode = "disabled"
    elif self.mock_mode:
      self.mode = "mock_conservative"
    else:
      self.mode = "api"

  def verify(self, entity_text: str, tag: str, context: str) -> bool:
    """Verify one ambiguous finding."""
    if not self.enabled:
      return False

    if self.mock_mode:
      logger.debug("Step 4 mock-conservative accept: [{}] {}", tag, entity_text)
      return True

    return self._call_api(entity_text, tag, context)

  def verify_batch(self, matches: list[NERMatch], full_text: str) -> list[NERMatch]:
    """Verify a list of low-confidence NER findings."""
    if not self.enabled or not matches:
      return []

    verified: list[NERMatch] = []
    for match in matches:
      try:
        context_start = max(0, match.start - 100)
        context_end = min(len(full_text), match.end + 100)
        context = full_text[context_start:context_end]
        if self.verify(match.text, match.tag, context):
          verified.append(match)
      except Exception as error:
        self.error_message = str(error)
        logger.warning(
          "Step 4 verification failed for [{}] {}. Falling back conservatively.",
          match.tag,
          match.text,
        )
        verified.append(match)

    return verified

  def get_runtime_status(
    self,
    *,
    candidate_count: int = 0,
    verified_count: int = 0,
    reason: str = "",
  ) -> dict[str, Any]:
    """Return a serializable Step 4 runtime status snapshot."""
    status = "skipped"
    if self.enabled and candidate_count > 0:
      status = "ready"
    elif self.enabled and self.mode == "mock_conservative":
      status = "ready"
    elif not self.enabled:
      status = "skipped"

    return {
      "enabled": self.enabled,
      "mode": self.mode,
      "status": status,
      "reason": reason,
      "model": self.model,
      "candidate_count": candidate_count,
      "verified_count": verified_count,
      "error": self.error_message,
    }

  def _call_api(self, entity_text: str, tag: str, context: str) -> bool:
    """Call the OpenAI API with retry and conservative fallback."""
    from openai import OpenAI

    client = OpenAI()
    prompt = self.VERIFICATION_PROMPT.format(
      entity=entity_text,
      tag=tag,
      context=context,
    )

    for attempt in range(self.max_retries):
      try:
        response = client.chat.completions.create(
          model=self.model,
          messages=[
            {
              "role": "system",
              "content": "You are validating whether a span is personal information.",
            },
            {"role": "user", "content": prompt},
          ],
          temperature=0.0,
          max_tokens=10,
        )
        answer = response.choices[0].message.content.strip().upper()
        self.error_message = ""
        return "PII" in answer and "NOT_PII" not in answer
      except Exception as error:
        self.error_message = str(error)
        if attempt < self.max_retries - 1:
          wait_time = self.retry_backoff ** attempt
          logger.warning(
            "Step 4 API call failed on attempt {} of {}: {}. Retrying in {}s.",
            attempt + 1,
            self.max_retries,
            error,
            wait_time,
          )
          time.sleep(wait_time)
        else:
          logger.warning(
            "Step 4 API call failed on attempt {} of {}: {}.",
            attempt + 1,
            self.max_retries,
            error,
          )

    logger.error(
      "Step 4 API exhausted retries. Falling back conservatively for [{}] {}.",
      tag,
      entity_text,
    )
    return True
