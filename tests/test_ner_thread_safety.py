"""STEP 3 NER 을 여러 스레드가 공유해도 안전한지 검증합니다.

배경(RAG-2026-0806-001, 2026-08-06 실측):
  `StorageSanitizer` 는 detector 를 하나 만들어 재사용하고(`artifacts.py:12`
  "Reuse one warmed-up detector"), CLI 는 그걸 5워커 ThreadPoolExecutor 에서
  동시에 호출한다. HuggingFace 의 fast(Rust) 토크나이저는 재진입이 안 되므로
  `RuntimeError: Already borrowed` 가 터진다.

  피해가 조용해서 더 나빴다 — 실행은 성공으로 끝나고(실행 실패 0건) 그 응답만
  **NER 없이** 채점된다. 전체 매트릭스 런에서 **응답 1,468건 중 611건(41.6%)**,
  R2 는 540건 중 398건이 이렇게 유출을 과소보고했다.

  게다가 `load_status` 가 sticky 라 **한 번의 경쟁이 뒤따르는 모든 응답까지**
  `failed` 로 물들였다(step4 도 `step3_unavailable` 로 연쇄 skip).
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from rag.pii.step3_ner import NERDetector


class _RaceDetectingTokenizerBackend:
  """재진입하면 터지는 Rust 토크나이저를 흉내낸다.

  실제 `tokenizers` 는 RefCell 이 이미 빌려진 상태에서 다시 들어오면
  `Already borrowed` 를 던진다. 여기서는 동시 진입 자체를 감지해 같은 예외를 낸다.
  """

  def __init__(self) -> None:
    self._active = 0
    self._guard = threading.Lock()
    self.max_concurrent = 0

  def _enter(self) -> None:
    with self._guard:
      self._active += 1
      self.max_concurrent = max(self.max_concurrent, self._active)
      if self._active > 1:
        self._active -= 1
        raise RuntimeError("Already borrowed")

  def _exit(self) -> None:
    with self._guard:
      self._active -= 1

  def run(self, payload):
    self._enter()
    try:
      # 경쟁 창을 넓혀 락이 없으면 반드시 겹치게 만든다.
      threading.Event().wait(0.002)
      return payload
    finally:
      self._exit()


class _FakeTokenizer:
  """`_iter_windows` 가 부르는 토크나이저. 백엔드를 공유해 경쟁을 감지한다."""

  model_max_length = 512

  def __init__(self, backend: _RaceDetectingTokenizerBackend) -> None:
    self._backend = backend

  def __call__(self, text, **kwargs):
    self._backend.run(None)
    # 창분할이 일어나지 않도록 짧은 오프셋을 돌려준다(이 테스트의 관심사가 아님).
    return {"offset_mapping": [(i, i + 1) for i in range(min(len(text), 10))]}


class _FakePipeline:
  """token-classification 파이프라인. 토크나이저와 같은 백엔드를 공유한다."""

  def __init__(self, backend: _RaceDetectingTokenizerBackend) -> None:
    self.tokenizer = _FakeTokenizer(backend)
    self._backend = backend

  def __call__(self, text):
    self._backend.run(None)
    return [
      {"entity_group": "PS_NAME", "word": "홍길동", "start": 0, "end": 3, "score": 0.99}
    ]


def _shared_detector() -> tuple[NERDetector, _RaceDetectingTokenizerBackend]:
  backend = _RaceDetectingTokenizerBackend()
  detector = NERDetector({"pii": {"ner": {"confidence_threshold": 0.5}}})
  detector.pipeline = _FakePipeline(backend)
  detector.load_status = "ready"
  return detector, backend


def test_concurrent_detect_does_not_raise_already_borrowed() -> None:
  """5워커가 detector 하나를 동시에 써도 전부 탐지에 성공해야 한다."""
  detector, backend = _shared_detector()

  with ThreadPoolExecutor(max_workers=5) as executor:
    results = list(
      executor.map(lambda i: detector.detect(f"홍길동 응답 {i}"), range(40))
    )

  # 하나라도 빈 결과면 그 응답은 NER 없이 채점된 것이다 — 조용한 과소보고.
  empty = [index for index, matches in enumerate(results) if not matches]
  assert not empty, f"NER 없이 채점된 응답 {len(empty)}건: {empty[:5]}"
  assert detector.load_status == "ready"
  # 락이 실제로 직렬화했는지 확인(백엔드에 두 스레드가 동시에 들어간 적 없음).
  assert backend.max_concurrent == 1


def test_transient_inference_failure_is_not_sticky() -> None:
  """일시적 추론 오류가 이후 응답의 상태까지 오염시키면 안 된다."""
  detector, _ = _shared_detector()
  detector.load_status = "failed"
  detector.error_message = "Already borrowed"

  matches = detector.detect("홍길동 응답")

  assert matches, "모델이 살아 있는데도 탐지가 비었습니다"
  assert detector.load_status == "ready", (
    "지난 호출의 실패가 남아 있으면 이후 모든 응답이 step3_unavailable 로 찍힌다"
  )
