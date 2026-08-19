#!/usr/bin/env python3
"""의존성·모델 라이선스를 스캔해 THIRD_PARTY_NOTICES.md 를 생성한다.

왜 pip-licenses 가 아니라 직접 짰나:
  - 표준 라이브러리(`importlib.metadata`)만으로 되는 일에 배포 의존성을 늘릴 이유가 없다.
  - pip-licenses 는 환경에 설치된 전부를 훑는다. 그러면 다른 프로젝트가 남긴 잔재까지
    섞여 들어와 있지도 않은 위험(예: AGPL 패키지)을 보고한다. 여기서는 `pyproject.toml` 의
    직접 의존성에서 출발해 실제 의존 폐포만 따라간다.

사용법:
  python scripts/license_scan.py           # THIRD_PARTY_NOTICES.md 갱신
  python scripts/license_scan.py --check   # 갱신 없이 위험 항목만 출력(종료코드 1=위험 있음)

주의: 결과는 설치된 버전 기준이다. 의존성을 바꿨으면 설치 후 다시 돌려야 맞는다.
"""

from __future__ import annotations

import importlib.metadata as md
import re
import sys
import tomllib
from pathlib import Path

# 재배포 시 의무가 생기는 라이선스 계열. 걸린다고 곧바로 위반은 아니고 "확인 대상"이다.
COPYLEFT = re.compile(
  r"GPL|AGPL|LGPL|MPL|EPL|CDDL|SSPL|CC.?BY.?NC|NonCommercial|Proprietary", re.I
)

# 학습·추론 코드(scripts/train/**)가 쓰는 의존성. pyproject 에는 없다 — 모델을 만들 때만
# 쓰고 진단 파이프라인 실행에는 필요 없기 때문이다. 제8조⑥ 이 "활용한 모든 오픈소스
# 라이브러리·프레임워크"의 출처·라이선스 공개를 요구하므로 여기에 함께 싣는다.
# 목록을 손으로 적지 않고 requirements 파일을 직접 읽는 이유는, 팀원이 그 파일을 고쳤을 때
# 표가 조용히 어긋나는 것을 막기 위해서다.
TRAINING_REQUIREMENT_GLOB = "scripts/train/*/requirements*.txt"

# 학습 전용 패키지는 CUDA 환경 전제라 우리 macOS/CPU 개발 환경에 설치되지 않는다.
# importlib.metadata 로 못 읽으므로 PyPI 메타데이터를 직접 조회해 받아 적었다(2026-08-19).
# 설치돼 있으면 아래 값이 아니라 설치된 배포판의 메타데이터가 우선한다.
TRAINING_LICENSE_FALLBACK: dict[str, str] = {
  "datasets": "Apache 2.0",
  "peft": "Apache",
  "bitsandbytes": "MIT",
  "tensorboard": "Apache 2.0",
}

# 모델·데이터셋은 PyPI 메타데이터에 없으므로 손으로 관리한다.
# (이름, 출처, 라이선스, 비고) — 라이선스가 불명확하면 그대로 적는다. 아는 척하지 않는다.
MODELS: list[tuple[str, str, str, str]] = [
  (
    "dragonkue/BGE-m3-ko",
    "HuggingFace",
    "Apache-2.0",
    "문서/질의 임베딩. 재배포 제약 없음",
  ),
  (
    "dragonkue/bge-reranker-v2-m3-ko",
    "HuggingFace",
    "Apache-2.0",
    "reranker_on 프로파일. 재배포 제약 없음",
  ),
  (
    "townboy/kpfbert-ner",
    "HuggingFace",
    "MIT",
    "STEP 3 한국어 PII NER (개인정보 33종). 저장소에 `LICENSE`(MIT) + "
    "`NOTICE`(상류 저작권 고지 2건) 포함. 상류가 MIT 라 이 선언에 근거가 있다 "
    "— 위 '확인 필요' 참조",
  ),
  (
    "KPF/KPF-bert-ner",
    "HuggingFace",
    "MIT (상류 저장소 기준)",
    "위 모델의 base. HF 카드에는 `license:` 필드가 없으나 배포 주체의 GitHub "
    "저장소가 MIT — 위 '확인 필요' 참조",
  ),
  (
    "bbanany/qwen25-3b-korean-pii-gguf",
    "HuggingFace",
    "Qwen Research License (정확히 표기됨)",
    "STEP 4 교차검증용 로컬 sLLM(Ollama `korean-pii`). 모델 자체는 대회 "
    "제9조① '오픈웨이트 이상' 요건을 충족한다. base 인 "
    "`Qwen/Qwen2.5-3B-Instruct` 의 조건이 함께 적용되며, `LICENSE`+`NOTICE`+"
    "'Improved using Qwen' 표기를 모두 갖춰 재배포 조건(§3·§4.b)을 충족한다 "
    "— 2026-08-12 갱신본 기준, 위 '확인 필요' 참조",
  ),
  (
    "bbanany/qwen25-3b-korean-pii-qlora3",
    "HuggingFace",
    "Qwen Research License (정확히 표기됨)",
    "위 GGUF 의 상류 어댑터(FP16 병합본). `LICENSE`+`NOTICE`+'Improved using "
    "Qwen' 표기를 모두 갖춰 재배포 조건(§3·§4.b)을 충족한다 — GGUF 저장소가 "
    "따라야 할 기준",
  ),
  (
    "Qwen/Qwen2.5-3B-Instruct",
    "HuggingFace",
    "Qwen Research License (비OSI · 비상업 — 대회는 허용)",
    "위 sLLM 의 base. Qwen2.5 계열에서 0.5B·1.5B·7B·14B·32B 는 Apache-2.0 이고 "
    "**3B 와 72B 만** 이 라이선스다(2026-08-10 카드 전수 확인). 대회 [별표2] 가 "
    "Qwen 을 오픈웨이트 대표 모델로 명시하므로 비OSI 라도 제9조① 은 충족",
  ),
]

DATASETS: list[tuple[str, str, str, str]] = [
  (
    "townboy/korean-pii-dataset",
    "HuggingFace",
    "CC-BY-4.0",
    "STEP 3 NER 학습셋(전량 합성, 11,732문서·33종). 저장소에 `LICENSE` 포함. "
    "출처 표기만 하면 상업적 이용까지 허용",
  ),
  (
    "bbanany/korean-pii-candidate-classification",
    "HuggingFace",
    "other / all-rights-reserved (저장소 `LICENSE` 원문 기준)",
    "STEP 4 sLLM(`-qlora3` → GGUF) 파인튜닝셋. 전량 합성, 19,842건"
    "(train 15,875 / valid 1,984 / test 1,983 · 후보 태그 23종 · PII/NOT_PII 이진). "
    "비OSI 지만 **제8조⑤⑥ 은 데이터셋 공개를 의무화하지 않고 출처·라이선스 명시만 "
    "요구**하므로 이 표기로 요건을 충족한다(가중치 의무는 제9조②-2-나 로 별개). "
    "재배포·상업적 이용에는 저작권자 서면 허가가 필요하다",
  ),
  (
    "KDPII",
    "외부 제공",
    "재배포 제약",
    "연구 목적 한정·외부 배포 금지. 저장소에 포함하지 않으며 벤치마크(`rag pii-eval`) "
    "실행 시 사용자가 직접 준비한다. 자체 데이터셋으로 대체 예정",
  ),
  (
    "data/documents/**",
    "본 저장소",
    "MIT (본 저장소와 동일)",
    "`scripts/generate_dataset.py` 로 생성한 전량 합성 데이터. 실제 개인정보 0건",
  ),
]


def normalize(requirement: str) -> str:
  """Requires-Dist 문자열에서 배포 이름만 뽑아 정규화한다."""
  name = re.split(r"[<>=!~\[; ]", requirement.strip(), maxsplit=1)[0]
  return name.strip().lower().replace("_", "-")


def license_of(dist: md.Distribution) -> str:
  """배포판의 라이선스를 PEP 639 → License 헤더 → Classifier 순으로 읽는다."""
  meta = dist.metadata
  for key in ("License-Expression", "License"):
    value = (meta.get(key) or "").strip()
    # 일부 패키지는 License 헤더에 전문(수십 줄)을 통째로 넣는다 — 그건 표에 못 쓴다.
    if value and len(value) < 120 and value.lower() != "unknown":
      return value
  classifiers = [c for c in meta.get_all("Classifier") or [] if c.startswith("License ::")]
  if classifiers:
    return " / ".join(c.split(" :: ")[-1] for c in classifiers)
  return "UNKNOWN"


def dependency_closure(root: Path) -> tuple[list[tuple[str, str, str]], list[str]]:
  """pyproject 직접 의존성에서 출발해 설치된 의존 폐포를 수집한다.

  Returns:
    (rows, missing) — rows 는 (이름, 버전, 라이선스), missing 은 미설치 배포 이름.
    extra 마커가 붙은 선택 의존성은 기본 설치에 안 들어오므로 따라가지 않는다.
  """
  project = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))["project"]
  queue = [normalize(dep) for dep in project["dependencies"]]
  seen: set[str] = set()
  missing: list[str] = []
  rows: list[tuple[str, str, str]] = []

  while queue:
    name = queue.pop()
    if name in seen:
      continue
    seen.add(name)
    try:
      dist = md.distribution(name)
    except md.PackageNotFoundError:
      missing.append(name)
      continue
    rows.append((dist.metadata["Name"], dist.version, license_of(dist)))
    for requirement in dist.requires or []:
      if ";" in requirement and "extra ==" in requirement.split(";", 1)[1]:
        continue
      queue.append(normalize(requirement))

  rows.sort(key=lambda row: row[0].lower())
  return rows, sorted(missing)


def training_requirements(root: Path) -> list[tuple[str, str, str]]:
  """scripts/train/**/requirements*.txt 를 읽어 (패키지, 사용처, 라이선스) 를 만든다.

  버전 조건은 표에 넣지 않는다. 파일마다 범위가 달라(예: torch 가 학습은 고정 버전,
  추론은 범위) 한 칸에 합치면 거짓이 되고, 원본 파일이 같은 저장소에 있으므로 중복이다.
  """
  used_by: dict[str, set[str]] = {}
  for path in sorted(root.glob(TRAINING_REQUIREMENT_GLOB)):
    label = f"{path.parent.name}(추론)" if "inference" in path.name else path.parent.name
    for line in path.read_text(encoding="utf-8").splitlines():
      line = line.strip()
      if not line or line.startswith("#"):
        continue
      used_by.setdefault(normalize(line), set()).add(label)

  rows: list[tuple[str, str, str]] = []
  for name in sorted(used_by):
    try:
      lic = license_of(md.distribution(name))
    except md.PackageNotFoundError:
      lic = TRAINING_LICENSE_FALLBACK.get(name, "UNKNOWN")
    rows.append((name, " · ".join(sorted(used_by[name])), lic))
  return rows


def render(
  rows: list[tuple[str, str, str]],
  missing: list[str],
  training: list[tuple[str, str, str]],
) -> str:
  """THIRD_PARTY_NOTICES.md 본문을 만든다."""
  flagged = [row for row in rows if COPYLEFT.search(row[2])]
  unknown = [row for row in rows if row[2] == "UNKNOWN"]

  lines = [
    "# Third-Party Notices",
    "",
    "이 파일은 `python scripts/license_scan.py` 로 생성됩니다. **직접 고치지 마세요** —",
    "의존성을 바꿨으면 설치 후 스크립트를 다시 돌리면 됩니다.",
    "",
    "본 프로젝트(RAG-DIAG)는 MIT 라이선스입니다(`LICENSE`). 아래는 함께 쓰이는 제3자",
    "구성요소의 라이선스 목록입니다.",
    "",
    "## 요약",
    "",
    f"- 파이썬 의존 폐포: **{len(rows)}개**(설치 기준)",
    f"- 학습·추론 코드 의존성: **{len(training)}개**(`scripts/train/**`, 폐포와 별개)",
    f"- copyleft 계열: **{len(flagged)}개** — {', '.join(n for n, _, _ in flagged) or '없음'}",
    f"- 라이선스 미상: **{len(unknown)}개** — {', '.join(n for n, _, _ in unknown) or '없음'}",
    "",
    "## 확인 필요 (재배포 전에 판단할 것)",
    "",
    "| 대상 | 사안 |",
    "| --- | --- |",
    "| `certifi`, `tqdm` (MPL-2.0) | MPL 은 **파일 단위** copyleft다. 우리는 두 패키지를 "
    "수정하지 않고 pip 로 설치해 쓰기만 하므로 소스 공개 의무가 발생하지 않는다. "
    "벤더링(저장소에 복사)하는 순간 조건이 달라지니 하지 말 것. |",
    "| `KPF/KPF-bert-ner` (HF 카드 메타데이터만 미선언) | **재배포 조건 자체는 "
    "확인됐다(2026-08-09).** HuggingFace 카드에 `license:` 필드가 없을 뿐이고, 이 모델을 "
    "배포하는 상류 프로젝트 저장소 두 곳이 모두 MIT 다 — "
    "[KPFBERT/kpfbert](https://github.com/KPFBERT/kpfbert)(base KPF-BERT, © 2021 KPFBERT) · "
    "[KPF-bigkinds/BIGKINDS-LAB](https://github.com/KPF-bigkinds/BIGKINDS-LAB)"
    "(`KPF-BERT-NER/` 하위, © 2022 빅카인즈랩). MIT 는 재배포·서브라이선스를 허용하므로 "
    "파생 가중치를 MIT 로 공개할 근거가 있으며, 조건인 **저작권 고지 유지**는 "
    "`townboy/kpfbert-ner` 의 `NOTICE` 가 두 건 다 담고 있다. 남은 것은 상류 HF 카드의 "
    "메타데이터 공백뿐이라 우리 쪽 조치 사항은 없다. |",
    "| `Qwen/Qwen2.5-3B-Instruct` (STEP 4 sLLM 의 base) | **라이선스 원문 전수 확인함"
    "(2026-08-10).** `license: other` → 저장소 `LICENSE` 가 Qwen RESEARCH LICENSE AGREEMENT "
    "다. Qwen2.5 계열에서 **0.5B·1.5B·7B·14B·32B 는 Apache-2.0**, **3B 와 72B 만** 이 "
    "라이선스다. 오해하기 쉬운 세 가지를 원문 기준으로 정리한다. "
    "**① 재배포는 금지가 아니다** — §3 이 파생물 배포를 명시적으로 허용한다"
    "(조건: §3.a 계약서 사본 동봉 · §3.b 수정 파일 명시 · §3.c NOTICE 저작권 문구 · "
    "§4.b 'Improved using Qwen' 표기). "
    "**② 우리 사용도 위반이 아니다** — §1.i 가 Non-Commercial 을 'research or evaluation "
    "purposes only' 로 정의하므로 연구·대회 평가 용도는 §2.a 의 허여 범위 안이다"
    "(상업적 이용은 §2.b 로 별도 계약 필요). "
    "**③ 대회 규정과도 충돌하지 않는다(규정집 원문 확인 2026-08-10)** — 제9조① 은 "
    "'최소한 가중치가 공개된 **오픈웨이트 모델 이상**의 공개 수준'만 요구하고 오픈소스 "
    "AI(OSAID)는 '권장하나 의무로 강제하지 않는다'고 못박는다. [별표2] 의 오픈웨이트 "
    "대표 모델 목록에 **Qwen 이 이름으로 올라 있다**(LLaMA·Mistral·Qwen·Gemma·SOLAR). "
    "가중치에 대한 의무는 제9조②-2-나 '기반 모델의 라이선스 정책을 **최우선으로 준수하여 "
    "공개**' 이지 OSI 인증이 아니다 — **OSI 의무는 참가팀이 직접 작성한 코드에만** 붙는다"
    "(제8조① · 제9조②-2-다). [별표2] 가 경계하라는 것도 '**재배포 및 수정본 공개 금지**' "
    "인데 §3 은 그 반대다. **→ 재학습 불필요.** "
    "**④ GGUF 저장소 표기 결함 2건은 2026-08-12 에 해소됐다(2026-08-17 HF 저장소 직접 "
    "조회로 재확인).** 한동안 `bbanany/qwen25-3b-korean-pii-gguf` 는 (ㄱ) 카드에 "
    "`license: apache-2.0` 을 선언해 **우리가 갖지 않은 상업적 이용 권리를 넘기고**(§3.d 는 "
    "수정분에 다른 조건을 붙이는 것을 '전체가 이 계약을 계속 준수하는 한'으로만 허용한다), "
    "(ㄴ) `LICENSE`·`NOTICE`·'Improved using Qwen' 이 없어 §3.a·§3.c·§4.b 를 못 채웠다 — "
    "제9조②-2-나·제8조⑤⑥ 에 걸리는 상태였다. **현재 갱신본은 셋 다 갖췄다**: "
    "`license: other`+`license_name: qwen-research-license`+`license_link` · `LICENSE` "
    "7,442B · `NOTICE` 378B · 카드 본문 'Improved using Qwen.'. 상류 `-qlora3` 도 동일하다. "
    "**→ 이 항목에 남은 우리 쪽 조치는 없다.** 이력을 지우지 않고 남기는 이유는 이 파일이 "
    "규정 증빙 원자료라 '언제 무엇을 확인했는가'가 근거이기 때문이다. |",
    "| 대회 규정 제9조④ (**미이행**) | 'AI 모델을 탑재하거나 적용한 경우, 참가자는 **모델 "
    "정보를 포함하여 지정된 서식에 따라** 관련 내용을 작성하여 출품작과 함께 제출해야 "
    "한다.' 우리는 NER(`townboy/kpfbert-ner`)·sLLM(`bbanany/qwen25-3b-korean-pii-gguf`)·"
    "임베딩·리랭커 4종을 탑재하고 있다. 서식은 해당 연도 모집 공고에 붙으므로 **공고에서 "
    "서식을 받아 채워야 한다** — 이 파일이 그 원자료다. |",
    "| KDPII 데이터셋 | 재배포 제약이 있어 저장소에 포함하지 않는다. "
    "자체 합성 데이터셋으로 대체하는 작업이 진행 중이다. |",
    "",
    "## 모델 가중치",
    "",
    "| 모델 | 출처 | 라이선스 | 비고 |",
    "| --- | --- | --- | --- |",
  ]
  lines += [f"| `{n}` | {src} | {lic} | {note} |" for n, src, lic, note in MODELS]
  lines += [
    "",
    "## 데이터셋",
    "",
    "| 데이터셋 | 출처 | 라이선스 | 비고 |",
    "| --- | --- | --- | --- |",
  ]
  lines += [f"| `{n}` | {src} | {lic} | {note} |" for n, src, lic, note in DATASETS]
  lines += [
    "",
    "## 파이썬 의존성",
    "",
    "`pyproject.toml` 의 직접 의존성에서 출발한 의존 폐포입니다(선택적 extra 제외).",
    "",
    "| 패키지 | 버전 | 라이선스 |",
    "| --- | --- | --- |",
  ]
  lines += [f"| `{n}` | {v} | {lic} |" for n, v, lic in rows]
  lines += [
    "",
    "## 학습·추론 코드 의존성",
    "",
    "`scripts/train/**` 의 모델 학습·추론 코드가 쓰는 패키지입니다. 진단 파이프라인 실행에는",
    "필요하지 않아 `pyproject.toml` 에 넣지 않았고, 정확한 버전 조건은 각 폴더의",
    "`requirements*.txt` 원본에 있습니다.",
    "",
    "| 패키지 | 사용처 | 라이선스 |",
    "| --- | --- | --- |",
  ]
  lines += [f"| `{n}` | {where} | {lic} |" for n, where, lic in training]

  if missing:
    lines += [
      "",
      "### 이 환경에 설치되지 않아 확인하지 못한 항목",
      "",
      "플랫폼 조건부 의존성(Windows 전용·CUDA 전용 등)이라 macOS/CPU 환경에서는 설치되지",
      "않습니다. 해당 플랫폼에서 다시 돌리면 표에 채워집니다.",
      "",
      ", ".join(f"`{name}`" for name in missing),
    ]

  return "\n".join(lines) + "\n"


def main() -> int:
  root = Path(__file__).resolve().parent.parent
  rows, missing = dependency_closure(root)
  flagged = [row for row in rows if COPYLEFT.search(row[2])]
  unknown = [row for row in rows if row[2] == "UNKNOWN"]

  if "--check" in sys.argv:
    for name, version, lic in flagged + unknown:
      print(f"{name:28s} {version:14s} {lic}")
    print(f"\ncopyleft {len(flagged)}건 · 미상 {len(unknown)}건 / 폐포 {len(rows)}개")
    return 1 if (flagged or unknown) else 0

  target = root / "THIRD_PARTY_NOTICES.md"
  training = training_requirements(root)
  target.write_text(render(rows, missing, training), encoding="utf-8")
  print(
    f"{target.name} 생성 — 의존성 {len(rows)}개 · 학습 의존성 {len(training)}개 · "
    f"copyleft {len(flagged)} · 미상 {len(unknown)}"
  )
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
