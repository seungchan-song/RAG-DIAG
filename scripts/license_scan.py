#!/usr/bin/env python3
"""의존성·모델 라이선스를 스캔해 THIRD_PARTY_NOTICES.md 를 생성한다.

왜 pip-licenses 가 아니라 직접 짰나:
  - 표준 라이브러리(`importlib.metadata`)만으로 되는 일에 배포 의존성을 늘릴 이유가 없다.
  - pip-licenses 는 **환경에 설치된 전부**를 훑는다. 그러면 다른 프로젝트가 남긴 잔재까지
    섞여 들어와 있지도 않은 위험(예: AGPL 패키지)을 보고한다. 여기서는 `pyproject.toml` 의
    직접 의존성에서 출발해 **실제 의존 폐포만** 따라간다.

사용법:
  python scripts/license_scan.py           # THIRD_PARTY_NOTICES.md 갱신
  python scripts/license_scan.py --check   # 갱신 없이 위험 항목만 출력(종료코드 1=위험 있음)

주의: 결과는 **설치된 버전 기준**이다. 의존성을 바꿨으면 설치 후 다시 돌려야 맞는다.
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
    "townboy/kpfbert-kdpii",
    "HuggingFace",
    "MIT (선언값)",
    "STEP 3 한국어 PII NER. base 가 KPF/KPF-bert-ner 이고 그쪽 라이선스가 "
    "미선언이라 이 MIT 선언의 근거가 확인되지 않았다 — 위 '확인 필요' 참조",
  ),
  (
    "KPF/KPF-bert-ner",
    "HuggingFace",
    "미선언",
    "위 모델의 base. 라이선스 표기가 없어 파생물 재배포 조건을 알 수 없다",
  ),
]

DATASETS: list[tuple[str, str, str, str]] = [
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


def render(rows: list[tuple[str, str, str]], missing: list[str]) -> str:
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
    "| `KPF/KPF-bert-ner` (미선언) | STEP 3 NER 의 base 모델인데 HuggingFace 에 라이선스 "
    "표기가 없다. 파생 가중치(`townboy/kpfbert-kdpii`)를 MIT 로 공개할 근거가 확인되지 "
    "않은 상태다. **한국언론진흥재단에 이용 조건을 확인하거나, 라이선스가 명확한 다른 "
    "백본으로 재학습**해야 대회 산출물 공개 요건이 안전하다. |",
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
  target.write_text(render(rows, missing), encoding="utf-8")
  print(
    f"{target.name} 생성 — 의존성 {len(rows)}개 · "
    f"copyleft {len(flagged)} · 미상 {len(unknown)}"
  )
  return 0


if __name__ == "__main__":
  raise SystemExit(main())
