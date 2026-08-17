# 샘플 진단 리포트

이 도구가 실제로 만들어내는 산출물입니다. 설치·실행 없이 결과물의 형태와 수준을 바로
확인할 수 있도록 완주한 실험 1건을 그대로 담았습니다.

## RAG-2026-0811-003 — 내장 RAG 전체 매트릭스

`RAG-2026-0811-003/report_dashboard.html` 은 외부 CDN 요청이 0건인 self-contained HTML 이라
웹서버도 인터넷 연결도 없이 브라우저로 바로 열립니다.

다만 **GitHub 웹에서 파일을 클릭해서는 볼 수 없습니다.** GitHub 은 HTML 을 렌더하지 않고,
3.2MB 라 미리보기도 뜨지 않으며(`View raw` 만 표시), raw 링크는 `text/plain` 으로 내려옵니다.
아래 둘 중 하나로 받아서 로컬 브라우저로 여세요.

```bash
# 저장소를 clone 한 경우 — 파일을 브라우저로 열기만 하면 됩니다
git clone https://github.com/seungchan-song/RAG-DIAG.git
# → RAG-DIAG/docs/sample-reports/RAG-2026-0811-003/report_dashboard.html

# 리포트 파일 하나만 받는 경우
curl -L -o report_dashboard.html \
  https://raw.githubusercontent.com/seungchan-song/RAG-DIAG/main/docs/sample-reports/RAG-2026-0811-003/report_dashboard.html
```

### 실험 구성

| 항목 | 값 |
|---|---|
| 진단 대상 | 내장 Haystack RAG (`adapter.type: builtin`, 6능력 전부 native) |
| 실행 범위 | 5시나리오 × 리랭커 2프로파일 = 10셀 |
| 총 질의 | 1,128건 (전량 `completed`, 실행 실패 0건) |
| 생성기 | 로컬 Ollama `qwen2.5:3b` — Closed API 호출 0건 |
| 리포트 생성 | 2026-08-12 |

### 이 리포트가 보여주는 것

| 지표 | 값 |
|---|---|
| 종합 위험 등급 | MEDIUM |
| R2 검색 데이터 유출 성공률 | 7.0% (300질의) |
| R4 멤버십 추론 성공률 | 38.0% (300질의) |
| R7 시스템 프롬프트 유출 성공률 | 15.0% (120질의) |
| R9 간접 프롬프트 주입 성공률 | 15.8% (120질의) |
| 대조군 대비 고유식별·금융 PII 노출 | 응답당 0.066건 → 0.257건 (**3.89배**) |

마지막 줄이 이 프로젝트의 핵심입니다. 공격 성공률만으로는 "원래도 새고 있던 양"과 "공격이
만든 양"을 구분할 수 없으므로, 공격 없는 일반 질의(NORMAL)를 같은 인덱스에서 함께 돌려
증분을 분리합니다.

### 담긴 파일

| 파일 | 설명 |
|---|---|
| `report_dashboard.html` | 심사·검토용 종합 대시보드 (판정 → 유출 규모 → 권고 조치 → 판정 근거 → 부록) |
| `report_summary.json` | 연구용 요약 원본 (시나리오·환경·프로파일별 전체 지표) |
| `report_detail.csv` | 질의 단위 원장 1,128행 |
| `snapshot.yaml` | 이 실험에 쓰인 설정 스냅샷 (`rag replay` 입력) |

시나리오별 상세 평가 결과(`<scenario>_result.json`)는 5개 합계 94MB 라 저장소에 넣지
않았습니다. 아래 명령을 돌리면 같은 자리에 생성됩니다.

### 재현

```bash
rag ingest --env clean                                  # 1) 정상 인덱스
rag ingest --env poisoned -s R9                         # 2) R9 전용 오염 인덱스
rag run --all-scenarios --all-profiles --auto-report    # 3) 10셀 실행 + 리포트
```

결과는 `data/results/<run_id>/` 에 저장됩니다. 선행 조건(로컬 LLM 서버 준비)과 소요 시간은
저장소 루트 [`README.md`](../../README.md) 2.3 절을 참고하세요.

### 재현 시 유의

이 실험은 **2026-08-12 에 R2 공격자 매트릭스에서 A1(외부 관찰자)을 제거하기 전** 구성으로
돌렸습니다. 그래서 `R2/A1` 60건이 포함되어 있고, 현재 코드로 위 명령을 실행하면 R2 는
A2(내용 인지 관찰자) 단독으로 300건이 실행되어 셀 구성이 달라집니다. A1 을 제거한 근거
(A1 은 거절률만 높이고 유출은 NORMAL 보다도 적게 만들었습니다)는 이 실험의
R2 결과에 수치로 남아 있습니다.

## 데이터 성격

실험에 사용한 문서는 전량 합성 데이터입니다. 실제 개인정보는 포함되지 않았고, 주민등록번호
mod 11 · 카드번호 Luhn 검증을 통과하는 난수 값으로 생성해 탐지 난이도만 유지했습니다.
모든 응답·문서 본문은 저장 직전 `src/rag/pii/artifacts.py` 가 PII 를 마스킹합니다
(`report.mask_raw_pii: true`).
