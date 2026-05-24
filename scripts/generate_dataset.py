#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
RAG 대규모/고품질 기업형 데이터셋 생성 스크립트

역할:
  - c:\\subak_rag\\CAPSTONE\\data\\documents\\clean\\normal 하위에 1,000개의 일반 문서 생성
  - c:\\subak_rag\\CAPSTONE\\data\\documents\\clean\\sensitive 하위에 200개의 민감 문서 생성
  - 기존 27개 데이터셋 파일은 data/documents_backup/ clean 폴더에 자동 백업
  - Mod11(주민번호) 및 Luhn(카드번호) 유효 검증을 통과하는 정형 PII 생성기 탑재
  - KDPII 33종 표준 개인정보 범주가 자연체 업무 문서 안에 자연스럽게 배치됨
  - 인위적 마커(합성 안내문, 검색 앵커)를 완전히 제거해 리얼리티 확보
  - 방안 A(Slack/이메일/회의록/위키/보고서) 및 방안 B(모듈형 문장 조합 빌더)를 통한 데이터 구조 다변화
"""

from __future__ import annotations

import os
import random
import re
import shutil
from pathlib import Path

# =============================================================================
# 1. Checksum-Valid PII 및 가상 데이터 풀 정의 (audit_pii_miss_by_category.py 호환)
# =============================================================================

# GT_PATTERNS 매칭을 위한 고정 풀
FAMILY_MAP = {
    "김": "kim", "이": "lee", "박": "park", "최": "choi", "정": "jeong",
    "강": "gang", "조": "cho", "윤": "yoon", "장": "jang", "임": "lim",
    "한": "han", "오": "oh", "서": "seo", "신": "shin", "권": "kwon",
    "황": "hwang", "안": "ahn", "송": "song", "전": "jeon", "홍": "hong",
    "유": "yoo", "채": "chae", "추": "chu", "봉": "bong", "도": "do",
    "노": "no", "양": "yang", "구": "gu", "표": "pyo", "차": "cha",
    "백": "paik", "류": "ryu", "변": "byeon", "엄": "eom", "우": "woo"
}

FIRST_MAP = {
    "민준": "minjun", "서준": "seojun", "예준": "yejun", "도윤": "doyun", "시우": "siwoo",
    "주원": "juwon", "하준": "hajun", "지호": "jiho", "지후": "jihu", "준우": "junwoo",
    "준서": "junseo", "건우": "geonwoo", "우진": "woojin", "선우": "seonwoo", "서연": "seoyeon",
    "서현": "seohyeon", "민서": "minseo", "하은": "haeun", "지민": "jimin", "서윤": "seoyun",
    "지원": "jiwon", "채원": "chaewon", "윤서": "yoonseo", "지아": "jia", "다은": "daeun",
    "은서": "eunser", "채아": "chaea", "수아": "sua", "지유": "jiyu", "지윤": "jiyoon",
    "아윤": "ayun", "서하": "seoha", "하린": "harin", "아름": "areum", "연우": "yeonwoo",
    "하경": "hagyeong", "태성": "taeseong", "유진": "yujin", "세아": "seah", "시현": "sihyeon",
    "윤슬": "yoonseul", "승우": "seungwoo", "예린": "yerin", "세인": "sein", "해솔": "haesol",
    "도훈": "dohun", "다인": "dain", "지안": "jian", "여울": "yeoul"
}

PER_POOL = [f + g for f in FAMILY_MAP for g in FIRST_MAP]

ORG_POOL = ["한빛클라우드", "새벽솔루션", "누리데이터랩스", "가람정보보안", "한울시큐리티"]

DEPT_POOL = [
    "검색품질팀", "정보보호심사팀", "계약운영팀", "청구심사팀", "상담운영팀", "보안관제팀",
    "인증서비스팀", "데이터관리팀", "권한심사팀", "법무대응팀", "인사운영팀", "인프라운영그룹"
]

NICKNAME_POOL = ["별찌", "도지", "마루짱", "지호짱", "다온", "냥냥", "초코"]

EDUCATION_POOL = ["한빛대학교", "누리정보대학교", "가람과학기술대학교", "새벽디지털고등학교", "한울사이버대학원"]

POSITION_POOL = ["사원", "대리", "과장", "차장", "부장", "책임", "선임", "매니저", "팀장", "이사"]

MAJOR_POOL = ["정보보호학과", "컴퓨터공학과", "산업공학과", "경영학과", "전자공학과", "통계학과"]

ACCOUNT_POOL = [
    "110-456-789012",
    "1002-345-678901",
    "302-1234-5678-12",
    "123-04-567890-1",
    "333-08-765432-9"
]

def generate_korean_name() -> str:
    return random.choice(PER_POOL)

def generate_rrn(birth_date_str: str | None = None) -> str:
    if birth_date_str:
        # 생년월일 기준 파싱 시도
        match = re.search(r'(\d{4})', birth_date_str)
        if match:
            year = int(match.group(1))
        else:
            year = random.randint(1960, 2005)
        
        match_md = re.findall(r'\b\d{1,2}\b', birth_date_str)
        if len(match_md) >= 2:
            month = int(match_md[0])
            day = int(match_md[1])
        else:
            month = random.randint(1, 12)
            day = random.randint(1, 28)
    else:
        year = random.randint(1960, 2005)
        month = random.randint(1, 12)
        day = random.randint(1, 28)

    yy = f"{year % 100:02d}"
    mm = f"{month:02d}"
    dd = f"{day:02d}"
    
    gender_digit = "1" if year < 2000 else "3"
    if random.random() > 0.5:
        gender_digit = "2" if year < 2000 else "4"

    local_office = f"{random.randint(0, 99999):05d}"
    base = yy + mm + dd + gender_digit + local_office
    
    # Modulo 11 주민번호 체크섬 수식 적용
    multipliers = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    total = sum(int(base[i]) * multipliers[i] for i in range(12))
    remainder = total % 11
    check = (11 - remainder) % 10
    
    return f"{yy}{mm}{dd}-{gender_digit}{local_office}{check}"

def generate_arn() -> str:
    year = random.randint(1970, 2004)
    yy = f"{year % 100:02d}"
    mm = f"{random.randint(1, 12):02d}"
    dd = f"{random.randint(1, 28):02d}"
    gender_digit = random.choice(["5", "6"]) if year < 2000 else random.choice(["7", "8"])
    
    local_office = f"{random.randint(0, 99999):05d}"
    base = yy + mm + dd + gender_digit + local_office
    
    # Modulo 11 수식 적용
    multipliers = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5]
    total = sum(int(base[i]) * multipliers[i] for i in range(12))
    remainder = total % 11
    check = (13 - remainder) % 10
    return f"{yy}{mm}{dd}-{gender_digit}{local_office}{check}"

def generate_luhn_card() -> str:
    prefix = random.choice(["4", "51", "52", "53", "54", "55"])
    digits = [int(x) for x in prefix]
    while len(digits) < 15:
        digits.append(random.randint(0, 9))
        
    # Luhn 알고리즘 역순 가중치 연산
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 0:
            d_double = d * 2
            total += d_double if d_double < 10 else d_double - 9
        else:
            total += d
            
    check = (10 - (total % 10)) % 10
    digits.append(check)
    
    card_str = "".join(map(str, digits))
    return f"{card_str[:4]}-{card_str[4:8]}-{card_str[8:12]}-{card_str[12:]}"

def generate_bank_account() -> str:
    return random.choice(ACCOUNT_POOL)

def generate_mobile() -> str:
    # GT_PATTERNS "QT_MOBILE" 매칭 규격 준수: 010-9000-xxxx
    return f"010-9000-{random.randint(1000, 9999)}"

def generate_phone() -> str:
    area = random.choice(["02", "031", "032", "042", "051", "053"])
    return f"{area}-{random.randint(300, 899)}-{random.randint(1000, 9999)}"

def generate_email(name: str) -> str:
    # GT_PATTERNS "TMI_EMAIL" 매칭 규격 준수: 영문@example.test
    if len(name) >= 2:
        family = name[0]
        given = name[1:]
        eng_family = FAMILY_MAP.get(family, "user")
        eng_given = FIRST_MAP.get(given, "")
        if eng_given:
            eng_name = f"{eng_given}.{eng_family}"
        else:
            eng_name = "user"
    else:
        eng_name = "user"
        
    return f"{eng_name}{random.randint(10, 99)}@example.test"

def generate_ip() -> str:
    # GT_PATTERNS "QT_IP" 매칭 규격 준수 (RFC 5737 reserved ranges)
    prefix = random.choice(["192.0.2", "198.51.100", "203.0.113"])
    return f"{prefix}.{random.randint(1, 254)}"

def generate_car_number() -> str:
    # GT_PATTERNS "QT_PLATE_NUMBER" 매칭 규격 준수
    regions = ["서울", "부산", "대구", "인천", "광주", "대전", "울산", "세종", "경기", ""]
    region = random.choice(regions)
    korean_chars = ["가", "나", "다", "라", "마", "거", "너", "더", "러", "머", "버", "서", "어", "저", "허", "하", "호"]
    num = random.randint(10, 999)
    char = random.choice(korean_chars)
    suffix = random.randint(1000, 9999)
    return f"{region}{num}{char}{suffix}"

def generate_passport() -> str:
    # GT_PATTERNS "QT_PASSPORT_NUMBER" 규격 준수 ([MRS]\d{8})
    prefix = random.choice(["M", "R", "S"])
    return f"{prefix}{random.randint(10000000, 99999999)}"

def generate_driver_license() -> str:
    # GT_PATTERNS "QT_DRIVER_NUMBER" 규격 준수 (\b\d{2}-\d{2}-\d{6}-\d{2}\b)
    return f"{random.randint(11, 28):02d}-{random.randint(10, 99):02d}-{random.randint(100000, 999999)}-{random.randint(10, 99):02d}"

def generate_detailed_address() -> str:
    # GT_PATTERNS "LC_ADDRESS" 규격 준수
    provinces = ["서울특별시", "경기도", "부산광역시", "대전광역시", "인천광역시", "광주광역시"]
    prov = random.choice(provinces)
    if prov == "서울특별시":
        dist = random.choice(["강남구 테헤란로", "서초구 반포대로", "마포구 마포대로", "종로구 대학로"])
    elif prov == "경기도":
        dist = random.choice(["성남시 분당구 판교역로", "수원시 영통구 광교중앙로"])
    elif prov == "부산광역시":
        dist = random.choice(["해운대구 센텀중앙로", "수영구 광안해변로"])
    elif prov == "대전광역시":
        dist = random.choice(["유성구 대학로", "서구 둔산서로"])
    elif prov == "인천광역시":
        dist = random.choice(["연수구 송도국제대로", "남동구 예술로"])
    else:  # 광주광역시
        dist = random.choice(["서구 상무중앙로", "북구 설죽로"])
        
    return f"{prov} {dist} {random.randint(1, 500)}"

def generate_site() -> str:
    # GT_PATTERNS "TMI_SITE" 규격 준수
    sub = random.choice(["hr", "wiki", "gw", "mail", "dev", "security", "cloud", "infra", "auth", "finance"])
    return f"{sub}.example.test"

def generate_birth_date() -> str:
    # GT_PATTERNS "DT_BIRTH" 규격 준수
    year = random.randint(1965, 2002)
    month = random.randint(1, 12)
    day = random.randint(1, 28)
    fmt = random.choice([
        f"{year}년 {month}월 {day}일",
        f"{year}-{month:02d}-{day:02d}",
        f"{year}년생"
    ])
    return fmt

def generate_age() -> str:
    # GT_PATTERNS "QT_AGE" 규격 준수
    age = random.randint(22, 58)
    return random.choice([f"만 {age}세", f"{age}세"])

def generate_nickname() -> str:
    return random.choice(NICKNAME_POOL)

def generate_education() -> str:
    return random.choice(EDUCATION_POOL)

def generate_position() -> str:
    return random.choice(POSITION_POOL)

def generate_major() -> str:
    return random.choice(MAJOR_POOL)

def generate_blood_type() -> str:
    # GT_PATTERNS "TM_BLOOD_TYPE" 규격 준수: "혈액형: O" 또는 "혈액형: AB" 등
    bt = random.choice(["A", "B", "O", "AB"])
    return f"혈액형: {bt}"

def generate_dsprosens_code() -> str:
    return f"DSPROSENS{random.randint(1, 99):02d}"

def generate_synth_identifier(category: str) -> str:
    prefixes = {
        "CUST": "SYNTH-CUST",
        "CONTRACT": "SYNTH-CONTRACT",
        "EMPLOYEE": "SYNTH-EMPLOYEE",
        "KEY": "SYNTH-KEY",
        "GROUP": "SYNTH-GROUP",
        "QUEUE": "SYNTH-QUEUE",
        "PROJECT": "SYNTH-PROJ"
    }
    prefix = prefixes.get(category, "SYNTH-ID")
    return f"{prefix}-{random.choice(['A', 'B', 'C', 'X', 'Y', 'Z'])}{random.randint(100, 999)}"

# =============================================================================
# 2. 문서 유형별 물리적 포맷팅 가이드 (방안 A)
# =============================================================================

def format_report(title: str, blocks: list[str], security_class: str = "") -> str:
    """다변화 및 분량 확장된 공식 보고서 포맷"""
    style = random.choice(["style1", "style2", "style3"])
    dept = random.choice(DEPT_POOL)
    date = f"2026-{random.randint(1, 5):02d}-{random.randint(1, 28):02d}"
    num = f"HBC-{random.randint(10000, 99999)}"
    
    lines = []
    
    # 공통: Executive Summary (요약) 생성
    summary_sentences = [
        f"본 보고서는 최근 당사에서 추진 중인 {title} 사업과 관련하여, 부서 간 협업을 공고히 하고 리스크 요인을 사전에 제거하는 것을 목적으로 합니다.",
        f"최근 시장 환경 변화 및 전사 전략 방향에 맞추어 {title}의 핵심 지침과 규정을 준수하고, 안정적인 운영 체계를 확립하고자 본 안을 상정합니다.",
        f"본 문서는 {dept}의 관리하에 진행되는 {title}의 핵심 추진 과제를 정의하며, 실무 부서의 마일스톤 준수 및 정기 점검 사항을 포함하고 있습니다."
    ]
    exec_summary = random.choice(summary_sentences)
    
    if style == "style1":
        lines.append(f"제목: {title}")
        lines.append("-" * 60)
        lines.append(f"작성부서: {dept}   |   작성일자: {date}")
        lines.append(f"문서번호: {num}      |   보안구분: 일반/기밀 대외비")
        lines.append("-" * 60)
        lines.append("\n[요약문 (Executive Summary)]")
        lines.append(f"  {exec_summary}\n")
        lines.append("[상세 보고 내용]")
        for i, block in enumerate(blocks, 1):
            lines.append(f"  {i}. {block}")
        lines.append("\n[향후 추진 마일스톤]")
        lines.append(f"  - Phase 1 (도입기): 지침 배포 및 부서별 사전 준비 (~ {date})")
        lines.append("  - Phase 2 (안정기): 시스템 반영 및 실무 피드백 수렴 (도입 후 1개월)")
        lines.append("  - Phase 3 (고도화): 운영 효율성 평가 및 정기 정합성 감사 시행 (분기별)")
        
    elif style == "style2":
        lines.append(f"■ {title} 관련 통합 보고서")
        lines.append("")
        lines.append(f"1. 개요 및 배경")
        lines.append(f"   {exec_summary}")
        lines.append("")
        lines.append("2. 주요 이행 사항 및 과제")
        for i, block in enumerate(blocks, 1):
            lines.append(f"   [{i}단계] {block}")
        lines.append("")
        lines.append("3. 협조 요청 사항")
        lines.append(f"   - 관련 실무팀은 본 지침을 준수하여 기한 내에 그룹웨어 상신을 마쳐주시기 바랍니다.")
        lines.append(f"   - 기타 상세 인프라 접속 권한이나 계정 관련 사항은 {dept}으로 직접 문의 바랍니다.")
        lines.append("")
        lines.append(f"(본 문서의 소유권은 {dept}에 있으며, {date}에 최종 등록되었습니다. 문서 식별자: {num})")
        
    else:
        lines.append("==============================================================")
        lines.append(f"기술 및 전략 제안서: {title}")
        lines.append("==============================================================")
        lines.append(f"* 발행 부서: {dept}   |   * 등록 일자: {date}")
        lines.append(f"* 관리 번호: {num}")
        lines.append("")
        lines.append("■ Section I. 추진 배경")
        lines.append(f"  {exec_summary}")
        lines.append("")
        lines.append("■ Section II. 세부 가이드라인 및 구현 명세")
        for i, block in enumerate(blocks, 1):
            lines.append(f"  ▶ 핵심 사항 {i}: {block}")
        lines.append("")
        lines.append("■ Section III. 기대 효과 및 향후 계획")
        lines.append(f"  - 업무 효율 개선 및 규정 위반 리스크 최소화 가능.")
        lines.append(f"  - 차주 내 {dept} 주관 부서별 실무 워크숍 및 Q&A 세션 예정.")
            
    return "\n".join(lines)

def format_email(title: str, sender: str, receiver: str, blocks: list[str], date_str: str) -> str:
    """다변화 및 분량 확장된 3턴 왕복 이메일 스레드 포맷"""
    style = random.choice(["style1", "style2", "style3"])
    lines = []
    
    sender_name = sender.split(" <")[0]
    receiver_name = receiver.split(" <")[0]
    
    date_part = date_str.split(" ")[0]
    time_part = date_str.split(" ")[1]
    
    # 가상의 시간 변화 계산 (1일 전, 2시간 전)
    prev_date = f"2026-{random.randint(1, 5):02d}-{random.randint(1, 28):02d} 09:30"
    
    if style == "style1":
        # 표준 3턴 메일 스레드 (Top-Posting)
        lines.append(f"보낸 사람: {receiver}")
        lines.append(f"받는 사람: {sender}")
        lines.append(f"보낸 날짜: {date_str}")
        lines.append(f"제목: Re: {title}\n")
        lines.append(f"안녕하세요, {sender_name}님.\n\n바쁘신 와중에도 상세히 지침을 안내해 주셔서 대단히 감사합니다.\n전달해 주신 가이드라인과 상세 목록을 바탕으로 금주 내에 저희 팀원들과 내부 회의를 거친 뒤 조치를 시작하겠습니다.\n\n진행 중 추가 문의사항이 생기면 다시 연락드리겠습니다.\n\n감사합니다.\n{receiver_name} 드림\n")
        
        lines.append("-" * 15 + " Original Message " + "-" * 15)
        lines.append(f"보낸 사람: {sender}")
        lines.append(f"받는 사람: {receiver}")
        lines.append(f"보낸 날짜: {date_part} {int(time_part.split(':')[0])-2:02d}:{time_part.split(':')[1]}")
        lines.append(f"제목: Re: {title}\n")
        lines.append("\n\n".join(blocks))
        lines.append("\n")
        
        lines.append("-" * 15 + " Original Message " + "-" * 15)
        lines.append(f"보낸 사람: {receiver}")
        lines.append(f"받는 사람: {sender}")
        lines.append(f"보낸 날짜: {prev_date}")
        lines.append(f"제목: {title}\n")
        lines.append(f"안녕하세요, {sender_name}님.\n{random.choice(DEPT_POOL)}의 {receiver_name}입니다.\n\n이번에 진행하는 {title} 건과 관련하여 실무 부서에서 참조할 수 있는 상세 가이드라인과 규정 정보를 요청드립니다.\n현업에서 혼선이 없도록 가능한 구체적인 리스트와 프로세스를 전달해 주시면 감사하겠습니다.\n\n확인 부탁드립니다.\n감사합니다.\n{receiver_name} 올림")
        
    elif style == "style2":
        # 비즈니스 메모형 이메일 스레드
        lines.append("★ BUSINESS EMAIL MEMO (Threaded) ★")
        lines.append("=" * 60)
        lines.append(f"최종 발신자: {sender}")
        lines.append(f"최종 수신자: {receiver}")
        lines.append(f"최종 일시  : {date_str}")
        lines.append(f"메일 제목  : [회신] {title}")
        lines.append("=" * 60)
        lines.append(f"\n안녕하세요, {receiver_name}님.\n\n요청하신 {title} 관련 상세 자료 및 대응 가이드를 공유해 드립니다.\n본 정보에는 실무 지침과 규정이 포함되어 있으니 반드시 숙지해 주시기 바랍니다.\n")
        lines.append("\n\n".join(blocks[1:]))
        lines.append("\n\n" + "> " * 2 + "이전 업무 메일 로그")
        lines.append(f"> 발신: {receiver_name} | 수신: {sender_name}")
        lines.append(f"> 일시: {prev_date}")
        lines.append(f"> 내용: {sender_name}님, 금번 {title} 안건에 대해 준비 현황 및 가이드라인 확인 요청 건입니다. 조속한 공유 부탁드립니다.")
        
    else:
        # 답장(Threaded Reply Top-Posting) 스타일
        lines.append(f"제목: Re: {title}")
        lines.append(f"보낸이: {sender}")
        lines.append(f"날짜: {date_str}")
        lines.append("")
        lines.append(f"안녕하세요 {receiver_name}님,\n{random.choice(DEPT_POOL)} {sender_name}입니다.\n\n이전에 말씀 나누었던 {title} 세부 기준을 정리하여 전달해 드립니다.\n")
        lines.append("\n\n".join(blocks[1:]))
        lines.append("\n\n" + "> " * 2 + "--- Original Thread (Mailing List) ---")
        lines.append(f"> From: {receiver}")
        lines.append(f"> Date: {prev_date}")
        lines.append(f"> Subject: {title}")
        lines.append("> ")
        lines.append(f"> 안녕하십니까, {sender_name}님. 금주 내로 {title}에 대한 최종 가이드를 수신해야 다음 마일스톤 추진이 가능합니다.")
        lines.append(f"> 조속히 가이드를 준비하시어 회신 부탁드립니다. 감사합니다.")
        
    return "\n".join(lines)

def format_slack(channel: str, messages: list[tuple[str, str, str]]) -> str:
    """다변화 및 분량 확장된 10~12턴 슬랙 메신저 대화 포맷"""
    style = random.choice(["style1", "style2"])
    lines = []
    
    users = list(set([m[1] for m in messages]))
    if len(users) < 2:
        users = [generate_korean_name(), generate_korean_name()]
    
    extended_messages = []
    base_time = random.randint(9, 17)
    
    extended_messages.append((f"{base_time:02d}:01", users[0], f"좋은 아침입니다! 혹시 다들 자리 계신가요?"))
    extended_messages.append((f"{base_time:02d}:02", users[1], f"넵! 출근 완료했습니다. 무슨 일이신가요?"))
    extended_messages.append((f"{base_time:02d}:03", users[0], messages[0][2]))
    extended_messages.append((f"{base_time:02d}:05", users[1], messages[1][2]))
    extended_messages.append((f"{base_time:02d}:06", users[1], f"관련해서 공유 문서도 같이 슬랙에 올릴게요. 잠시만요! (이모지: 👍)"))
    
    if len(users) > 2:
        extended_messages.append((f"{base_time:02d}:07", users[2], f"아, 그 건은 제가 어제 인프라운영그룹이랑 협의했던 내용과도 닿아 있네요."))
        extended_messages.append((f"{base_time:02d}:08", users[0], messages[2][2]))
        extended_messages.append((f"{base_time:02d}:10", users[1], messages[3][2]))
        extended_messages.append((f"{base_time:02d}:11", users[2], messages[4][2]))
    else:
        extended_messages.append((f"{base_time:02d}:08", users[0], messages[2][2]))
        extended_messages.append((f"{base_time:02d}:10", users[1], messages[3][2]))
        extended_messages.append((f"{base_time:02d}:11", users[1], messages[4][2]))
        
    extended_messages.append((f"{base_time:02d}:13", users[0], messages[5][2]))
    extended_messages.append((f"{base_time:02d}:14", users[1], f"네, 문제 생기면 바로 이 스레드나 DM으로 호출해 주세요!"))
    extended_messages.append((f"{base_time:02d}:15", users[0], f"감사합니다. 다들 오늘 하루도 수고하십시오~"))
    
    if style == "style1":
        lines.append(f"[{channel} 채널 대화 기록]")
        lines.append(f"조회 기간: 2026-05-{random.randint(10, 20):02d}")
        lines.append("=" * 60)
        for time_str, user, msg in extended_messages:
            lines.append(f"[{time_str}] {user}: {msg}")
    else:
        lines.append(f"Slack # {channel.replace('#', '')} - 대화 히스토리 및 스레드")
        lines.append("-" * 60)
        for time_str, user, msg in extended_messages:
            lines.append(f"{user} ({time_str}): {msg}")
            
    return "\n".join(lines)

def format_wiki(title: str, author: str, blocks: list[str], version: str) -> str:
    """다변화 및 분량 확장된 사내 위키 포맷"""
    style = random.choice(["style1", "style2"])
    category = random.choice(['사내 가이드', '기술 문서', '업무 공유', '프로젝트 인덱스', '운영 정책', '보안 규정'])
    lines = []
    
    rev_history = [
        "| 개정 버전 | 개정 일자 | 개정자 | 개정 사유 및 요약 |",
        "| :--- | :--- | :--- | :--- |",
        f"| v1.0 | 2026-01-15 | {generate_korean_name()} | 최초 제정 및 초안 등록 |",
        f"| v{version} | 2026-05-10 | {author} | 최신 운영 규칙 및 상세 세부사항 현행화 |"
    ]
    
    related_docs = [
        "\n### ■ 관련 문서 바로가기 링크",
        f"- [사내 인프라 표준 운영 규정](wiki.example.test/infra-policy)",
        f"- [보안 가이드라인 및 취약점 조치 프로세스](wiki.example.test/security-guide)",
        f"- [업무 협업용 서식 자료실](wiki.example.test/templates)"
    ]
    
    if style == "style1":
        lines.append(f"# {title}")
        lines.append(f"* 최근 수정: {author} (v{version})")
        lines.append(f"* 카테고리: {category}")
        lines.append("\n" + "=" * 50)
        lines.append("## 문서 개정이력 (Revision History)")
        lines.extend(rev_history)
        lines.append("\n" + "=" * 50 + "\n")
        
        for block in blocks:
            lines.append(block)
            
        lines.extend(related_docs)
        lines.append("\n---\n*본 문서는 사내 지식 관리 시스템(Wiki)에서 공식 생성된 콘텐츠입니다. 무단 반출을 금합니다.*")
    else:
        lines.append(f"■ 사내 지식베이스 > {category} ■")
        lines.append(f"문서명: {title} (최종 편집자: {author} / 개정 버전: v{version})")
        lines.append("=" * 60)
        lines.append("### 문서 이력 관리")
        lines.extend(rev_history)
        lines.append("=" * 60)
        lines.append("")
        
        for block in blocks:
            lines.append(block)
            
        lines.extend(related_docs)
        lines.append("\n* 주의: 본 위키 문서는 내부 임직원 전용 정보입니다. 외부 반출 및 오남용 시 제재를 받을 수 있습니다.")
        
    return "\n\n".join(lines)

def format_meeting_minutes(title: str, facilitator: str, attendees: list[str], blocks: list[str]) -> str:
    """다변화 및 분량 확장된 회의록 포맷"""
    style = random.choice(["style1", "style2"])
    date = f"2026-{random.randint(1, 5):02d}-{random.randint(1, 28):02d}"
    
    lines = []
    
    discussion_lines = [
        "## 회의 주요 진행 사항 및 참석자 발언 요약",
        f"- **{facilitator} (회의 주재)**: 오늘 미팅은 {title}에 대한 현황과 실무 부서의 마일스톤 준수 여부를 종합 검토하기 위해 개최되었습니다.",
        f"- **{attendees[1]}**: {blocks[0]} 부분과 관련하여 실무 적용 상의 예외 사례 처리가 먼저 정의되어야 현업의 불필요한 혼선을 막을 수 있습니다.",
        f"- **{attendees[2]}**: 동감합니다. 특히 {blocks[1]}의 도입 시점에 맞춰 인프라 접속 권한이나 계정 동기화 등이 차질 없이 완료되어야 합니다."
    ]
    
    if style == "style1":
        lines.append(f"회의록: {title}")
        lines.append("=" * 50)
        lines.append(f"일시: {date} (14:00 - 15:30)")
        lines.append(f"주재자: {facilitator}")
        lines.append(f"참석자: {', '.join(attendees)}")
        lines.append("-" * 50)
        lines.append("## 회의 안건 및 결의 내용\n")
        for block in blocks:
            lines.append(block)
        lines.append("")
        lines.extend(discussion_lines)
    else:
        lines.append(f"[회의 요약] {title}")
        lines.append(f"* 일시: {date}  |  * 작성자: {facilitator}")
        lines.append(f"* 참석 부서원: {', '.join(attendees)}")
        lines.append("-" * 50)
        lines.append("## 주요 안건 및 회의록 상세")
        for block in blocks:
            lines.append(block)
        lines.append("")
        lines.extend(discussion_lines)
            
    # Action Items
    lines.append("\n## Action Items (조치 사항 및 일정)")
    action_items_templates = [
        "회의 결의 사항 관련 상세 위키 가이드 작성 및 사내 공유",
        "보안 규정 및 관련 계약 사항 조치 여부 법무대응팀 재검토 요청",
        "부서별 예산 조정안 반영 후 최종 지출 결재 승인 품의서 작성",
        "신규 정책 및 가이드라인 공유를 위한 파트별 공지 및 배포 진행",
        "관련 도구 및 인프라 접근 권한 회수 및 비상 계정 정리 검토",
        "진행 사항 공유 및 추가 피드백 수렴을 위한 부서 미팅 예약",
        "차주 주간 보고 회의 전까지 세부 실행 지침 보완 및 보고",
        "거래처/협력사 협의 사항 통보 및 미팅 피드백 공유"
    ]
    num_items = random.randint(1, 3)
    selected_tasks = random.sample(action_items_templates, num_items)
    for task in selected_tasks:
        assignee = random.choice(attendees)
        lines.append(f"- [ ] [담당: {assignee} / 기한: {date}] {task}")
        
    return "\n".join(lines)

def format_commit_log(topic_name: str, blocks: list[str]) -> str:
    """Git 커밋 로그 포맷 (Git Diff 주입으로 분량 및 디테일 극대화)"""
    commit_hash = f"{random.randint(1000000, 9999999):x}"
    author = generate_korean_name()
    email = generate_email(author)
    date = f"2026-05-{random.randint(1, 28):02d} {random.randint(9, 18):02d}:{random.randint(10, 59):02d}:02"
    
    # Git Diff 시뮬레이션 코드
    diff_lines = [
        f"diff --git a/src/services/dev_task.py b/src/services/dev_task.py",
        f"index 4a3e210..9f8c12a 100644",
        f"--- a/src/services/dev_task.py",
        f"+++ b/src/services/dev_task.py",
        f"@@ -42,12 +42,26 @@ def process_{commit_hash[:4]}():",
        f"-    # TODO: {topic_name} 임시 프로토타입 상태",
        f"+    # {topic_name}에 대한 최종 보완 구현체 적용 완료",
        f"+    log.info(\"Initializing modules for: {topic_name}\")",
        f"+    status = initialize_configs()",
        f"+    if not status:",
        f"+        raise ConfigurationError(\"Failed loading data for {topic_name}\")",
        f"+",
        f"+    # 2단계 검증 루틴 및 PII 안전 마스킹 필터 탑재",
        f"+    mask_filter = MaskingFilter(policy='strict')",
        f"+    payload = {{",
        f"+        'task_name': '{topic_name}',",
        f"+        'author': '{author}',",
        f"+        'timestamp': '{date}'",
        f"+    }}",
        f"+    return mask_filter.execute(payload)"
    ]
    
    lines = [
        f"commit {commit_hash}{commit_hash}",
        f"Author: {author} <{email}>",
        f"Date:   {date}",
        "",
        f"    [DevTask] {topic_name} 관련 작업 내역 적용",
        "",
        "    상세 수행 내역:",
        f"    - {blocks[0]}",
        f"    - {blocks[1]}",
        f"    - {blocks[2]}",
        f"    - {blocks[3]}",
        "",
        "--------------------------------------------------",
        "Git Diff (Source Code Changes):",
        "--------------------------------------------------",
    ]
    lines.extend(diff_lines)
    return "\n".join(lines)

def format_dev_log(topic_name: str, blocks: list[str]) -> str:
    """개발 작업 일지 포맷 (실행 명령어 로그 및 응답 본문 추가)"""
    author = generate_korean_name()
    date = f"2026-05-{random.randint(1, 28):02d}"
    
    cmd_trace = [
        f"$ npm run test:unit --filter={topic_name.replace(' ', '_')}",
        "",
        f"> test:unit:hbc-platform",
        f"> jest --config jest.config.js \"--filter={topic_name}\"",
        "",
        f"PASS  tests/unit/components/test_{random.randint(100, 999)}.spec.ts",
        f"  ✓ Initializing {topic_name} test cases (82 ms)",
        f"  ✓ Injecting schema values and validating PII mapping (140 ms)",
        f"  ✓ Simulating connection metrics under load (45 ms)",
        "",
        "Test Suites: 1 passed, 1 total",
        "Tests:       3 passed, 3 total",
        "Snapshots:   0 total",
        "Time:        1.84s",
        "Ran all test suites matching Jest filters."
    ]
    
    lines = [
        f"[개발 일지] {topic_name} - {date}",
        f"작성자: {author} (연구원)",
        "-" * 60,
        f"1. 오늘 진행한 업무",
        f"   - {blocks[0]}",
        f"   - {blocks[1]}",
        f"2. 문제점 및 해결 방안",
        f"   - {blocks[2]}",
        f"3. 내일 예정 업무",
        f"   - {blocks[3]}",
        "-" * 60,
        "■ 개발 환경 터미널 명령어 실행 트레이스 (Debug Console):",
    ]
    lines.extend(cmd_trace)
    lines.append("-" * 60)
    return "\n".join(lines)

def format_asset_list(topic_name: str, blocks: list[str]) -> str:
    """IT 자산 장비 실사대장 포맷 (행 수 확장 및 실질 장비 정보 추가)"""
    manager = generate_korean_name()
    date = f"2026-05-{random.randint(1, 28):02d}"
    
    lines = [
        f"[자산 실사대장] {topic_name}",
        f"실사 일자: {date} | 실사 담당자: {manager}",
        "==========================================================================",
        "자산 번호     | 자산 구분     | 관리 상태 | 실사 상세 내역 및 배정 임직원",
        "--------------------------------------------------------------------------",
        f"EQ-2026-001   | 개요         | 정상     | {blocks[0]}",
        f"EQ-2026-002   | 현황         | 검토 요망 | {blocks[1]}",
        f"EQ-2026-003   | 조치         | 완료     | {blocks[2]}",
        f"EQ-2026-004   | 비고         | -        | {blocks[3]}",
        f"EQ-2026-005   | 노트북 단말   | 정상     | 개발팀 {generate_korean_name()} 연구원 (MacBook Pro 16')",
        f"EQ-2026-006   | 테스트 서버   | 정상     | 인프라팀 {generate_korean_name()} 책임 (Ubuntu Enterprise 22.04 LTS)",
        f"EQ-2026-007   | 듀얼 모니터   | 정상     | 마케팅팀 {generate_korean_name()} 대리 (Dell UltraSharp 27')",
        f"EQ-2026-008   | 부서용 프린터 | 점검 필요 | 3층 서편 복합기 (드럼 교체 및 네트워크 오프라인 재설정)",
        "=========================================================================="
    ]
    return "\n".join(lines)

def format_status_check(topic_name: str, blocks: list[str]) -> str:
    """시스템 모니터링 체크 보고서 포맷 (메트릭 수치 및 이벤트 로그 추가)"""
    system_id = f"SYS-{random.randint(100, 999)}"
    time_str = f"2026-05-{random.randint(1, 28):02d} {random.randint(0, 23):02d}:00:00"
    
    metrics = [
        f"[SYSTEM PERFORMANCE METRICS]",
        f"  - CPU Utilization: {random.randint(12, 45)}% (Average)",
        f"  - Memory Usage: {random.randint(40, 75)}% (48.2 GB of 64 GB allocated)",
        f"  - Disk I/O: Read {random.randint(10, 80)}MB/s, Write {random.randint(5, 40)}MB/s",
        f"  - Network Bandwidth: Inbound {random.randint(50, 200)}Mbps | Outbound {random.randint(10, 100)}Mbps",
        f"  - DB Latency: {random.randint(2, 18)}ms | Active Connections: {random.randint(150, 480)}/1000"
    ]
    
    event_logs = [
        f"[RECENT EVENT LOGS]",
        f"  - [INFO] {time_str[:-6]}:12:04 Connection pool initialized.",
        f"  - [INFO] {time_str[:-6]}:15:45 Scheduled backup job completed successfully.",
        f"  - [WARN] {time_str[:-6]}:32:19 DNS lookup latency spike (exceeded 250ms), auto-resolved.",
        f"  - [INFO] {time_str[:-6]}:59:58 Health checks passed. Status code: 200 OK."
    ]
    
    lines = [
        f"[STATUS REPORT] {topic_name} (ID: {system_id})",
        f"Check Time: {time_str} | Status: Healthy",
        "--------------------------------------------------",
        f"[1] System Metrics & Background:",
        f"    {blocks[0]}",
    ]
    lines.extend(metrics)
    lines.append("")
    lines.append(f"[2] Latency and DB Checks:")
    lines.append(f"    {blocks[1]}")
    lines.append("")
    lines.append(f"[3] Configuration & Security state:")
    lines.append(f"    {blocks[2]}")
    lines.append("")
    lines.append(f"[4] Event Log / Next action items:")
    lines.append(f"    {blocks[3]}")
    lines.extend(event_logs)
    lines.append("--------------------------------------------------")
    return "\n".join(lines)

def format_qa_board(topic_name: str, blocks: list[str]) -> str:
    """사내 QA 게시판 포맷 (댓글 스레드 토론 추가)"""
    author = generate_korean_name()
    views = random.randint(15, 120)
    user2 = generate_korean_name()
    user3 = generate_korean_name()
    
    lines = [
        f"[사내 QA 게시판] {topic_name} 질문드립니다.",
        f"작성자: {author} | 조회수: {views} | 등록일: 2026-05-12",
        "-" * 50,
        f"Q: {blocks[0]}",
        f"   {blocks[1]}",
        "",
        f"Re: 답변드립니다. (답변자: {generate_korean_name()})",
        f"A: {blocks[2]}",
        f"   {blocks[3]}",
        "",
        "==================================================",
        "댓글 (Comments Thread)",
        "==================================================",
        f"ㄴ {user2} (2026-05-13 10:24):",
        f"   상세히 답변 주셔서 감사합니다. 알려주신 {topic_name} 조치법대로 하니 한결 수월해졌습니다! 혹시 이 가이드는 외부망에서도 접속 가능할까요?",
        f"ㄴ {user3} (2026-05-13 11:05):",
        f"   @{user2}님, 사외 접속은 VPN 권한이 신청되어 있어야 하며, OTP 승인을 거쳐야 정상 접속되는 것으로 알고 있습니다.",
        f"ㄴ {author} (작성자) (2026-05-13 13:40):",
        f"   모두 친절하게 정보 덧붙여 주셔서 감사합니다. 많은 도움이 되었습니다.",
        "-" * 60
    ]
    return "\n".join(lines)

def format_voc_ticket(topic_name: str, blocks: list[str]) -> str:
    """고객 지원 VOC 상담 티켓 포맷 (상담 녹취록 및 라이브 채팅 추가)"""
    ticket_id = f"VOC-{random.randint(100000, 999999)}"
    agent = generate_korean_name()
    cust_name = generate_korean_name()
    
    dialog = [
        "--------------------------------------------------",
        "상담 실시간 채팅 대본 및 녹취록 (Customer-Agent Dialog):",
        "--------------------------------------------------",
        f"[상담원 {agent}]: 안녕하십니까, 고객 지원 센터 {agent}입니다. 무엇을 도와드릴까요?",
        f"[고객 {cust_name}]: 안녕하세요. 제가 지금 {topic_name} 신청 프로세스를 밟고 있는데, 몇 가지 막히는 부분이 있습니다.",
        f"[상담원 {agent}]: 네, 많이 불편하셨겠습니다. 본인 확인 후 곧바로 처리 절차와 세부 옵션을 설명해 드리겠습니다.",
        f"[고객 {cust_name}]: 감사합니다. 개인정보 수집 및 이용 동의도 완료했으니 계정 상태를 한번 확인해 주세요.",
        f"[상담원 {agent}]: 확인 결과, 고객님께서는 {blocks[2]}에 기재된 대로 조치해 주시면 즉각 서비스 권한을 획득하실 수 있습니다.",
        f"[고객 {cust_name}]: 아, 그렇군요! 이해했습니다. 정말 친절하게 설명해 주셔서 감사해요.",
        f"[상담원 {agent}]: 네, 추가적인 문의사항이 있으시면 언제든지 고객 센터로 연락 부탁드립니다. 행복한 하루 보내십시오."
    ]
    
    lines = [
        f"[고객 지원 티켓] {topic_name} (ID: {ticket_id})",
        f"처리 상담원: {agent} | 상태: 처리 완료",
        "==================================================",
        "[고객 인적사항 및 인트로]",
        f"- {blocks[0]}",
        "[접수된 상세 내용]",
        f"- {blocks[1]}",
        "[개인정보 확인 및 조치 사항]",
        f"- {blocks[2]}",
        "[최종 상담원 요약]",
        f"- {blocks[3]}",
        "=================================================="
    ]
    lines.extend(dialog)
    lines.append("==================================================")
    return "\n".join(lines)


def format_contract(topic_name: str, blocks: list[str]) -> str:
    """표준 협약서 및 약정 계약서 포맷 (손해배상 및 갑/을 서명 주소 블록 추가)"""
    contract_id = f"CNTR-{random.randint(202600, 202699)}"
    comp_a = "주식회사 한빛클라우드 (이하 '갑')"
    comp_b = f"주식회사 {random.choice(['새벽솔루션', '누리데이터랩스', '가람정보보안', '한울시큐리티'])} (이하 '을')"
    
    lines = [
        '■ 표준 합의서 및 계약 조항 ■',
        f'계약명: {topic_name} (계약 번호: {contract_id})',
        f'본 계약은 {comp_a}와 {comp_b} 간에 상호 신뢰를 바탕으로 {topic_name} 업무를 성실히 이행하기 위해 체결한다.',
        '--------------------------------------------------',
        '제1조 (목적 및 서문)',
        f'  {blocks[0]}',
        '제2조 (계약의 효력 및 약정 내용)',
        f'  {blocks[1]}',
        '제3조 (기밀 정보 및 보장 범위)',
        f'  {blocks[2]}',
        '제4조 (기타 유의사항)',
        f'  {blocks[3]}',
        '제5조 (손해배상 및 기밀 준수 의무)',
        "  1. '갑'과 '을'은 본 계약과 관련하여 취득한 상대방의 모든 기밀 및 개인정보(PII)를 외부로 유출하여서는 아니 된다.",
        '  2. 일방의 귀책사유로 인해 정보 유출 및 손해가 발생할 경우, 귀책 당사자는 상대방이 입은 일체의 손실에 대하여 민형사상 손해배상 책임을 진다.',
        '제6조 (관할 법원)',
        '  본 계약서의 해석상 이견이 있거나 분쟁이 발생할 경우, 상호 협의하에 해결하되 협의가 불가능할 시 서울중앙지방법원을 합의 관할 법원으로 한다.',
        '--------------------------------------------------',
        '본 합의 사항은 쌍방 간의 신뢰 하에 성실히 이행될 것이며, 이를 증명하기 위해 날인한다.',
        '',
        f'[갑]: {comp_a}',
        '  - 주소: 서울특별시 중구 세종대로 110',
        f'  - 대표이사: {generate_korean_name()} (인)',
        '',
        f'[을]: {comp_b}',
        '  - 주소: 경기도 성남시 분당구 판교역로 231',
        f'  - 대표이사: {generate_korean_name()} (인)'
    ]
    return '\n'.join(lines)


def format_audit_log(topic_name: str, blocks: list[str]) -> str:
    """보안 감사 감사 로그 포맷 (원시 JSON 페이로드 및 스택 트레이스 추가)"""
    log_id = f"AUD-{random.randint(100000, 999999)}"
    time_str = f"2026-05-{random.randint(1, 28):02d} {random.randint(0, 23):02d}:{random.randint(10, 59):02d}:03"
    
    raw_json = [
        '--------------------------------------------------',
        'RAW AUDIT EVENT PAYLOAD (JSON Format):',
        '--------------------------------------------------',
        '{',
        f'  "event_id": "{log_id}",',
        f'  "event_timestamp": "{time_str}",',
        '  "severity": "HIGH",',
        '  "trigger_rule": "PII_LEAK_PREVENTION",',
        f'  "category": "{topic_name}",',
        '  "connection_info": {',
        f'    "remote_ip": "198.51.100.{random.randint(10, 250)}",',
        '    "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HttpClient/4.5.13"',
        '  },',
        '  "target_blocks": [',
        f'    "{blocks[0][:40]}...",',
        f'    "{blocks[1][:40]}..."',
        '  ],',
        '  "action_taken": "BLOCK_AND_ALERT_ADMIN"',
        '}'
    ]
    
    stack_trace = [
        '--------------------------------------------------',
        'SYSTEM TRACE EXCEPTION (If applicable):',
        '--------------------------------------------------',
        'org.hbc.security.interceptors.PIIExposureException: Exposed sensitive data on endpoint',
        '    at org.hbc.security.filters.AuditFilter.doFilter(AuditFilter.java:184)',
        '    at org.apache.catalina.core.ApplicationFilterChain.internalDoFilter(ApplicationFilterChain.java:193)',
        '    at org.apache.catalina.core.ApplicationFilterChain.doFilter(ApplicationFilterChain.java:166)',
        '    at org.springframework.web.filter.RequestContextFilter.doFilterInternal(RequestContextFilter.java:100)'
    ]
    
    lines = [
        f'[AUDIT LOG ENTRY] {topic_name} (ID: {log_id})',
        f'Event Timestamp: {time_str} | Severity: High',
        '==================================================',
        '[System Trigger & Context]',
        f'  {blocks[0]}',
        '[Detailed Audit Payload]',
        f'  {blocks[1]}',
        '[Identified PII/Secret Elements]',
        f'  {blocks[2]}',
        '[Security Action Taken]',
        f'  {blocks[3]}',
        '=================================================='
    ]
    lines.extend(raw_json)
    lines.extend(stack_trace)
    lines.append('==================================================')
    return '\n'.join(lines)


def format_invoice(topic_name: str, blocks: list[str]) -> str:
    """지출 결재 청구서 포맷 (상세 품목 견적서 추가)"""
    invoice_num = f"INV-{random.randint(1000000, 9999999)}"
    manager = generate_korean_name()
    price_unit = random.choice([150000, 280000, 1200000])
    qty = random.randint(1, 10)
    subtotal = price_unit * qty
    tax = int(subtotal * 0.1)
    total = subtotal + tax
    
    lines = [
        f'[지출 결재 청구서] {topic_name}',
        f'청구 일련번호: {invoice_num} | 담당자: {manager}',
        '--------------------------------------------------',
        '1. 청구 개요 및 사업명',
        f'   {blocks[0]}',
        '2. 상세 지출 사유 및 내용',
        f'   {blocks[1]}',
        '3. 결제 수단 및 계좌 정보',
        f'   {blocks[2]}',
        '4. 정산 관련 유의사항',
        f'   {blocks[3]}',
        '--------------------------------------------------',
        '지출 세부 청구 내역 (Itemized Costs Table):',
        '--------------------------------------------------------------------------',
        '품목명 / 항목 설명               | 수량  | 단가 (원)      | 공급가액 (원)',
        '--------------------------------------------------------------------------',
        f'{topic_name[:20]:<25} | {qty:<5} | {price_unit:<13,} | {subtotal:<14,}',
        '가상 기술 유지 보수 기술 지원비 | 1     | 0              | 0',
        '--------------------------------------------------------------------------',
        f'합계 금액: {subtotal:,} 원  |  부가세 (10%): {tax:,} 원  |  최종 청구 총액: {total:,} 원',
        '--------------------------------------------------------------------------',
        '* 결재권자 최종 승인 대기 중'
    ]
    return '\n'.join(lines)


def format_resume_hr(topic_name: str, blocks: list[str]) -> str:
    """인사 카드 및 면접 대장 포맷 (직장 경력 및 다면 평가 점수 추가)"""
    resume_id = f"HR-{random.randint(1000, 9999)}"
    interviewer = generate_korean_name()
    prev_comp = random.choice(['라인에이치', '대아네트웍스', '이룸에듀테크', '코어데이터웍스'])
    
    scores = [
        '--------------------------------------------------',
        '다면 면접 평가 점수표 (Interview Evaluations):',
        '--------------------------------------------------',
        '  - 전공 실무 능력 (Technical Skill): 85 / 100',
        '  - 조직 적응력 및 태도 (Cultural Fit): 90 / 100',
        '  - 의사소통 및 협업 역량 (Communication): 92 / 100',
        '  - 인프라 지식 이해도 (Infrastructure Knowledge): 88 / 100',
        f'  - [최종 종합 판정]: 채용 권장 (Interviewer: {interviewer})'
    ]
    
    lines = [
        f'[인사 카드 및 채용 면접 대장] {topic_name} (ID: {resume_id})',
        f'작성자: {interviewer} (인사담당)',
        '==================================================',
        '[지원자 인적사항 및 지원 배경]',
        f'  {blocks[0]}',
        '[학력 및 기술 이력 상세]',
        f'  {blocks[1]}',
        '[제출 서류 및 자격 유효성 검증]',
        f'  {blocks[2]}',
        '[평가 코멘트 및 유의사항]',
        f'  {blocks[3]}',
        '--------------------------------------------------',
        '이전 직장 경력 내역 (Career History):',
        '--------------------------------------------------',
        f'  - 직장명: (주){prev_comp} 연구개발부',
        '  - 근무 기간: 2022-03 ~ 2025-12 (3년 9개월)',
        '  - 최종 직급: 대리 / 주무연구원',
        f'  - 주요 수행 프로젝트: {topic_name} 관련 마이그레이션 및 REST API 모듈 재설계'
    ]
    lines.extend(scores)
    lines.append('==================================================')
    return '\n'.join(lines)


NORMAL_TOPICS = [{'topic_name': '사내 복지 지원 제도',
  'intros': ['임직원 여러분의 복지 향상을 위해 {year}년도 사내 {welfare} 지원 제도를 다음과 같이 공지합니다.',
             '복리후생 지침에 따라 {year}년도 {welfare} 신청 요강을 안내해 드립니다.'],
  'bodies': ['본 지침은 {dept}의 협의를 거쳐 확정되었으며, 근속 기간 1년 이상인 {org} 임직원에게 적용됩니다.',
             '이번 제도는 전사 임직원의 근무 여건 개선 및 복리후생 증진을 위해 {org} 경영진의 승인을 받았습니다.'],
  'details': ['지원 신청은 매월 {date}까지 사내 위키 포털({site})의 복지지원 탭을 통해 상시 접수합니다.',
              '관련 영수증 전표와 신청서를 작성하여 {dept} 담당자 이메일({email})로 보내주시기 바랍니다.'],
  'conclusions': ['기타 의문사항은 {dept}(내선번호 {phone})로 문의해 주시기 바랍니다.', '규정을 준수하여 기한 내에 사내 시스템({site})으로 기안 승인을 완료해 주세요.'],
  'allowed_formats': ['REPORT', 'EMAIL', 'SLACK', 'WIKI', 'MINUTES']},
 {'topic_name': '원격근무 VPN 접속 매뉴얼',
  'intros': ['재택근무 및 사외 외근 시 사내 망 접속을 위한 {vpn_client} VPN 설치 매뉴얼을 배포합니다.', '{dept}에서 제공하는 원격 업무 네트워크 접속 가이드라인입니다.'],
  'bodies': ['사외에서 사내 시스템({site})에 접근하려면 반드시 {vpn_client} 보안 에이전트 설치가 필요합니다.',
             '본 가이드는 사내 보안을 위해 {org}의 보안 규정을 따르며 임의의 VPN 우회 시도는 제재 대상이 됩니다.'],
  'details': ['접속 서버 주소는 {vpn_server} 이며, OTP 2차 인증을 필수로 완료해야 로그인됩니다.',
              '장애 발생 시 본인 단말의 외부 IP({ip})를 캡처하여 {dept} 담당자({email})에게 지원을 요청하세요.'],
  'conclusions': ['비밀번호 유출 방지를 위해 타인에게 계정을 공유하지 않도록 각별히 유의바랍니다.',
                  '설치 링크 및 추가 FAQ는 {org} 인프라 위키 페이지({site})를 참조하시기 바랍니다.'],
  'allowed_formats': ['REPORT', 'EMAIL', 'WIKI']},
 {'topic_name': '연차 소진 촉진 및 휴가 제도',
  'intros': ['근로기준법에 따라 전 임직원 대상 {year}년도 연차 유급 휴가 소진 촉진 제도를 안내합니다.', '인사총무 관련 경조사 및 {holiday} 지원 기준에 관한 공지사항입니다.'],
  'bodies': ['각 부서장께서는 소속 부서원들의 연차 계획을 확인하시고, {holiday} 사용을 적극 독려해 주시기 바랍니다.',
             '본 규정은 {org} 임직원의 건강한 근로 조건 보장을 목표로 시행됩니다.'],
  'details': ['휴가 기안은 그룹웨어({site})의 연차 신청 메뉴를 사용하고, 증빙은 {date}까지 {dept}에 제출해야 합니다.',
              '휴가 기간 동안 급박한 연락처는 개인 휴대전화({mobile}) 또는 비상 연락망으로 연락바랍니다.'],
  'conclusions': ['휴가 전 인수인계를 확실히 하여 업무 공백이 발생하지 않도록 협조 부탁드립니다.', '관련 문의는 {dept} 담당자({email})에게 연락 바랍니다.'],
  'allowed_formats': ['REPORT', 'EMAIL', 'WIKI', 'MINUTES']},
 {'topic_name': '회의실 예약 및 비품 관리',
  'intros': ['사내 공유 협업 환경 개선을 위한 공용 회의실 예약 및 비품 예약 관리 지침입니다.', '회의실 무단 점유 방지 및 자산 보존을 위한 운영 규칙입니다.'],
  'bodies': ['회의실 예약은 그룹웨어({site}) 예약 현황판에서 신청할 수 있으며, 사용 후 정리 정돈은 필수입니다.',
             '소모품 및 비품은 {dept}의 관리 대장을 통해 승인을 얻어야 반출이 가능합니다.'],
  'details': ['회의실 내 빔프로젝터 오작동 등 설비 이상은 내선 번호 {phone}로 보안관제에 즉각 접수바랍니다.',
              '사용 일시는 {date} 기준으로 예약 가능하며, 대형 회의실의 경우 부서장의 사전 승인이 필수입니다.'],
  'conclusions': ['공동 자산이므로 깨끗이 사용해 주시고 분실 시 즉각 신고해 주십시오.', '비품 신청 서식 다운로드는 {org} 위키 시스템({site}) 내 서식 자료실에서 가능합니다.'],
  'allowed_formats': ['EMAIL', 'SLACK', 'WIKI', 'MINUTES']},
 {'topic_name': '사내 Wi-Fi 연결 가이드',
  'intros': ['본사 오피스 건물 내 무선 네트워크(Wi-Fi) 연결 설정 및 단말 등록 방법입니다.', '안전한 사내 무선인터넷 환경을 구축하기 위한 필수 보안 연결 설정 가이드입니다.'],
  'bodies': ["무선 SSID는 'HBC-Secure-WiFi'를 선택하고, 사내 SSO 포털({site}) 인증 정보로 로그인해야 합니다.",
             '미등록 사설 AP 또는 무단 테더링 공유기 사용은 보안 규정상 금지됩니다.'],
  'details': ['연결 시 할당되는 IP 대역은 사내용 IP({ip}) 대역이며, 방화벽 규칙이 타이트하게 적용됩니다.',
              '기술 지원이나 계정 잠김 등의 문제는 {dept}({email})로 문의하시기 바랍니다.'],
  'conclusions': ['노트북 및 모바일 단말의 백신 상태를 항상 최신으로 유지하시기 바랍니다.', '무선 인터넷 상세 접속 오류 현상은 {site} 네트워크 가이드에서 해결책을 확인하세요.'],
  'allowed_formats': ['REPORT', 'EMAIL', 'WIKI']},
 {'topic_name': '프린터 복합기 사용법',
  'intros': ['각 층에 도입된 신규 고속 컬러 복합기 드라이버 설치 및 사용법 매뉴얼입니다.', '임직원들의 인쇄, 스캔, 팩스 사용 편의를 돕기 위한 복합기 설정 가이드입니다.'],
  'bodies': ['드라이버 패키지는 인프라 자료실({site})에서 다운로드 가능하며, 복합기 IP와 포트를 일치시켜야 합니다.',
             '인쇄 시 개인 사원증 접촉 태깅을 통하거나 사번 입력을 통해 최종 인쇄가 수행됩니다.'],
  'details': ['인쇄 오류가 지속될 경우 인쇄 큐를 초기화하고 네트워크 프린터 서버 IP({ip})를 재확인하세요.',
              '토너 부족 및 종이 걸림 장애는 내선 {phone} 또는 메일({email})로 {dept} 행정 담당자에게 알리시기 바랍니다.'],
  'conclusions': ['종이 절약 및 친환경 업무 환경을 위해 가급적 양면 인쇄와 전자 문서 활용을 부탁드립니다.',
                  '부서별 월간 인쇄 통계는 {org} 인사운영팀에서 자동 집계되어 연말 보고서에 반영됩니다.'],
  'allowed_formats': ['REPORT', 'EMAIL', 'WIKI']},
 {'topic_name': '신규 입사자 온보딩 가이드',
  'intros': ['새롭게 합류하신 {org} 신규 입사자분들을 위한 사내 온보딩 지침과 안내 사항입니다.', '입사 첫 주 원활한 업무 적응을 돕기 위해 {dept}에서 작성한 가이드라인입니다.'],
  'bodies': ['출근 당일 사내 IT 인프라 계정 활성화와 PC 세팅을 먼저 완료하셔야 합니다.', '사내 그룹웨어 사이트({site})에서 개인 프로필 및 기본 설정 조회를 마쳐주시기 바랍니다.'],
  'details': ['인사 카드 작성을 위해 개인 기본 정보와 비상 연락처 등을 {date}까지 시스템에 기입하셔야 합니다.',
              '기초 온보딩 교육 세션 및 지원은 총무 총괄팀을 통해 지원받으실 수 있습니다.'],
  'conclusions': ['회사 생활 전반에 걸친 유용한 팁은 온보딩 위키 페이지({site})에서 풍부하게 제공됩니다.', '{org}의 일원이 되신 것을 진심으로 환영하며, 성장을 응원합니다.'],
  'allowed_formats': ['REPORT', 'EMAIL', 'WIKI']},
 {'topic_name': 'Git 브랜치 전략 및 코드 리뷰',
  'intros': ['개발 생산성과 릴리즈 안정성을 높이기 위한 소스코드 버전 관리 및 브랜치 배포 전략입니다.',
             '한빛클라우드 개발자들의 원활한 협업을 위한 Git 브랜치 전략 가이드와 코드 리뷰 지침입니다.'],
  'bodies': ['우리는 Git Flow 기반의 변형 전략을 사용하며, feature 브랜치 작업 완료 후 Pull Request가 권장됩니다.',
             '모든 코드는 최소 1명 이상의 피어 리뷰어 승인을 득한 후 master/main에 머지될 수 있습니다.'],
  'details': ['개발용 로컬 테스트 서버 IP는 {ip}이며, CI/CD 빌드 상태는 사내 젠킨스 웹({site})에서 실시간 확인됩니다.',
              '의견 충돌이 있을 시에는 슬랙 채널({site}) 혹은 {dept} 개발 파트 미팅을 통해 조율하시기 바랍니다.'],
  'conclusions': ['코드 퀄리티 유지와 오너십 공유를 위해 모든 커밋 메시지 컨벤션을 명확히 지켜주십시오.',
                  '추가 변경 사항 및 배포 스케줄은 기술 위키 페이지({site})에서 상시 업데이트됩니다.'],
  'allowed_formats': ['REPORT', 'EMAIL', 'SLACK', 'WIKI', 'MINUTES']},
 {'topic_name': '사내 메신저 사용 수칙',
  'intros': ['비대면 협업 및 효율적인 의사소통을 위한 사내 협업 메신저 사용 규칙과 에티켓 가이드입니다.',
             '사내 메신저를 통한 소통 시 정보 유출 방지 및 상호 존중을 위해 필요한 공지사항입니다.'],
  'bodies': ['업무 시간 외 급박하지 않은 메시지 전송은 지양하며, 상태 메시지를 활용해 부재 상황을 공유하세요.',
             '메신저를 통해 기밀 정보나 소스코드 원본을 암호화 없이 외부 채널로 송신하는 행위는 제한됩니다.'],
  'details': ['메신저 계정 분실 및 다중 접속 해제는 포털({site})에서 직접 초기화할 수 있습니다.',
              '인터넷 방화벽 장애 및 메신저 차단은 {dept} 보안 헬프데스크(내선 {phone})로 지원받으십시오.'],
  'conclusions': ['편안하고 배려 있는 대화 분위기를 위해 상호 존중과 신뢰의 태도로 임해주시기 바랍니다.', '자세한 가이드와 예시 템플릿은 사내 복지 채널({site})을 확인해 주세요.'],
  'allowed_formats': ['REPORT', 'EMAIL', 'WIKI']},
 {'topic_name': '개발 가이드 및 테스트 코드 규칙',
  'intros': ['소프트웨어 결함 감소와 유지보수성 향상을 위해 {org} 개발 표준 테스트 가이드를 공유합니다.',
             '안정적인 서비스 배포를 위한 유닛 테스트 및 통합 테스트 작성 규칙에 관한 공지입니다.'],
  'bodies': ['모든 신규 기능 컴포넌트는 최소 70% 이상의 코드 커버리지를 만족해야 배포 빌드가 승인됩니다.',
             '테스트 코드는 Mock 객체를 적극 활용하여 외부 종속성을 완전히 격리하여 구현해야 합니다.'],
  'details': ['개발 통합 테스트용 데이터베이스 접근 정보는 사내 DB 위키({site})에서 안전하게 발급받을 수 있습니다.',
              '테스트 수행 중 발생하는 오류에 대한 질문은 {dept} ({email}) 기술 채널을 활용해 주세요.'],
  'conclusions': ['테스트 작성을 개발 프로세스의 기본으로 정착시켜 고품질 소프트웨어를 만들어 나갑시다.',
                  '상세 모킹 라이브러리 가이드와 예시는 개발 위키 문서({site})에 상세히 기재되어 있습니다.'],
  'allowed_formats': ['REPORT', 'EMAIL', 'WIKI']},
 {'topic_name': '회사 소개서 및 보도자료 지침',
  'intros': ['대외 커뮤니케이션 일관성 확보를 위한 공식 회사 소개서 및 보도자료 작성 배포 가이드라인입니다.', '미디어 대응 및 언론 보도 배포 프로세스 지침을 안내해 드립니다.'],
  'bodies': ['모든 대외 보도자료는 {dept}의 사전 내용 팩트 체크 및 홍보 승인을 득한 후 최종 배포되어야 합니다.',
             '회사 브로셔 및 IR 소개 자료의 로고 CI 규격과 서식은 변경 없이 그대로 유지해야 합니다.'],
  'details': ['최신 소개서 파일은 공식 홈페이지 혹은 사내 웹 다운로드({site})에서 가져올 수 있습니다.',
              '배포 관련 일정 조율 및 세부 조율은 마케팅 담당자({email})로 일원화하여 진행합니다.'],
  'conclusions': ['회사의 대외 신뢰도 제고를 위해 본 배포 프로세스를 철저히 엄수해 주시기 바랍니다.',
                  '관련 파일 아카이브 및 템플릿 모음은 마케팅 위키({site})에서 열람할 수 있습니다.'],
  'allowed_formats': ['REPORT', 'EMAIL', 'WIKI']},
 {'topic_name': '분기별 사업 목표 및 경영 계획',
  'intros': ['{org}의 지속 가능한 성장과 {year}년도 전략 목표 수립을 위한 분기별 경영 계획입니다.',
             '전사 목표 달성을 위해 임직원들과 공유하는 분기별 주요 마일스톤 및 핵심 추진 방향입니다.'],
  'bodies': ['이번 분기에는 고객사 중심의 클라우드 플랫폼 안정성 강화 및 {feature} 고도화를 최우선 목표로 삼고 있습니다.',
             '각 본부별 세부 KPI와 추진 일정은 경영기획본부의 조정과 예산 승인을 완료하였습니다.'],
  'details': ['목표 추진 성과는 분기 말 {date}에 개최되는 타운홀 미팅 및 사내 생방송({site})을 통해 발표됩니다.',
              '실적 통계 및 보고서 파일 다운로드는 경영지원 위키({site})를 활용해 주십시오.'],
  'conclusions': ['도전적인 목표 달성을 위해 한마음으로 노력하는 {org} 임직원 여러분이 되기를 기대합니다.',
                  '부서별 목표 조정 문의는 {dept} 기획 파트 담당자({email})에게 접수 바랍니다.'],
  'allowed_formats': ['REPORT', 'EMAIL', 'WIKI', 'MINUTES']},
 {'topic_name': '오픈소스 사용 가이드라인',
  'intros': ['사내 제품 개발 시 법적 라이선스 리스크를 예방하기 위한 오픈소스 소프트웨어 사용 지침입니다.', '보안 취약점 및 라이선스 위반 방지를 위해 마련된 오픈소스 도입 규칙을 배포합니다.'],
  'bodies': ['모든 오픈소스 라이브러리는 도입 전에 라이선스 종류(GPL, MIT, Apache 등)를 분석하고 등록 요청을 해야 합니다.',
             '특히 Copyleft 조항이 포함된 소스는 상용 릴리즈에 중대한 영향을 미치므로 {dept}의 특별 심의를 거쳐야 합니다.'],
  'details': ['오픈소스 취약점 스캔 서버 IP는 {ip}이며, 분석 요청 양식은 위키 사이트({site})에서 확인하실 수 있습니다.',
              '검토 결과에 관한 문의사항은 기술보안 담당자({email})에게 연락하시기 바랍니다.'],
  'conclusions': ['라이선스 위반은 기업 평판과 제품 보급에 치명적이므로 사용 지침을 적극 엄수해 주시기 바랍니다.',
                  '승인 완료된 오픈소스 라이브러리 카탈로그는 {org} 개발자 포털({site})에 게시되어 있습니다.'],
  'allowed_formats': ['REPORT', 'EMAIL', 'WIKI']},
 {'topic_name': '법인 차량 배차 신청 지침',
  'intros': ['외근 및 영업 지원 업무용 법인 차량의 배차 신청과 안전 운행에 대한 통합 가이드라인입니다.', '업무용 차량 관리 효율성 제고를 위해 법인 차량 이용 규칙을 안내합니다.'],
  'bodies': ['법인 차량 신청은 그룹웨어({site}) 차량 예약 현황판에서 운행 계획을 작성한 후 선착순으로 배정됩니다.',
             '차량 키 반납 시에는 주유 잔량 확인과 운행 일지 작성을 필수로 완료하셔야 합니다.'],
  'details': ['차량 내부 장비 파손 및 정기 검사는 {dept} 총무 지원팀(내선 {phone})에서 전담하여 관리하고 있습니다.',
              '주요 배차 관련 확인 메일은 담당 팀장({email})과 공유되며, 운행 일은 {date}에 마감됩니다.'],
  'conclusions': ['무엇보다 안전 운행이 최우선이므로 도로 교통 법규를 철저히 지켜 안전 사고를 예방해 주시기 바랍니다.',
                  '자세한 안전 가이드라인은 사내 행정 페이지({site})에 안내되어 있습니다.'],
  'allowed_formats': ['REPORT', 'EMAIL', 'WIKI']},
 {'topic_name': '브랜드 스타일 가이드라인',
  'intros': ['한빛클라우드의 통일성 있는 브랜드 아이덴티티 구축을 위한 디자인 스타일 가이드를 전사 배포합니다.',
             '일관된 브랜드 이미지 전달을 위해 마련된 대외 커뮤니케이션 스타일 가이드라인입니다.'],
  'bodies': ['로고 CI, 지정 폰트, 슬로건 서식 등은 마케팅본부의 승인 없이 변형하여 사용할 수 없습니다.',
             '본 지침은 {org}의 가치를 대외적으로 나타내는 핵심 시각 자산으로 법적 보호를 받습니다.'],
  'details': ['가이드라인 문서와 관련 리소스 패키지는 사내 디자인 허브({site})에서 바로 다운로드 받을 수 있습니다.',
              '브랜드 규격 문의와 피드백은 디자인 품질 파트({email})로 보내주시면 답변드리겠습니다.'],
  'conclusions': ['전 직원이 회사의 얼굴인 브랜드 가치를 적극 높이고 올바르게 활용해 주시기를 당부드립니다.',
                  '실제 발표용 슬라이드 및 템플릿 서식은 그룹웨어 디자인 게시판({site})을 참조하십시오.'],
  'allowed_formats': ['REPORT', 'EMAIL', 'WIKI']}]
SENSITIVE_TOPICS = [{'topic_name': '임직원 연봉 계약서',
  'intros': ["근로기준법 및 사내 규정에 의거하여 {org}(이하 '갑')와 근로자 {name} 은 연봉 근로계약을 체결합니다.",
             '비밀 유지 서약이 동반된 {org} 임직원 {name} 의 개별 연봉 계약 정보입니다.'],
  'bodies': ['소속 부서는 {dept}이며, 직책은 {position} 으로 지정합니다. 계약 대상 기간 내의 기본 급여와 근로 조건을 설정합니다.',
             '근로자는 본 계약 상의 연봉 정보 및 인사 기밀을 외부에 절대 누설하지 않을 것을 엄숙히 서약하며 서명합니다.'],
  'details': ['근로자 인적사항: 성명 {name}, 주민등록번호 {rrn}, 휴대전화 {mobile}, 현주소는 {address} 로 등록되어 있습니다.',
              '계약 연봉은 금 5,800만 원 정(세전 기준)이며, 매월 급여일에 지정 계좌 {account} 로 균등 분할 지급합니다.'],
  'conclusions': ['본 연봉 세부 내역은 {dept} 의 제한된 승인자 외에는 공유를 전면 금지하는 대외비 자료입니다.',
                  '비밀유지 의무 위반 시에는 인사 규정에 의한 즉각 처벌과 면직 해고 조치가 이루어질 수 있습니다.'],
  'allowed_formats': ['REPORT', 'EMAIL']},
 {'topic_name': '성과 평가 피드백 보고서',
  'intros': ['{org} 인사 평가 프로세스에 따라 진행된 {dept} 소속 {name} {position} 의 연간 성과 평가서입니다.',
             '비밀 유지가 필수적인 임직원 {name} 의 종합 근무 평정 및 역량 다면 평가 보고서입니다.'],
  'bodies': ['피평가자 {name} ( {age} )은 정보보호 및 {major} 을 전공하였으며, 당해 분기 종합 업무 실적 달성율은 98%로 우수합니다.',
             '리더십 및 다면 평가 결과 협업 능력은 최우수 수준이나, 업무 기한 준수 면에서 개선 요구 사항이 파악되었습니다.'],
  'details': ['피평가자 상세: 성명 {name}, 학력 {education} 졸업 ( {major} 전공), 이메일 {email}, 연락처 {mobile} 입니다.',
              '최종 고과 등급은 A등급으로 부여되었으며, 관련 평정 회의 결과는 {date} 에 최종 의결되었습니다.'],
  'conclusions': ['평가 등급 및 피드백 내용은 본인의 역량 개발용으로만 활용되어야 하며 타 부서 유출은 불가합니다.',
                  '고과 이의 신청 절차는 규정에 따라 7일 이내에 {dept} 파트장 이메일로 서면 접수바랍니다.'],
  'allowed_formats': ['REPORT', 'EMAIL']},
 {'topic_name': '인사위원회 징계의결서',
  'intros': ['사내 복무 규정 및 보안 위반 혐의로 소집된 인사위원회의 최종 징계 의결 사항 보고서입니다.',
             '중대 보안 유출 위반자 {name} {position} 에 대한 징계 조사 경위 및 위원회 처분 결과입니다.'],
  'bodies': ['위반자 {name} (소속 {dept})은 회사 내부의 중요 소스코드를 개인 이메일({email})로 무단 전송하다 관제 시스템에 적발되었습니다.',
             '조사 과정에서 본인의 행위를 정당화하는 주장을 하였으나 보안 침해 고의성이 명백하여 징계 조치가 결의되었습니다.'],
  'details': ['대상자 정보: 성명 {name}, 사내 메일 {email}, 주민등록번호 {rrn}, 등록 차량번호 {car_num} 입니다.',
              '위원회 의결 결과: 정직 3개월 처분 및 기밀 유출 손해에 대한 민형사 소송 제기(의결일자 {date}).'],
  'conclusions': ['본 결정 사항은 1급 보안 문서로 취급되며 외부인의 열람 및 공표를 제한합니다.', '징계 관련 문서는 인사운영 위키 시스템({site})에 영구 보존 조치됩니다.'],
  'allowed_formats': ['REPORT', 'EMAIL']},
 {'topic_name': '퇴직 면담 및 인수인계 대장',
  'intros': ['{org} 퇴직 절차에 따른 퇴사 예정 임직원 {name} {position} 의 심층 면담 일지입니다.',
             '사직 의사를 표명한 {dept} {name} 사원의 사유 조사 및 퇴직급여 이체 처리 대장입니다.'],
  'bodies': ['퇴사 희망자 {name} 은 이직 및 일신상의 사유로 사직을 신청하였으며, 보유한 권한은 {date} 부로 회수 완료 예정입니다.',
             '담당했던 사내 프로젝트({project}) 소스코드 및 문서 자산은 {dept} 파트원에게 성실히 이관되었습니다.'],
  'details': ['퇴직 임직원 정보: 성명 {name}, 연락처 {mobile}, 이메일 {email}, 퇴직금 지급 은행 계좌 {account} 입니다.',
              '상세 인수인계 파일 보존 경로는 {site} 내 퇴직자 문서 보관소에 업로드되었습니다.'],
  'conclusions': ['퇴직 후 3년간 경업 금지 및 기밀 유출 금지 약정이 발효됨을 서면 서약하였습니다.',
                  '문의사항은 {dept} 인사 파트 담당자({email})에게 유선 또는 메일 연락바랍니다.'],
  'allowed_formats': ['REPORT', 'EMAIL']},
 {'topic_name': '입사 지원자 이력서 및 면접 평가서',
  'intros': ['{year}년도 {dept} 신입 및 경력 사원 채용을 위해 접수된 입사 지원자 {name} 의 서류 평가서입니다.',
             '서류 전형 및 실무 면접 평가 결과를 기록한 종합 채용 평가 대장입니다.'],
  'bodies': ['지원자 {name} ( {age} )은 {education} 에서 {major} 을 전공하였으며, 유관 프로젝트 수행 실적이 탁월합니다.',
             '기술 평가 점수는 평균 92점으로 매우 우수하며, 문제 해결 능력 면에서 면접관 전원 우수 평가를 하였습니다.'],
  'details': ['지원자 인적사항: 성명 {name}, 생년월일 {birth}, 연락처 {mobile}, 이메일 {email}, 현주소는 {address} 입니다.',
              '증빙 제출 여권번호는 {passport} 이며 운전면허번호는 {driver_license} 로 확인되어 유효성을 검증 완료했습니다.'],
  'conclusions': ['본 개인정보는 채용 목적 이외에는 사용이 불가능하며 불합격 처리가 확정될 시 180일 이내에 파기됩니다.',
                  '합격 통보 및 연봉 가이드 협상은 {dept} 팀장 메신저 채널({site})에서 후속 논의됩니다.'],
  'allowed_formats': ['REPORT', 'EMAIL']},
 {'topic_name': 'M&A 인수합병 검토 및 비밀유지계약',
  'intros': ['{org} 경영전략팀에서 입안한 경쟁사 영업 양수도 및 M&A(인수합병) 기밀 추진안입니다.', '투자 유치 전략 및 기밀 상호 NDA(비밀유지계약서) 주요 조항 분석 보고서입니다.'],
  'bodies': ['인수 대상인 {org} 파트너사는 보안 가치 및 클라우드 결제 플랫폼({site}) 분석 결과 450억 원의 기업 가치를 갖는 것으로 평가됩니다.',
             '이사회 승인 하에 무기명 전환사채 및 예산 펀드 조성을 통한 우회 자금 확보 계획을 수립하였습니다.'],
  'details': ['비밀 보장 대표자 서명: 의장 {name}, 서명 대행사 주소 {address} , 자금 조달 대표 계좌 {account} 입니다.',
              '자금 실사 및 계약 실행일은 {date} 로 확정되었으며, 진행 상황은 기밀 식별자 {synth_id} 로 관리됩니다.'],
  'conclusions': ['M&A 관련 기밀 누설 시 주가 영향 및 민형사상 중대한 리스크가 발생하므로 배포를 전면 금지합니다.',
                  '상세 보안 규정 검토는 {dept} 담당자({email})에게 문의하여 사전 컨설팅을 득하십시오.'],
  'allowed_formats': ['REPORT', 'EMAIL']},
 {'topic_name': '신규 프로젝트 예산 및 지출 승인',
  'intros': ['{year}년도 하반기 {project} 추진을 위해 상정된 개발 예산안 및 지출 품의 기밀 내역입니다.', '클라우드 서비스 아키텍처 개편 및 연구개발 비용 승인 의결 보고서입니다.'],
  'bodies': ['{project}는 지능형 RAG 구현과 {feature} 탑재를 최종 개발 목표로 하며 총 예산은 15억 원입니다.',
             '인프라 구축과 서버 리스 구매를 위해 집행 예정인 예산 코드는 {dsprosens} 및 식별자 {synth_id} 로 분류됩니다.'],
  'details': ['예산 집행 총괄 책임자: {name} {position} , 연구 개발 지원 부서 {dept} 입니다.',
              '초기 장비 구매 카드 정보는 {card} 이며, 예산 이체 대표 법인 계좌는 {account} 입니다.'],
  'conclusions': ['본 예산 편성 내역은 감사 대상이므로 외부 노출이나 허위 영수증 첨부를 일절 엄금합니다.',
                  '상세 예산 집행 항목 검증 지침은 사내 세무 관리 위키({site})를 확인하세요.'],
  'allowed_formats': ['REPORT', 'EMAIL', 'MINUTES']},
 {'topic_name': '주요 거래처 단가 계약서',
  'intros': ['{org}와 외부 핵심 협력사 간 체결된 제품 공급 단가 계약서 및 기밀 합의서 세부 내역입니다.',
             '타사 유출 시 심각한 경쟁력 훼손을 초래할 수 있는 원가 및 단가 조항 분석서입니다.'],
  'bodies': ['계약 대상 품목은 {product}의 엔터프라이즈 에디션이며, 연간 공급 총액은 금 8억 원으로 약정합니다.',
             '비밀 보장 조항에 의거하여 단가 정보 및 계약 내용은 쌍방 합의 하에 대외비 1급으로 관리됩니다.'],
  'details': ['계약 체결 책임자: {name} {position} , 담당 부서 {dept}, 비상 연락처 {mobile}, 이메일 {email} 입니다.',
              '대금 결제는 매월 지정된 결제 계좌 {account} 로 송금하며, 거래처 식별자는 {synth_id} 로 표시합니다.'],
  'conclusions': ['본 단가 계약 위반 시에는 공급 중단 및 계약 위약금 연 15% 가산 조항이 청구됩니다.',
                  '계약 원본 파일 아카이빙은 계약운영팀 내부망 위키({site})에 탑재 완료되었습니다.'],
  'allowed_formats': ['REPORT', 'EMAIL']},
 {'topic_name': '보안 유출 침해 사고 보고서',
  'intros': ['{org} 보안관제실에서 적발한 내부자 중요 영업 비밀 무단 외부 유출 사고의 조사 경위서입니다.',
             '사내 인프라 단말기에서 탐지된 소스코드 무단 발송 탐지 로그 및 보안 징계 요청서입니다.'],
  'bodies': ['피의자 {name} 은 {date} 경 할당 IP {ip} 를 사용하여 사내 지적 자산인 알고리즘 코드를 외부 메일({email})로 무단 전송하였습니다.',
             '위반자는 개인적 신념 및 사상 유포 목적으로 정보를 유출했다고 소명서에 기술하여 정상적인 훈방이 불가합니다.'],
  'details': ['위반자 인적사항: 성명 {name}, 소속 부서 {dept}, 접속 단말 IP {ip}, 접속 주소는 {address} 입니다.',
              '로그 추적 결과 식별 코드 {synth_id} 및 보안 경보 번호 {dsprosens} 이 활성화된 것을 방화벽 장비에서 검증했습니다.'],
  'conclusions': ['추가 기밀 유출 차단을 위해 피의자의 인프라 계정 접속 권한을 즉시 차단 처리하고 영구 제명하였습니다.',
                  '기술적 추적 로그 상세 본은 보안관제팀 위키({site})에 백업 및 증거 자료로 박제되었습니다.'],
  'allowed_formats': ['REPORT', 'EMAIL']},
 {'topic_name': '데이터베이스 접근 권한 대장',
  'intros': ['{org}의 개인정보 처리 시스템 및 중요 데이터베이스(DB) 접근 권한 관리 대장입니다.', '사내 핵심 정보 자산 접근 통제 및 계정 권한 승인 내역 기밀 문서입니다.'],
  'bodies': ['본 DB 권한은 개인정보 처리 규정에 따라 {dept}에서 통제하며, 권한 등급 1등급의 제한된 인원만 허용됩니다.',
             '권한 보유자는 사내 보안 수칙을 엄수해야 하며 허가받지 않은 IP 및 단말에서의 우회 접속은 차단됩니다.'],
  'details': ['데이터베이스 정보: 관리 호스트 {site}, 할당된 전용 접속 IP는 {ip} 이며 계정 식별자는 {synth_id} 입니다.',
              '승인된 관리자: 성명 {name}, 메일 주소 {email}, 소속 {dept}, 등록된 주민등록번호는 {rrn} 입니다.'],
  'conclusions': ['본 데이터베이스 접근 로그는 매 분기마다 내부 감사 보고서({dsprosens})에 기재되어 경영진에 보고됩니다.',
                  '권한 변경 신청 및 긴급 파기 요청은 보안 포털({site})을 이용해 주시기 바랍니다.'],
  'allowed_formats': ['REPORT', 'WIKI']},
 {'topic_name': '인프라 취약점 진단 결과 보고서',
  'intros': ['한울시큐리티에서 대행 수행한 {org} 핵심 가상 인프라 및 서버 취약점 모의해킹 진단 결과 보고서입니다.',
             '시스템 침투 취약점 분석 및 패치 적용 완료 상태 점검 기밀 요약본입니다.'],
  'bodies': ['진단 결과 웹 애플리케이션 및 WAS 계층에서 원격 코드 실행(RCE)이 가능한 위험 수준의 취약점이 발견되었습니다.',
             '취약점이 식별된 포트 및 데몬 서비스는 즉각 최신 패치를 적용하고 방화벽 포트 차단 조치를 완료했습니다.'],
  'details': ['진단 대상 서버 IP는 {ip} 이며 외부 접근 호스트는 {site} 입니다. 진단 식별 번호는 {synth_id} 및 {dsprosens} 입니다.',
              '인프라 조치 담당자: 성명 {name}, 소속 {dept}, 이메일 {email}, 연락처 {mobile} 입니다.'],
  'conclusions': ['취약점 진단 결과에 포함된 서버 설정 및 구성 정보는 1급 비밀이며 외부 반출을 일절 금지합니다.',
                  '패치 스크립트 적용 검증 로그는 인프라 관리자 위키({site})에서 검토 가능합니다.'],
  'allowed_formats': ['REPORT', 'EMAIL']},
 {'topic_name': '신제품 소스코드 설계 및 특허 초안',
  'intros': ['{org} 기술연구소에서 독점 개발한 {project} 핵심 모듈 아키텍처 및 특허 출원 전 기밀 명세서입니다.',
             '경쟁 우위 확보를 위한 지능형 알고리즘 메커니즘 설명 및 특허 청구 범위 기밀 초안입니다.'],
  'bodies': ['본 기술은 검색 품질 개선을 위해 {reranker} 모델을 연동하고 고효율 벡터 데이터를 탐색하는 메커니즘을 골자로 합니다.',
             '출원 예정인 특허 청구 항 및 독점 기술 설명서는 출원 완료 전까지 절대 외부에 공개되어서는 안 됩니다.'],
  'details': ['발명자 및 연구 책임자: 성명 {name}, 소속 {dept}, 이메일 {email}, 테스트 베드 IP는 {ip} 입니다.',
              '특허 출원 대리 법인은 {org} 법무지원실이며, 발명 보안 토큰은 {synth_id} 및 {dsprosens} 으로 발급되었습니다.'],
  'conclusions': ['이 기술 정보가 외부에 유출될 경우 특허 신규성 상실로 특허 취득이 불가하므로 유출 시 징계 조치합니다.',
                  '상세 소스코드 소유권 조항 및 계약 내역은 개발 위키 문서({site})에 영구 봉인되어 있습니다.'],
  'allowed_formats': ['REPORT', 'EMAIL']},
 {'topic_name': 'AI 모델 학습 데이터 및 프롬프트 보안',
  'intros': ['{org}의 차세대 LLM 제품 {product}의 미세조정(Fine-Tuning) 학습 데이터 구성 및 프롬프트 설계 전략입니다.',
             '모델 응답 안정성 확보 및 프롬프트 인젝션 차단 메커니즘을 상세 기술한 연구 기술서입니다.'],
  'bodies': ['우리는 {product} 모델의 성능 강화를 위해 약 12만 건의 정제된 사내 데이터를 사용하며, 학습 파이프라인 보안을 적용합니다.',
             '모델 구동 단계에서 탈옥(Jailbreak)을 차단하는 시스템 프롬프트 가이드는 1급 기밀로 유지되어야 합니다.'],
  'details': ['연구 개발 파트: {name} {position} , 소속 {dept}, 연구용 서버 접속 IP {ip}, 이메일 {email} 입니다.',
              '모델 검증 결과 코드는 {dsprosens} 이며 개발용 데이터 묶음 토큰은 {synth_id} 로 명명하여 격리 보관합니다.'],
  'conclusions': ['본 프롬프트 설계 정보 및 가중치 정보의 유출은 악의적인 공격에 취약점을 제공하게 되므로 열람 권한을 제한합니다.',
                  '학습 진척도 대시보드 및 상세 평가는 연구 포털({site})에서 담당 승인자에 한해 조회할 수 있습니다.'],
  'allowed_formats': ['REPORT', 'EMAIL', 'WIKI']},
 {'topic_name': 'VIP 고객 명부 및 의전 계획',
  'intros': ['{org}의 프리미엄 클라우드 서비스를 계약한 글로벌 VIP 고객 회원 명부 및 의전 지원 가이드라인입니다.',
             '주요 거래처 VIP 임원의 본사 방문 시 의전 정보 및 신상 정보가 포함된 보안 문서입니다.'],
  'bodies': ['글로벌 VIP 고객인 {name} 은 연간 15억 원 규모의 계약 주체이며 본사 방문 시 지정 차량 에스코트를 진행합니다.',
             '해외 출입국 의전 및 호텔 예약 정보는 오직 VIP 케어 지원 부서에서만 관리하도록 제한됩니다.'],
  'details': ['VIP 상세 정보: 성명 {name}, 여권번호 {passport}, 주민등록번호 {rrn}, 주소 {address} 입니다.',
              '의전 배차 차량번호는 {car_num} 이며, 고객 연락처는 {mobile}, 비상 관리용 이메일은 {email} 입니다.'],
  'conclusions': ['VIP 고객의 동선 및 신상 서류 사본({passport}) 유출 시 중대한 법적 분쟁 소지가 있어 열람을 강력히 통제합니다.',
                  '의전 세부 영수증 결제 내역과 일정표는 총무 비공개 위키({site})에 아카이빙 처리되었습니다.'],
  'allowed_formats': ['REPORT', 'EMAIL']},
 {'topic_name': '보건실 진료 및 처방 기록',
  'intros': ['{org} 사내 건강관리 보건실에 내원하여 진료 및 처방받은 임직원의 의료 기록 대장입니다.',
             '민감 개인정보에 해당하는 임직원의 신체 지표와 질병 치료 및 약품 수급 현황 일지입니다.'],
  'bodies': ['내원자 {name} 은 업무 스트레스로 인한 급성 편두통 및 통증을 호소하여 내원하였으며 바이탈 체크 결과 안정이 요망됩니다.',
             '신체 발달 사항 및 만성 질환 여부(고혈압 등)를 기록하고 사내 보건 규정에 의거하여 임시 요양을 유도했습니다.'],
  'details': ['임직원 인적사항: 성명 {name}, 소속 {dept}, 나이 {age}, {blood} 입니다.',
              '신체 지표: 신장 172cm, 체중 68kg이며 장애 등급 여부는 해당 없음으로 기록, 처방 일은 {date} 입니다.'],
  'conclusions': ['환자의 의료 및 건강진단 내역은 민감 정보 중에서도 극비로 취급되어 본인 외에는 절대로 조회되어서는 안 됩니다.',
                  '추가 요양 확인서 제출 및 양식은 사내 보건 포털({site})에서 다운로드 받아 {dept} 로 제출하시기 바랍니다.'],
  'allowed_formats': ['REPORT']},
 {'topic_name': '고객 상담 요약 및 민원 대장',
  'intros': ['콜센터 접수 고객 민원 상담 처리 대장 및 신용카드 재결제 통제 기록물입니다.', '가계 곤란 고객 상담 기록 및 요금 납부 유예 심사 기밀 명세서입니다.'],
  'bodies': ['고객 {name} 님은 당사 서비스 요금 청구 내역 중 {card} 신용카드 승인 실패 오류에 대해 이의를 제기하셨습니다.',
             '최근 고객 본인의 중대한 질병 진단 및 입원 치료 과정에서 급격한 가계 소득 감소가 발생해 납부 연기 처리를 요청하셨습니다.'],
  'details': ['상담 정보: 고객명 {name}, 고객 연락처 {mobile}, 등록 주소 {address} , 매핑된 식별자 {synth_id} 입니다.',
              '연체 가산금은 일시 면제 처리하되 당월 청구 카드({card}) 재결제 일정을 조율 완료하여 기록합니다.'],
  'conclusions': ['가계 사정을 고려해 장기 미납 보류 승인은 청구심사팀 특별 품의({dsprosens})가 필요함을 안내하였습니다.',
                  '고객 불만 및 상담 세부 녹취 로그는 그룹웨어 고객 시스템({site})에서 안전하게 확인할 수 있습니다.'],
  'allowed_formats': ['REPORT', 'EMAIL']}]
def make_slack_conversation(topic_name: str, blocks: list[str]) -> str:
    channel = f"#{random.choice(['general', 'dev-chat', 'hr-support', 'security-alerts', 'finance-qa', 'design-review', 'it-helpdesk'])}"
    users = [generate_korean_name() for _ in range(3)]
    while len(set(users)) < 3:
        users = [generate_korean_name() for _ in range(3)]
        
    messages = []
    base_time = random.randint(9, 17)
    
    q1 = random.choice([
        f"안녕하세요 팀원분들, 혹시 이번 {topic_name} 진행 상황 아시는 분 계신가요?",
        f"오늘 공지된 {topic_name} 세부 지침 다들 검토하셨나요?",
        f"이번에 진행하는 {topic_name} 관련해서 추가 확인이 필요한 부분이 있습니다.",
        f"혹시 {topic_name} 건에 대해 공유할 만한 진척 사항이 있나요?",
        f"공유해 주신 {topic_name} 정책 다들 확인 부탁드립니다.",
        f"안녕하세요, 이번 {topic_name} 담당자님 혹시 소식 있으신가요?"
    ])
    q2 = random.choice([
        "아하, 구체적인 적용 가이드나 대상은 어떻게 설정되어 있죠?",
        "혹시 세부 일정이나 조치 대상 범위를 자세히 알 수 있을까요?",
        "네, 관련 지침의 세부적인 수행 절차나 준비 사항이 궁금합니다.",
        "그렇군요. 그럼 로컬 테스트를 위한 접속 정보 등도 가이드에 포함되어 있나요?",
        "감사합니다. 혹시 이와 관련해 추가 주의점이나 승인 기한이 따로 있을까요?",
        "확인했습니다! 세부적인 절차나 제출 서류에 대해서도 알려주실 수 있나요?"
    ])
    ack = random.choice([
        f"확인 감사합니다. {blocks[3]}",
        f"자세히 공유해 주셔서 감사합니다. {blocks[3]}",
        f"네, 공유해주신 내용 바탕으로 업무 진행해 보겠습니다. {blocks[3]}",
        f"꼼꼼히 공유해주셔서 고맙습니다! 바로 확인해보죠. {blocks[3]}",
        f"지침에 따라 차질 없이 진행하겠습니다. 정보 공유 감사해요! {blocks[3]}",
        f"감사합니다. 참고하여 조치하도록 하겠습니다. {blocks[3]}"
    ])
    
    messages.append((
        f"{base_time:02d}:01",
        users[0],
        q1
    ))
    messages.append((
        f"{base_time:02d}:03",
        users[1],
        f"네, {blocks[0]}"
    ))
    messages.append((
        f"{base_time:02d}:05",
        users[0],
        q2
    ))
    messages.append((
        f"{base_time:02d}:07",
        users[1],
        f"{blocks[1]}"
    ))
    
    # 3인 대화 및 2인 대화 구조 다양화
    if random.random() > 0.3:
        messages.append((
            f"{base_time:02d}:09",
            users[2],
            f"여기에 덧붙여서 세부 정보 공유드립니다. {blocks[2]}"
        ))
    else:
        messages.append((
            f"{base_time:02d}:09",
            users[1],
            f"덧붙여서 상세 정보를 알려드리자면, {blocks[2]}"
        ))
        
    messages.append((
        f"{base_time:02d}:12",
        users[0],
        ack
    ))
    
    return format_slack(channel, messages)

def make_email_thread(topic_name: str, blocks: list[str]) -> str:
    sender_name = generate_korean_name()
    receiver_name = generate_korean_name()
    while sender_name == receiver_name:
        receiver_name = generate_korean_name()
        
    sender = f"{sender_name} <{generate_email(sender_name)}>"
    receiver = f"{receiver_name} <{generate_email(receiver_name)}>"
    date_str = f"2026-{random.randint(1, 5):02d}-{random.randint(1, 28):02d} {random.randint(9, 18):02d}:{random.randint(0, 59):02d}"
    
    # 이메일 제목 다양화
    title = random.choice([
        f"[{random.choice(['공지', '협조', '요청', '공유'])}] {topic_name} 세부 사항 관련 안내",
        f"[중요] {topic_name}에 관한 업무 협조 요청의 건",
        f"{topic_name} 관련 안내 및 자료 확인 요청",
        f"[{random.choice(DEPT_POOL)}] {topic_name} 관련 가이드 배포"
    ])
    
    # 인사말 다양화
    greeting = random.choice([
        f"안녕하세요, {receiver_name}님.\n업무에 노고가 많으십니다. {random.choice(DEPT_POOL)}에서 관련 지침 공유드립니다.",
        f"{receiver_name}님,\n안녕하십니까. {random.choice(DEPT_POOL)}에서 {topic_name} 관련 자료 전달드립니다.",
        f"수신: {receiver_name}님\n발신: {random.choice(DEPT_POOL)} {sender_name}\n\n안녕하십니까. 협조에 항상 감사드립니다.",
        f"안녕하십니까, {receiver_name}님.\n{random.choice(DEPT_POOL)}에서 금주 조치해야 할 지침을 알려드립니다."
    ])
    
    # 본문 구성
    middle_intro = random.choice([
        f"관련 상세 규정 및 서식 정보는 아래와 같습니다:\n{blocks[2]}",
        f"이와 관련하여 아래의 세부 정보 및 확인 사항을 전달해 드립니다:\n{blocks[2]}",
        f"참고하실 상세 항목은 다음과 같이 구성되어 있습니다:\n{blocks[2]}"
    ])
    
    # 맺음말 다양화
    closing = random.choice([
        f"{blocks[3]}\n\n감사합니다.\n{sender_name} 드림",
        f"{blocks[3]}\n\n확인 후 의견이 있으시면 회신 바랍니다.\n{sender_name} 올림",
        f"{blocks[3]}\n\n좋은 하루 보내십시오.\n{random.choice(DEPT_POOL)} {sender_name} 배상",
        f"{blocks[3]}\n\n수고하십시오.\n{sender_name} 드림"
    ])
    
    email_blocks = [
        greeting,
        f"{blocks[0]}\n\n{blocks[1]}",
        middle_intro,
        closing
    ]
    
    return format_email(title, sender, receiver, email_blocks, date_str)

def make_wiki_page(topic_name: str, blocks: list[str]) -> str:
    author = generate_korean_name()
    version = f"1.{random.randint(0, 9)}"
    
    # 위키 제목 다양화
    title = random.choice([
        f"{topic_name} 통합 가이드 및 운영 규정",
        f"{topic_name} 기술 백서 및 가이드라인",
        f"{topic_name} 업무 표준 매뉴얼 및 FAQ",
        f"{topic_name} 운영 프로세스 및 세부 정의서"
    ])
    
    # 위키 구조 스타일 다양화
    wiki_style = random.choice(["style1", "style2", "style3"])
    if wiki_style == "style1":
        wiki_blocks = [
            f"## 1. 개요 및 취지\n{blocks[0]}",
            f"## 2. 주요 운영 가이드라인\n{blocks[1]}",
            f"## 3. 상세 항목 및 절차\n{blocks[2]}",
            f"## 4. 유의사항\n{blocks[3]}"
        ]
    elif wiki_style == "style2":
        wiki_blocks = [
            f"## I. 도입 배경 및 목적\n{blocks[0]}",
            f"## II. 핵심 원칙 및 방침\n{blocks[1]}",
            f"## III. 세부 실행 절차\n{blocks[2]}",
            f"## IV. 준수사항 및 예외처리\n{blocks[3]}"
        ]
    else:
        wiki_blocks = [
            f"### 1. 목적 (Goal)\n{blocks[0]}",
            f"### 2. 세부 지침 (Policy)\n{blocks[1]}",
            f"### 3. 체크리스트 (Checklist)\n{blocks[2]}",
            f"### 4. 경고 및 주의사항 (Warning)\n{blocks[3]}"
        ]
    
    return format_wiki(title, author, wiki_blocks, version)

def make_meeting_minutes(topic_name: str, blocks: list[str]) -> str:
    facilitator = generate_korean_name()
    attendees = [facilitator, generate_korean_name(), generate_korean_name()]
    while len(set(attendees)) < 3:
        attendees = [facilitator, generate_korean_name(), generate_korean_name()]
        
    # 회의록 제목 다양화
    title = random.choice([
        f"{topic_name} 운영 의결 및 정기 검토 회의",
        f"{topic_name} 쟁점 해결 및 부서 조율 미팅",
        f"{topic_name} 도입 계획 수립을 위한 1차 협의회",
        f"{topic_name} 주간 진척도 검토 및 성과 보고 회의"
    ])
    
    # 회의록 안건 헤더 다양화
    minutes_style = random.choice(["style1", "style2", "style3"])
    if minutes_style == "style1":
        minutes_blocks = [
            f"### 안건 1. 추진 배경 검토\n- {blocks[0]}",
            f"### 안건 2. 운영 지침 구체화 및 상세 논의\n- {blocks[1]}\n- {blocks[2]}",
            f"### 안건 3. 결의 사항 및 특이사항\n- {blocks[3]}"
        ]
    elif minutes_style == "style2":
        minutes_blocks = [
            f"### 1. 현황 및 이슈 공유\n- {blocks[0]}",
            f"### 2. 주요 쟁점 조율\n- {blocks[1]}\n- {blocks[2]}",
            f"### 3. 최종 의결 및 후속 조치\n- {blocks[3]}"
        ]
    else:
        minutes_blocks = [
            f"### Agenda A. 프로젝트 브리핑\n- {blocks[0]}",
            f"### Agenda B. 부서별 질의응답 및 조치 사항\n- {blocks[1]}\n- {blocks[2]}",
            f"### Agenda C. 마일스톤 및 향후 일정\n- {blocks[3]}"
        ]
    
    return format_meeting_minutes(title, facilitator, attendees, minutes_blocks)

def make_report_document(topic_name: str, blocks: list[str], is_sensitive: bool) -> str:
    # 보고서 제목 다양화
    title = random.choice([
        f"{topic_name} 추진 계획 보고서",
        f"{topic_name} 세부 운영 지침서",
        f"{topic_name} 도입 및 개선방안 보고",
        f"{topic_name} 운영 현황 보고서"
    ])
    return format_report(title, blocks)


# Map specific topics to their allowed new formats in-place
for topic in NORMAL_TOPICS:
    name = topic["topic_name"]
    formats = list(topic.get("allowed_formats", ["REPORT", "EMAIL", "SLACK", "WIKI", "MINUTES"]))
    if name == "Git 브랜치 전략 및 코드 리뷰":
        formats.append("COMMIT_LOG")
    elif name == "개발 가이드 및 테스트 코드 규칙":
        formats.append("DEV_LOG")
    elif name == "회의실 예약 및 비품 관리":
        formats.append("ASSET_LIST")
    elif name in ["원격근무 VPN 접속 매뉴얼", "사내 Wi-Fi 연결 가이드", "프린터 복합기 사용법"]:
        formats.append("STATUS_CHECK")
    else:
        formats.append("QA_BOARD")
    topic["allowed_formats"] = formats

for topic in SENSITIVE_TOPICS:
    name = topic["topic_name"]
    formats = list(topic.get("allowed_formats", ["REPORT", "EMAIL", "SLACK", "WIKI", "MINUTES"]))
    if name in ["임직원 연봉 계약서", "주요 거래처 단가 계약서", "M&A 인수합병 검토 및 비밀유지계약"]:
        formats.append("CONTRACT")
    elif name in ["성과 평가 피드백 보고서", "퇴직 면담 및 인수인계 대장", "입사 지원자 이력서 및 면접 평가서", "보건실 진료 및 처방 기록"]:
        formats.append("RESUME_HR")
    elif name in ["보안 유출 침해 사고 보고서", "데이터베이스 접근 권한 대장", "인프라 취약점 진단 결과 보고서"]:
        formats.append("AUDIT_LOG")
    elif name in ["신규 프로젝트 예산 및 지출 승인"]:
        formats.append("INVOICE")
    elif name in ["고객 상담 요약 및 민원 대장"]:
        formats.append("VOC_TICKET")
    topic["allowed_formats"] = formats


def generate_document_text(is_sensitive: bool = False) -> str:
    """무작위 형식과 모듈러 문장 조합으로 고도의 비정형 문서 본문 생성"""
    pii_dict = {
        "name": generate_korean_name(),
        "dept": random.choice(DEPT_POOL),
        "org": random.choice(ORG_POOL),
        "position": generate_position(),
        "ip": generate_ip(),
        "car_num": generate_car_number(),
        "passport": generate_passport(),
        "driver_license": generate_driver_license(),
        "address": generate_detailed_address(),
        "site": generate_site(),
        "birth": generate_birth_date(),
        "age": generate_age(),
        "nickname": generate_nickname(),
        "education": generate_education(),
        "major": generate_major(),
        "blood": generate_blood_type(),
        "dsprosens": generate_dsprosens_code(),
        "year": str(random.choice([2025, 2026])),
        "date": f"2026-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}",
        "welfare": random.choice(["도서구입비", "체력단련비", "외국어 학습", "직무 교육", "종합 건강검진", "가족 의료비", "사내 동호회"]),
        "vpn_client": random.choice(["AnyConnect", "PulseSecure", "FortiClient", "OpenVPN"]),
        "vpn_server": random.choice(["vpn.hbc.co.kr", "secure.hbc.co.kr", "remote.hbc.co.kr"]),
        "holiday": random.choice(["경조 휴가", "포상 연차", "특별 유급휴가", "출산 전후휴가", "반차/반반차"]),
        "product": random.choice(["DocSearch Pro", "DocVault", "DocAudit", "HBC Cloud Platform"]),
        "feature": random.choice(["RAG 기반 답변 생성", "지능형 가로채기 차단", "개인정보 자동 마스킹", "문서 접근권한 제어", "멀티엔티티 매칭 랭킹"]),
        "reranker": random.choice(["bge-reranker-v2-m3", "ko-reranker-v2", "hbc-custom-ranker"]),
        "project": f"{random.choice(['알파', '베타', '시그마', '오메가', '뉴트론', '타이탄'])} {random.choice(['프로젝트', '이니셔티브', '시스템'])}"
    }
    
    # 2단계 PII 주입 시 필요한 추가 종속성 기입
    pii_dict["email"] = generate_email(pii_dict["name"])
    pii_dict["mobile"] = generate_mobile()
    pii_dict["phone"] = generate_phone()
    pii_dict["rrn"] = generate_rrn(pii_dict["birth"])
    pii_dict["card"] = generate_luhn_card()
    pii_dict["account"] = generate_bank_account()
    pii_dict["synth_id"] = generate_synth_identifier(random.choice(["CUST", "CONTRACT", "EMPLOYEE", "KEY", "GROUP", "QUEUE", "PROJECT"]))
    
    # 주제 선정
    topic = random.choice(SENSITIVE_TOPICS) if is_sensitive else random.choice(NORMAL_TOPICS)
    
    # 문단 단위 결합 및 문맥 브릿지 생성
    intro_sentences = [s.format(**pii_dict) for s in topic["intros"]]
    body_sentences = [s.format(**pii_dict) for s in topic["bodies"]]
    detail_sentences = [s.format(**pii_dict) for s in topic["details"]]
    conclusion_sentences = [s.format(**pii_dict) for s in topic["conclusions"]]
    
    # 인트로 문단 구성 (1~2문장)
    intro_paragraph = " ".join(intro_sentences[:random.randint(1, 2)])
    
    # 본문 문단 구성 (2문장 모두 결합 + 추가 정량화 구문)
    additional_context = [
        f"본 과제는 전사 IT 인프라 혁신 전략 및 {pii_dict['dept']}의 연간 로드맵에 의거하여 기획되었으며, 관련 프로세스의 준수 여부가 엄격하게 요구됩니다.",
        f"최근 내부 보안 실태 감사 결과에 따라 식별된 개선 사항을 신속하게 보완하고, 비즈니스 연속성을 극대화하기 위하여 관련 시스템의 점검이 시급히 요해집니다.",
        f"임직원들이 실무 업무 프로세스를 올바르게 이행할 수 있도록 본 내용에 언급된 세부 항목들을 하나하나 검토하고 준수해 주시기를 바랍니다.",
        f"따라서 각 담당자는 본 가이드라인의 세부 사항을 명확히 인지하고, 실무 적용 시 발생할 수 있는 취약점을 사전 예방하는 데 만전을 기해주시기 바랍니다.",
        f"본 사안은 상반기 경영 목표 달성 및 내부 규정 정비 계획의 핵심 과제 중 하나이므로, 일정 지연 없이 적극적으로 협조해 주셔야 합니다.",
        f"정기 서비스 릴리즈 및 배포 과정에서 보안 취약점이 유입되는 것을 원천 차단하기 위해 본 절차의 준수 여부를 상시 모니터링할 예정입니다."
    ]
    body_paragraph = " ".join(body_sentences) + " " + random.choice(additional_context)
    
    # 상세 항목 문단 구성
    detail_paragraph = " ".join(detail_sentences)
    
    # 결론 문단 구성 (1~2문장 + 맺음말 연결)
    closing_context = [
        f"조치 사항에 의문이 있으실 경우 {pii_dict['dept']} 담당자({pii_dict['email']}) 혹은 사내 포털 사이트({pii_dict['site']})를 통해 질의 바랍니다.",
        f"지침 준수에 협조해 주셔서 감사드리며, 추가 공지나 변동 사항이 발생할 경우 그룹웨어를 통해 신속히 공유하겠습니다.",
        f"협조해 주시는 모든 임직원 여러분께 감사드리며, 더욱 안정적이고 효율적인 업무 환경 조성을 위해 노력하겠습니다.",
        f"가이드라인을 위반하거나 보안 침해 사고 징후를 발견한 즉시 {pii_dict['dept']} 긴급 대응 핫라인을 통해 전파해 주시기 바랍니다.",
        f"규정 관련 세부 해석이나 예외 적용 신청은 사내 정보보안 그룹웨어 페이지({pii_dict['site']})의 공식 서식을 활용해 주십시오.",
        f"안정적인 비즈니스 운영과 고객 신뢰 확보를 위한 조치이오니 임직원 여러분의 아낌없는 협조와 적극적인 동참을 부탁드립니다."
    ]
    conclusion_paragraph = " ".join(conclusion_sentences[:random.randint(1, 2)]) + " " + random.choice(closing_context)
    
    blocks = [
        intro_paragraph,
        body_paragraph,
        detail_paragraph,
        conclusion_paragraph
    ]
    
    # 문서 형식 선정
    allowed_formats = topic.get("allowed_formats", ["REPORT", "EMAIL", "SLACK", "WIKI", "MINUTES"])
    doc_type = random.choice(allowed_formats)
    topic_name = topic["topic_name"]
    
    if doc_type == "REPORT":
        return make_report_document(topic_name, blocks, is_sensitive)
    elif doc_type == "EMAIL":
        return make_email_thread(topic_name, blocks)
    elif doc_type == "SLACK":
        return make_slack_conversation(topic_name, blocks)
    elif doc_type == "WIKI":
        return make_wiki_page(topic_name, blocks)
    elif doc_type == "MINUTES":
        return make_meeting_minutes(topic_name, blocks)
    elif doc_type == "COMMIT_LOG":
        return format_commit_log(topic_name, blocks)
    elif doc_type == "DEV_LOG":
        return format_dev_log(topic_name, blocks)
    elif doc_type == "ASSET_LIST":
        return format_asset_list(topic_name, blocks)
    elif doc_type == "STATUS_CHECK":
        return format_status_check(topic_name, blocks)
    elif doc_type == "QA_BOARD":
        return format_qa_board(topic_name, blocks)
    elif doc_type == "VOC_TICKET":
        return format_voc_ticket(topic_name, blocks)
    elif doc_type == "CONTRACT":
        return format_contract(topic_name, blocks)
    elif doc_type == "AUDIT_LOG":
        return format_audit_log(topic_name, blocks)
    elif doc_type == "INVOICE":
        return format_invoice(topic_name, blocks)
    elif doc_type == "RESUME_HR":
        return format_resume_hr(topic_name, blocks)
        
    return "\n\n".join(blocks)

# =============================================================================
# 5. 데이터셋 생성 및 백업 오케스트레이터
# =============================================================================

from reportlab.pdfgen import canvas
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib.pagesizes import letter

def write_pdf_file(file_path: Path, content: str):
    font_paths = [
        "C:/Windows/Fonts/malgun.ttf",
        "C:/Windows/Fonts/malgunbd.ttf",
        "C:/Windows/Fonts/batang.ttc",
        "C:/Windows/Fonts/gulim.ttc"
    ]
    font_name = "MalgunGothic"
    font_registered = False
    for path in font_paths:
        if os.path.exists(path):
            try:
                pdfmetrics.registerFont(TTFont(font_name, path))
                font_registered = True
                break
            except Exception:
                continue
                
    c = canvas.Canvas(str(file_path), pagesize=letter)
    width, height = letter
    
    margin = 54
    x = margin
    y = height - margin
    line_height = 16
    
    c.setFont(font_name if font_registered else "Helvetica", 10)
    
    lines = content.split("\n")
    for line in lines:
        if y < margin:
            c.showPage()
            y = height - margin
            c.setFont(font_name if font_registered else "Helvetica", 10)
            
        max_chars = 50
        wrapped_lines = []
        if len(line) > max_chars:
            for start in range(0, len(line), max_chars):
                wrapped_lines.append(line[start:start+max_chars])
        else:
            wrapped_lines.append(line)
            
        for w_line in wrapped_lines:
            if y < margin:
                c.showPage()
                y = height - margin
                c.setFont(font_name if font_registered else "Helvetica", 10)
            c.drawString(x, y, w_line)
            y -= line_height
            
    c.save()


def make_markdown_content(content: str) -> str:
    lines = content.split("\n")
    formatted = []
    for idx, line in enumerate(lines):
        line_strip = line.strip()
        if not line_strip:
            formatted.append("")
            continue
        if idx == 0 and (line_strip.startswith("[") or line_strip.startswith("■")):
            formatted.append(f"# {line_strip.strip('■[] ')}")
        elif line_strip.startswith("[") and line_strip.endswith("]"):
            formatted.append(f"\n## {line_strip.strip('[]')}")
        elif line_strip.startswith("-------------------------") or line_strip.startswith("========================="):
            formatted.append("---")
        elif line_strip.startswith("-") or line_strip.startswith("*") or line_strip.startswith("  -"):
            formatted.append(line)
        else:
            formatted.append(line)
    return "\n".join(formatted)


def run_dataset_generation():
    """전체 데이터셋 생성 프로세스 구동"""
    print("=" * 60)
    print(" RAG 대규모/고품질 기업형 데이터셋 생성 시작 (다변화 개편)")
    print("=" * 60)
    
    # 1. 경로 설정
    project_root = Path(__file__).parent.parent
    doc_clean_dir = project_root / "data" / "documents" / "clean"
    clean_normal_dir = doc_clean_dir / "normal"
    clean_sensitive_dir = doc_clean_dir / "sensitive"
    
    doc_poisoned_dir = project_root / "data" / "documents" / "poisoned"
    poisoned_normal_dir = doc_poisoned_dir / "normal"
    poisoned_sensitive_dir = doc_poisoned_dir / "sensitive"
    
    backup_root = project_root / "data" / "documents_backup"
    
    # 2. 백업 프로세스
    # Clean 백업 및 삭제
    if doc_clean_dir.exists():
        print(f"기존 clean 데이터셋 감지됨: {doc_clean_dir}")
        backup_root.mkdir(parents=True, exist_ok=True)
        backup_clean_dir = backup_root / "clean"
        if backup_clean_dir.exists():
            shutil.rmtree(backup_clean_dir)
        shutil.copytree(doc_clean_dir, backup_clean_dir)
        print(f"[OK] 기존 clean 데이터셋이 백업되었습니다: {backup_clean_dir}")
        shutil.rmtree(doc_clean_dir)
        
    # Poisoned 백업 및 삭제 (attack은 유지)
    if doc_poisoned_dir.exists():
        print(f"기존 poisoned 데이터셋 감지됨: {doc_poisoned_dir}")
        backup_root.mkdir(parents=True, exist_ok=True)
        backup_poisoned_dir = backup_root / "poisoned"
        if backup_poisoned_dir.exists():
            shutil.rmtree(backup_poisoned_dir)
        shutil.copytree(doc_poisoned_dir, backup_poisoned_dir)
        print(f"[OK] 기존 poisoned 데이터셋이 백업되었습니다: {backup_poisoned_dir}")
        
        if poisoned_normal_dir.exists():
            shutil.rmtree(poisoned_normal_dir)
        if poisoned_sensitive_dir.exists():
            shutil.rmtree(poisoned_sensitive_dir)
            
    # 폴더 신규 생성
    clean_normal_dir.mkdir(parents=True, exist_ok=True)
    clean_sensitive_dir.mkdir(parents=True, exist_ok=True)
    poisoned_normal_dir.mkdir(parents=True, exist_ok=True)
    poisoned_sensitive_dir.mkdir(parents=True, exist_ok=True)
    
    print("\n[단계 1] 일반 문서(Normal) 1,000개 생성 중 (TXT 800, MD 100, PDF 100)...")
    for i in range(1, 1001):
        content = generate_document_text(is_sensitive=False)
        
        if i <= 800:
            filename = f"normal_{i:04d}.txt"
            write_fn = lambda path: path.write_text(content, encoding="utf-8")
        elif i <= 900:
            filename = f"normal_{i:04d}.md"
            md_content = make_markdown_content(content)
            write_fn = lambda path: path.write_text(md_content, encoding="utf-8")
        else:
            filename = f"normal_{i:04d}.pdf"
            write_fn = lambda path: write_pdf_file(path, content)
            
        # clean & poisoned 폴더 둘 다에 작성
        write_fn(clean_normal_dir / filename)
        write_fn(poisoned_normal_dir / filename)
        
        if i % 200 == 0:
            print(f"  · 일반 문서 {i}/1000개 완료...")
            
    print("[OK] 일반 문서 1,000개 생성 완료!")
    
    print("\n[단계 2] 민감 문서(Sensitive) 200개 생성 중 (TXT 160, MD 20, PDF 20)...")
    for i in range(1, 201):
        content = generate_document_text(is_sensitive=True)
        
        if i <= 160:
            filename = f"sensitive_{i:03d}.txt"
            write_fn = lambda path: path.write_text(content, encoding="utf-8")
        elif i <= 180:
            filename = f"sensitive_{i:03d}.md"
            md_content = make_markdown_content(content)
            write_fn = lambda path: path.write_text(md_content, encoding="utf-8")
        else:
            filename = f"sensitive_{i:03d}.pdf"
            write_fn = lambda path: write_pdf_file(path, content)
            
        # clean & poisoned 폴더 둘 다에 작성
        write_fn(clean_sensitive_dir / filename)
        write_fn(poisoned_sensitive_dir / filename)
        
        if i % 50 == 0:
            print(f"  · 민감 문서 {i}/200개 완료...")
            
    print("[OK] 민감 문서 200개 생성 완료!")
    
    print("\n" + "=" * 60)
    print(" [성공] 데이터셋 원본 생성 완료!")
    print(f" - Clean 일반 문서 저장소: {clean_normal_dir}")
    print(f" - Clean 민감 문서 저장소: {clean_sensitive_dir}")
    print(f" - Poisoned 일반 문서 저장소: {poisoned_normal_dir}")
    print(f" - Poisoned 민감 문서 저장소: {poisoned_sensitive_dir}")
    print(" - 생성 파일 총합: 1,200개 (각 환경별)")
    print("=" * 60)


if __name__ == "__main__":
    run_dataset_generation()
