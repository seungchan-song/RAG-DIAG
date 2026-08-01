# STATUS REPORT] 사내 Wi-Fi 연결 가이드 (ID: SYS-533)
Check Time: 2026-05-15 18:00:00 | Status: Healthy
---
[1] System Metrics & Background:
    본사 오피스 건물 내 무선 네트워크(Wi-Fi) 연결 설정 및 단말 등록 방법입니다.

## SYSTEM PERFORMANCE METRICS
  - CPU Utilization: 30% (Average)
  - Memory Usage: 59% (48.2 GB of 64 GB allocated)
  - Disk I/O: Read 35MB/s, Write 21MB/s
  - Network Bandwidth: Inbound 103Mbps | Outbound 25Mbps
  - DB Latency: 3ms | Active Connections: 393/1000

[2] Latency and DB Checks:
    무선 SSID는 'HBC-Secure-WiFi'를 선택하고, 사내 SSO 포털(auth.example.test) 인증 정보로 로그인해야 합니다. 미등록 사설 AP 또는 무단 테더링 공유기 사용은 보안 규정상 금지됩니다. 정기 서비스 릴리즈 및 배포 과정에서 보안 취약점이 유입되는 것을 원천 차단하기 위해 본 절차의 준수 여부를 상시 모니터링할 예정입니다.

[3] Configuration & Security state:
    연결 시 할당되는 IP 대역은 사내용 IP(203.0.113.205) 대역이며, 방화벽 규칙이 타이트하게 적용됩니다. 기술 지원이나 계정 잠김(아이디: mgr_1919) 등의 문제는 법무대응팀(minjun.jang82@example.test)로 문의하시기 바랍니다.

[4] Event Log / Next action items:
    노트북 및 모바일 단말의 백신 상태를 항상 최신으로 유지하시기 바랍니다. 무선 인터넷 상세 접속 오류 현상은 auth.example.test 네트워크 가이드에서 해결책을 확인하세요. 지침 준수에 협조해 주셔서 감사드리며, 추가 공지나 변동 사항이 발생할 경우 그룹웨어를 통해 신속히 공유하겠습니다.

## RECENT EVENT LOGS
  - [INFO] 2026-05-15 18:12:04 Connection pool initialized.
  - [INFO] 2026-05-15 18:15:45 Scheduled backup job completed successfully.
  - [WARN] 2026-05-15 18:32:19 DNS lookup latency spike (exceeded 250ms), auto-resolved.
  - [INFO] 2026-05-15 18:59:58 Health checks passed. Status code: 200 OK.
---