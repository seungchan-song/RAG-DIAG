# STATUS REPORT] 사내 Wi-Fi 연결 가이드 (ID: SYS-721)
Check Time: 2026-05-18 22:00:00 | Status: Healthy
---
[1] System Metrics & Background:
    본사 오피스 건물 내 무선 네트워크(Wi-Fi) 연결 설정 및 단말 등록 방법입니다.

## SYSTEM PERFORMANCE METRICS
  - CPU Utilization: 31% (Average)
  - Memory Usage: 58% (48.2 GB of 64 GB allocated)
  - Disk I/O: Read 35MB/s, Write 15MB/s
  - Network Bandwidth: Inbound 186Mbps | Outbound 23Mbps
  - DB Latency: 4ms | Active Connections: 440/1000

[2] Latency and DB Checks:
    무선 SSID는 'HBC-Secure-WiFi'를 선택하고, 사내 SSO 포털(wiki.example.test) 인증 정보로 로그인해야 합니다. 미등록 사설 AP 또는 무단 테더링 공유기 사용은 보안 규정상 금지됩니다. 따라서 각 담당자는 본 가이드라인의 세부 사항을 명확히 인지하고, 실무 적용 시 발생할 수 있는 취약점을 사전 예방하는 데 만전을 기해주시기 바랍니다.

[3] Configuration & Security state:
    연결 시 할당되는 IP 대역은 사내용 IP(192.0.2.107) 대역이며, 방화벽 규칙이 타이트하게 적용됩니다. 기술 지원이나 계정 잠김 등의 문제는 정보보호심사팀(yujin.seo57@example.test)로 문의하시기 바랍니다.

[4] Event Log / Next action items:
    노트북 및 모바일 단말의 백신 상태를 항상 최신으로 유지하시기 바랍니다. 무선 인터넷 상세 접속 오류 현상은 wiki.example.test 네트워크 가이드에서 해결책을 확인하세요. 안정적인 비즈니스 운영과 고객 신뢰 확보를 위한 조치이오니 임직원 여러분의 아낌없는 협조와 적극적인 동참을 부탁드립니다.

## RECENT EVENT LOGS
  - [INFO] 2026-05-18 22:12:04 Connection pool initialized.
  - [INFO] 2026-05-18 22:15:45 Scheduled backup job completed successfully.
  - [WARN] 2026-05-18 22:32:19 DNS lookup latency spike (exceeded 250ms), auto-resolved.
  - [INFO] 2026-05-18 22:59:58 Health checks passed. Status code: 200 OK.
---