# WireGuard 자동 등록(Auto-Enrollment) 기능 추가 변경 이력

## 1. 버전 및 브랜치 정보
- **브랜치명**: `feat-auto-enroll`
- **기준 브랜치**: `dev-vpn-gateway` (커밋 `06cc2c0` - `v2.4.17+sd_logger`)
- **버전 표기**: `v2.4.17+auto_enroll`
- **작업 일시**: 2026-09-27
- **참조 프로젝트**: `E:\oata\WireGuardvpn\WireGuardvpn` (오라클 WireGuard 등록 서버: `https://168.110.106.47:8443`)

---

## 2. 기능 개요
기존 `esp32_nat_router`의 강력한 라우팅 기능(NAT 인터넷 공유, Wi-Fi AP, DHCP 서버, 방화벽, 포트포워딩 등)을 100% 그대로 유지하면서, 오라클 중앙 서버에 암호화 키를 자동 등록하고 WireGuard 터널 IP 및 설정을 자동으로 받아오는 **제로 터치(Zero-Touch) 자동 등록(Auto-Enrollment) 기능**을 추가했습니다.

---

## 3. 인증 및 동작 구조

```
[ESP32 NAT Router (feat-auto-enroll)]
      │
      ├─ 1. [부팅 시] Curve25519 하드웨어 난수 기반 키 페어 자동 생성
      │      - Private Key: NVS "vpn_privkey" (외부 비공개)
      │      - Public Key: NVS "vpn_dev_pubkey"
      │
      ├─ 2. [인터넷 연결 시] Wi-Fi STA 또는 Ethernet 링크 활성화 및 SNTP 시간 동기화
      │
      ├─ 3. [HTTPS 자동 등록] POST https://168.110.106.47:8443/api/enroll
      │      - 서버 인증서 핀 검증: main/certs/enroll_server.pem
      │      - 인증 헤더: Authorization: Bearer <Enrollment Token>
      │      - JSON 요청: {"mac": MAC, "public_key": 기기공개키, "name": 호스트명, "firmware": "2.4.17+auto_enroll"}
      │
      ├─ 4. [설정 자동 수신 & 저장]
      │      - 수신 항목: tunnel IP, netmask, server public key, preshared key, endpoint, port, keepalive
      │      - NVS에 영구 보존 및 런타임 변수 갱신
      │
      └─ 5. [WireGuard 터널 연결] vpn_connect() 실행 -> 원격 터널 즉시 개통
```

---

## 4. 변경된 파일 목록 및 상세 내용

| 구분 | 파일 경로 | 변경 상세 내용 |
| :--- | :--- | :--- |
| **신규** | `main/certs/enroll_server.pem` | 오라클 등록 서버의 검증용 공개 인증서 (바이너리 임베드용) |
| **신규** | `include/vpn_enroll.h` | 자동 등록 관련 함수 선언 및 기본 서버 URL 상수 정의 |
| **신규** | `main/vpn_enroll.c` | Curve25519 키 생성, HTTPS 클라이언트(토큰/인증서), JSON 응답 파싱 및 상태 관리 |
| **수정** | `main/CMakeLists.txt` | `esp_http_client`, `mbedtls` 라이브러리 추가, `enroll_server.pem` 임베드, `vpn_enroll.c` 등록 |
| **수정** | `main/Kconfig.projbuild` | `menu "WireGuard Auto-Enrollment (Oracle)"` 추가 (토큰, URL, 활성화 기본값) |
| **수정** | `include/vpn_config.h` | `vpn_auto_enroll`, `vpn_enroll_url`, `vpn_enroll_token`, `vpn_device_pubkey` 선언 |
| **수정** | `main/esp32_nat_router.c` | 변수 정의, 부팅 시 NVS/Kconfig 값 로드 및 Wi-Fi/ETH 연결 시 자동 트리거 |
| **수정** | `main/vpn_manager.c` | `vpn_connect_task`에서 SNTP 동기화 후 자동 등록 요청(`vpn_enroll_request`) 실행, 작업 스택 8KB로 상향 |
| **수정** | `components/cmd_router/cmd_router.c` | 시리얼 콘솔 명령어 `set_vpn_enroll <0\|1> [-u <url>] [-t <token>]` 추가 |
| **수정** | `components/http_server/CMakeLists.txt` | `${CMAKE_SOURCE_DIR}/include` 추가로 `vpn_enroll.h` 참조 가능 |
| **수정** | `components/http_server/http_server.c` | 웹 UI의 VPN 설정 페이지에 자동 등록 상태/기기 공개키 표시, 모드 선택(Manual/Auto) 및 토큰 입력 폼 추가 |
| **신규** | `server/wg_enroll.py` | 오라클 서버용 WireGuard 자동 등록 REST API & 웹 관리자 대시보드 데몬 |
| **신규** | `server/install.sh` | 오라클 서버 1-Click 설치 스크립트 |
| **신규** | `server/wg-enroll.service` | systemd 백그라운드 서비스 등록 파일 |
| **신규** | `server/README.md` | 오라클 서버 설치 및 명령어 운영 가이드 |
| **수정** | `sdkconfig.defaults` | `CONFIG_LWIP_PPP_SUPPORT=y` 추가 (WireGuard 연결 시 `LoadProhibited` 무한 재부팅 방지) |
| **수정** | `sdkconfig` | `CONFIG_LWIP_PPP_SUPPORT=y` 활성화 |


---

## 5. 빌드 및 설정 가이드 (직접 빌드용)

### 1) menuconfig로 토큰 설정
```bash
idf.py menuconfig
```
1. **`WireGuard Auto-Enrollment (Oracle)`** 메뉴 선택
2. **`Enable WireGuard Auto-Enrollment by default`**: `[Y]` (기본 활성화)
3. **`Enrollment server URL`**: `https://168.110.106.47:8443` (기본값)
4. **`Enrollment token`**: 오라클 서버에서 발급받은 **Bearer 토큰 입력**
5. 저장(`Save`) 후 종료

### 2) 빌드 및 플래시
```bash
idf.py build
idf.py flash monitor
```

---

## 6. 테스트 및 확인 방법

1. **최초 부팅 로그 확인**:
   - `Generated new device key pair. Public key: ...` (기기 고유 키 자동 생성)
   - `Sending enrollment request to https://168.110.106.47:8443/api/enroll ...`
   - `Enrollment successful! Assigned VPN IP: 10.10.0.X, Endpoint: 168.110.106.47:51820`
   - `WireGuard VPN connected`
2. **웹 UI 확인**:
   - 브라우저에서 `http://192.168.4.1` 접속 후 **[VPN]** 탭 진입
   - **Auto-Enroll**: `등록됨 (연결 준비 완료)` 상태 표시 확인
   - **Device Key**: 기기의 Base64 공개키 확인
   - 필요 시 웹 UI에서 다른 토큰으로 교체 가능
3. **시리얼 콘솔(CLI) 확인**:
   - `status` 또는 `set_vpn_enroll` 명령으로 상태 확인 및 제어 가능
4. **수동 모드와의 호환성 테스트**:
   - `set_vpn_enroll 0` 또는 웹 UI에서 `Manual` 모드로 전환 시 기존처럼 수동 WireGuard 설정으로 동작함
