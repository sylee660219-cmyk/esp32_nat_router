# WireGuard 자동 등록 서버 (wg-enroll)

ESP32 가 스스로 만든 WireGuard 공개키를 보내면, 이 서비스가 IP 를 배정하고
오라클 서버의 `wg0` 에 피어로 등록한 뒤 터널 설정을 돌려줍니다.

```
ESP32 --HTTPS(8443, 등록 토큰)--> wg-enroll --wg set--> wg0
      <-- IP, 서버 공개키, PSK, 엔드포인트 --
```

- Python 3 표준 라이브러리만 사용 (추가 설치 없음)
- 장비 목록은 `/etc/wg-enroll/devices.json` 에 저장. `wg0.conf` 는 수정하지 않음
  (서비스가 시작할 때 목록의 장비들을 `wg0` 에 다시 등록)
- 자동 배정 IP: `10.10.0.10` ~ `10.10.0.250`. 수동 피어(.1 서버, .2, .3 사무실 PC)는 건드리지 않음

## 1. 설치 (오라클 서버에서 한 번)

```bash
ssh ubuntu@168.110.106.47
git clone -b keysetup https://github.com/sylee660219-cmyk/WireGuardvpn.git
cd WireGuardvpn/WireGuardvpn/server
sudo bash install.sh            # 공인 IP 가 다르면: sudo bash install.sh <공인IP>
```

설치가 끝나면 화면에 다음 두 가지가 출력됩니다.

| 출력 | 성격 | 넣는 곳 |
|---|---|---|
| 등록 토큰 | **비밀** | PC 에서 `idf.py menuconfig` → `WireGuard VPN Client` → `Enrollment token` |
| 서버 인증서 (`-----BEGIN CERTIFICATE-----` ~ `-----END CERTIFICATE-----`) | 공개 | `WireGuardvpn/main/certs/enroll_server.pem` 파일 내용을 통째로 교체 |

다시 보고 싶을 때:
```bash
sudo python3 -c "import json;print(json.load(open('/etc/wg-enroll/config.json'))['tokens'])"
sudo cat /etc/wg-enroll/server.crt
```

`install.sh` 는 다시 실행해도 안전합니다 (토큰, 인증서, 장비 목록 유지).

## 2. OCI 콘솔에서 TCP 8443 열기

오라클 클라우드는 방화벽이 두 겹입니다. 우분투 방화벽은 `install.sh` 가 열고,
OCI 보안 목록은 웹 콘솔에서 직접 열어야 합니다 (UDP 51820 을 열었던 곳과 같은 화면).

1. cloud.oracle.com → 메뉴(≡) → **네트워킹** → **가상 클라우드 네트워크**
2. 서버의 VCN → **서브넷** → **보안 목록** (예: Default Security List)
3. **수신 규칙 추가**: 소스 CIDR `0.0.0.0/0`, IP 프로토콜 `TCP`, 대상 포트 `8443`

LTE 망의 ESP32 는 IP 가 계속 바뀌므로 소스는 `0.0.0.0/0` 이고, 대신 토큰과 인증서로 보호합니다.

## 3. 동작 확인

```bash
sudo systemctl status wg-enroll          # active (running)
sudo journalctl -u wg-enroll -f          # 등록 요청 로그 실시간 보기
sudo wg_enroll.py list                   # 등록된 장비 목록
```

서버에서 직접 시험 (가짜 키로 등록 → 확인 → 삭제):
```bash
TOKEN=<등록 토큰>
curl -k -H "Authorization: Bearer $TOKEN" \
  -d '{"mac":"00:00:00:00:00:01","public_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","name":"test"}' \
  https://127.0.0.1:8443/api/enroll
sudo wg show wg0                         # 10.10.0.10 피어가 보이면 성공
sudo wg_enroll.py delete 00:00:00:00:00:01   # 시험 장비 삭제, IP 반납
```

## 4. 관리 명령

| 명령 | 설명 |
|---|---|
| `sudo wg_enroll.py list` | 장비 목록 (MAC, IP, 상태, 이름, 펌웨어, 등록/최근 접속 시각) |
| `sudo wg_enroll.py revoke <MAC>` | 장비 차단. VPN 에서 즉시 제거, 다시 등록 요청해도 거부 (IP 는 예약 유지) |
| `sudo wg_enroll.py reset <MAC>` | 장비 재등록 허용. flash 를 지운 장비가 새 키로 등록할 때 필요. **같은 IP 유지** |
| `sudo wg_enroll.py delete <MAC>` | 장비를 목록에서 완전히 삭제하고 IP 반납 (폐기한 장비, 시험 등록) |
| `sudo wg_enroll.py token-new` | 새 등록 토큰 추가 |
| `sudo wg_enroll.py token-remove <토큰>` | 토큰 삭제 |

토큰을 추가/삭제한 뒤에는 `sudo systemctl restart wg-enroll`.

### 장비가 등록되지 않을 때 (ESP32 로그 기준)

| ESP32 로그 | 원인 | 조치 |
|---|---|---|
| `Enrollment token rejected` | 토큰 불일치 | menuconfig 토큰 확인 후 다시 빌드 |
| `MAC already registered with another key` | flash 를 지워 키가 새로 만들어짐 | 서버에서 `sudo wg_enroll.py reset <MAC>` |
| `This device was revoked` | 차단된 장비 | 의도한 것이 아니면 `reset <MAC>` |
| `Connection to ... failed` | 8443 포트가 막힘, 서비스 중지, 인증서 불일치 | OCI 보안 목록, `systemctl status wg-enroll`, pem 파일 확인 |

## 5. 토큰이 유출되었을 때

1. `sudo wg_enroll.py token-new` 로 새 토큰 발급 → `token-remove <옛 토큰>` → `systemctl restart wg-enroll`
2. 새 토큰으로 펌웨어 빌드 (이미 등록된 장비는 영향 없음, 계속 동작)
3. `sudo wg_enroll.py list` 에서 모르는 장비가 있으면 `revoke`

유출된 토큰으로는 **새 장비 등록만** 가능하고, 이미 등록된 장비의 IP 를 빼앗을 수는 없습니다
(같은 MAC 에 다른 키로 요청하면 거부).

## 6. 권장: 장비 간 접속 차단 (선택)

가짜 장비가 등록되더라도 사무실 PC 로 들어오지 못하게, VPN 안에서 **사무실 PC → 장비** 방향만 허용합니다.
기존 규칙과 순서가 중요하므로 적용 전에 `sudo iptables -L FORWARD -n --line-numbers` 로 현재 상태를 확인하세요.

```bash
# 이미 연결된 통신의 응답은 허용
sudo iptables -I FORWARD 1 -i wg0 -o wg0 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# 사무실 PC(10.10.0.3) 에서 시작하는 접속만 허용
sudo iptables -I FORWARD 2 -i wg0 -o wg0 -s 10.10.0.3 -j ACCEPT
# 그 외 VPN 내부 신규 접속(장비 → PC, 장비 ↔ 장비) 차단
sudo iptables -I FORWARD 3 -i wg0 -o wg0 -j DROP
sudo netfilter-persistent save
```

사무실 PC 를 추가하면 2번 규칙처럼 그 PC 의 IP 를 허용하는 줄을 추가합니다.

## 파일

| 파일 | 설치 위치 |
|---|---|
| `wg_enroll.py` | `/usr/local/bin/wg_enroll.py` |
| `wg-enroll.service` | `/etc/systemd/system/wg-enroll.service` |
| 설정 (토큰, IP 풀 등) | `/etc/wg-enroll/config.json` |
| 인증서 / 개인키 | `/etc/wg-enroll/server.crt`, `server.key` |
| 장비 목록 | `/etc/wg-enroll/devices.json` |
