#!/usr/bin/env python3
"""WireGuard enrollment service & Web Admin Dashboard for ESP32 devices.
Version: see VERSION below (shown in the dashboard header and startup log)

Features:
- REST API for ESP32 auto-enrollment (HTTPS POST /api/enroll)
- Responsive Modern Web Admin Dashboard (GET /admin, GET /)
- Interactive Device Management: List, Reset, Delete, Revoke with 1-click
- Real-time WireGuard Peer Status & Traffic Monitoring
- Token Management via Web UI and CLI
- CLI admin commands (list, revoke, reset, delete, token-new, token-remove)

Only the Python 3 standard library is used.
"""

import argparse
import base64
import ipaddress
import json
import os
import re
import secrets
import ssl
import subprocess
import sys
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CONFIG_PATH = os.environ.get("WG_ENROLL_CONFIG", "/etc/wg-enroll/config.json")

MAC_RE = re.compile(r"^[0-9A-F]{2}(:[0-9A-F]{2}){5}$")
KEY_RE = re.compile(r"^[A-Za-z0-9+/]{43}=$")
MAX_BODY = 4096
VERSION = "2.5"  # bump on every server change

db_lock = threading.Lock()
cfg_lock = threading.Lock()
rate_lock = threading.Lock()
rate_hits = {}


def now():
    return datetime.now().isoformat(timespec="seconds")


def log(msg):
    print(f"{now()} {msg}", flush=True)


def load_json(path, default):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return default


def save_json(path, data):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    os.chmod(tmp, 0o600)
    os.replace(tmp, path)


def current_tokens(cfg):
    """Tokens as saved in the config file right now, so CLI token-new/remove apply without a restart."""
    try:
        cfg["tokens"] = load_json(CONFIG_PATH, cfg)["tokens"]
    except (OSError, ValueError, KeyError):
        pass  # keep the last good list if the file cannot be read
    return cfg["tokens"]


def edit_tokens(cfg, change):
    """Apply change(tokens) to the config file's current token list and save it.
    Works on the file, not the in-memory cfg, so edits made from the CLI are never overwritten."""
    with cfg_lock:
        disk = load_json(CONFIG_PATH, None)
        if disk is None:
            raise OSError(f"config not found: {CONFIG_PATH}")
        result = change(disk["tokens"])
        save_json(CONFIG_PATH, disk)
        cfg["tokens"] = disk["tokens"]
        return result


def load_config():
    cfg = load_json(CONFIG_PATH, None)
    if cfg is None:
        sys.exit(f"config not found: {CONFIG_PATH} (run install.sh first)")
    return cfg


# ---- WireGuard helpers ----

def wg(*args, stdin=None):
    return subprocess.run(["wg", *args], input=stdin, capture_output=True, text=True, check=True).stdout.strip()


def server_public_key(cfg):
    return wg("show", cfg["interface"], "public-key")


def apply_peer(cfg, dev):
    # preshared-key only accepts a file, so feed it through stdin instead of a temp file
    wg("set", cfg["interface"], "peer", dev["public_key"],
       "preshared-key", "/dev/stdin",
       "allowed-ips", f"{dev['ip']}/32",
       stdin=dev["preshared_key"] + "\n")


def remove_peer(cfg, public_key):
    if public_key:
        subprocess.run(["wg", "set", cfg["interface"], "peer", public_key, "remove"],
                       capture_output=True, text=True)


def interface_ips(cfg):
    """IPs already used by any peer on the interface (including manually added ones)."""
    used = set()
    try:
        out = wg("show", cfg["interface"], "allowed-ips")
        for line in out.splitlines():
            for cidr in line.split()[1:]:
                try:
                    used.add(str(ipaddress.ip_interface(cidr).ip))
                except ValueError:
                    pass
    except Exception:
        pass
    return used


def allocate_ip(cfg, db):
    used = interface_ips(cfg) | {d["ip"] for d in db.values()}
    start = ipaddress.IPv4Address(cfg["pool_start"])
    end = ipaddress.IPv4Address(cfg["pool_end"])
    ip = start
    while ip <= end:
        if str(ip) not in used:
            return str(ip)
        ip += 1
    return None


def new_psk():
    return base64.b64encode(secrets.token_bytes(32)).decode()


def restore_peers(cfg):
    db = load_json(cfg["db"], {})
    n = 0
    for mac, dev in db.items():
        if dev.get("public_key") and not dev.get("revoked"):
            try:
                apply_peer(cfg, dev)
                n += 1
            except subprocess.CalledProcessError as e:
                log(f"restore {mac} failed: {e.stderr.strip()}")
    log(f"restored {n} peer(s) on {cfg['interface']}")


def get_wg_stats(cfg):
    """Parse real-time wireguard peer statistics using 'wg show <iface> dump'."""
    stats = {}
    try:
        out = wg("show", cfg["interface"], "dump")
        lines = out.splitlines()
        for line in lines[1:]:
            parts = line.split("\t")
            if len(parts) >= 8:
                pub = parts[0]
                endpoint = parts[2] if parts[2] != "(none)" else ""
                allowed_ips = parts[3]
                try:
                    handshake = int(parts[4])
                except ValueError:
                    handshake = 0
                try:
                    rx = int(parts[5])
                    tx = int(parts[6])
                except ValueError:
                    rx, tx = 0, 0
                stats[pub] = {
                    "endpoint": endpoint,
                    "allowed_ips": allowed_ips,
                    "latest_handshake": handshake,
                    "rx_bytes": rx,
                    "tx_bytes": tx,
                }
    except Exception as e:
        log(f"get_wg_stats failed: {e}")
    return stats


# ---- Web Admin HTML Dashboard Template ----

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>WireGuard IoT 기기 관리 대시보드</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Pretendard:wght@400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0f172a;
      --card-bg: rgba(30, 41, 59, 0.7);
      --card-border: rgba(255, 255, 255, 0.08);
      --text-main: #f8fafc;
      --text-muted: #94a3b8;
      --accent: #38bdf8;
      --accent-hover: #0ea5e9;
      --green: #22c55e;
      --green-bg: rgba(34, 197, 94, 0.15);
      --amber: #f59e0b;
      --amber-bg: rgba(245, 158, 11, 0.15);
      --red: #ef4444;
      --red-bg: rgba(239, 68, 68, 0.15);
      --gray: #64748b;
      --radius: 12px;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: 'Pretendard', -apple-system, BlinkMacSystemFont, sans-serif;
      background-color: var(--bg);
      color: var(--text-main);
      min-height: 100vh;
      padding: 24px;
      line-height: 1.5;
    }
    .container { max-width: 1200px; margin: 0 auto; }
    
    /* Header */
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 24px;
      padding-bottom: 16px;
      border-bottom: 1px solid var(--card-border);
      flex-wrap: wrap;
      gap: 16px;
    }
    .brand { display: flex; align-items: center; gap: 12px; }
    .brand-icon {
      width: 40px; height: 40px; background: linear-gradient(135deg, #0284c7, #38bdf8);
      border-radius: 10px; display: flex; align-items: center; justify-content: center;
      font-size: 20px; box-shadow: 0 4px 12px rgba(56, 189, 248, 0.3);
    }
    .brand-title { font-size: 1.4rem; font-weight: 700; color: #fff; }
    .brand-version { font-size: 0.8rem; font-weight: 500; color: var(--text-muted); margin-left: 6px; }
    .brand-sub { font-size: 0.85rem; color: var(--text-muted); }

    .header-actions { display: flex; align-items: center; gap: 12px; }
    .btn {
      padding: 8px 16px;
      border-radius: 8px;
      font-size: 0.88rem;
      font-weight: 600;
      cursor: pointer;
      border: 1px solid transparent;
      transition: all 0.2s;
      display: inline-flex;
      align-items: center;
      gap: 6px;
    }
    .btn-primary { background: var(--accent); color: #0f172a; }
    .btn-primary:hover { background: var(--accent-hover); }
    .btn-outline { background: transparent; border-color: var(--card-border); color: var(--text-main); }
    .btn-outline:hover { background: rgba(255,255,255,0.05); }
    .btn-sm { padding: 4px 10px; font-size: 0.8rem; border-radius: 6px; }
    .btn-reset { color: var(--amber); border-color: rgba(245, 158, 11, 0.3); background: var(--amber-bg); }
    .btn-reset:hover { background: rgba(245, 158, 11, 0.3); }
    .btn-delete { color: var(--red); border-color: rgba(239, 68, 68, 0.3); background: var(--red-bg); }
    .btn-delete:hover { background: rgba(239, 68, 68, 0.3); }
    .btn-revoke { color: var(--text-muted); border-color: rgba(148, 163, 184, 0.3); background: rgba(255,255,255,0.05); }
    .btn-revoke:hover { color: #fff; background: rgba(255,255,255,0.1); }
    .btn-unrevoke { color: var(--green); border-color: rgba(34, 197, 94, 0.3); background: var(--green-bg); }
    .btn-unrevoke:hover { background: rgba(34, 197, 94, 0.3); }

    .filters { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
    .filter-input {
      padding: 6px 10px; background: rgba(15, 23, 42, 0.8); border: 1px solid var(--card-border);
      border-radius: 6px; color: #fff; font-size: 0.85rem; outline: none;
    }
    .filter-input:focus { border-color: var(--accent); }

    .auto-refresh { display: flex; align-items: center; gap: 8px; font-size: 0.85rem; color: var(--text-muted); }

    /* Stats Grid */
    .stats-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(220px, 1fr));
      gap: 16px;
      margin-bottom: 24px;
    }
    .stat-card {
      background: var(--card-bg);
      backdrop-filter: blur(12px);
      border: 1px solid var(--card-border);
      border-radius: var(--radius);
      padding: 18px 20px;
      box-shadow: 0 4px 20px rgba(0,0,0,0.2);
    }
    .stat-label { font-size: 0.85rem; color: var(--text-muted); margin-bottom: 6px; }
    .stat-value { font-size: 1.8rem; font-weight: 700; color: #fff; display: flex; align-items: baseline; gap: 6px; }
    .stat-unit { font-size: 0.85rem; color: var(--text-muted); font-weight: 400; }

    /* Main Table Card */
    .card {
      background: var(--card-bg);
      backdrop-filter: blur(12px);
      border: 1px solid var(--card-border);
      border-radius: var(--radius);
      overflow: hidden;
      box-shadow: 0 4px 20px rgba(0,0,0,0.2);
      margin-bottom: 24px;
    }
    .card-header {
      padding: 16px 20px;
      border-bottom: 1px solid var(--card-border);
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 12px;
    }
    .card-title { font-size: 1.1rem; font-weight: 600; display: flex; align-items: center; gap: 8px; }

    .table-responsive { width: 100%; overflow: auto; max-height: calc(100vh - 380px); min-height: 240px; }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.9rem; }
    th {
      position: sticky;
      top: 0;
      z-index: 1;
      padding: 12px 18px;
      background: #131c30;
      color: var(--text-muted);
      font-weight: 600;
      border-bottom: 1px solid var(--card-border);
      white-space: nowrap;
    }
    td {
      padding: 14px 18px;
      border-bottom: 1px solid rgba(255, 255, 255, 0.04);
      vertical-align: middle;
      white-space: nowrap;
    }
    tr:hover td { background: rgba(255, 255, 255, 0.02); }

    /* Badges */
    .badge {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      padding: 4px 10px;
      border-radius: 9999px;
      font-size: 0.78rem;
      font-weight: 600;
    }
    .badge-online { background: var(--green-bg); color: var(--green); }
    .badge-offline { background: rgba(255,255,255,0.06); color: var(--gray); }
    .badge-reset { background: var(--amber-bg); color: var(--amber); }
    .badge-revoked { background: var(--red-bg); color: var(--red); }
    
    .pulse-dot {
      width: 8px; height: 8px; border-radius: 50%; background: currentColor;
      box-shadow: 0 0 8px currentColor;
    }

    .mac-tag { font-family: monospace; font-size: 0.92rem; font-weight: 600; color: var(--accent); }
    .ip-tag { font-family: monospace; font-size: 0.92rem; color: #fff; }
    a.ip-tag { text-decoration: underline dotted; }
    a.ip-tag:hover { color: var(--accent); }
    .actions-cell { display: flex; gap: 6px; }

    /* Modal */
    .modal-overlay {
      position: fixed; inset: 0; background: rgba(0,0,0,0.7); backdrop-filter: blur(4px);
      display: flex; align-items: center; justify-content: center; z-index: 1000;
      opacity: 0; pointer-events: none; transition: all 0.2s;
    }
    .modal-overlay.active { opacity: 1; pointer-events: auto; }
    .modal {
      background: #1e293b; border: 1px solid var(--card-border); border-radius: 14px;
      padding: 24px; width: 90%; max-width: 480px; box-shadow: 0 10px 30px rgba(0,0,0,0.5);
    }
    .modal-title { font-size: 1.2rem; font-weight: 700; margin-bottom: 12px; }
    .modal-body { font-size: 0.9rem; color: var(--text-muted); margin-bottom: 20px; }
    .input-field {
      width: 100%; padding: 10px 14px; background: rgba(15, 23, 42, 0.8);
      border: 1px solid var(--card-border); border-radius: 8px; color: #fff;
      font-size: 0.95rem; margin-top: 8px; outline: none;
    }
    .input-field:focus { border-color: var(--accent); }
    .modal-footer { display: flex; justify-content: flex-end; gap: 10px; }

    /* Toast */
    #toast {
      position: fixed; bottom: 24px; right: 24px; background: #1e293b;
      border: 1px solid var(--card-border); border-left: 4px solid var(--accent);
      padding: 12px 20px; border-radius: 8px; color: #fff; font-size: 0.9rem;
      box-shadow: 0 6px 20px rgba(0,0,0,0.4); transform: translateY(100px);
      transition: all 0.3s; z-index: 2000;
    }
    #toast.show { transform: translateY(0); }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="brand">
        <div class="brand-icon">🛡️</div>
        <div>
          <h1 class="brand-title">WireGuard IoT VPN Manager<span class="brand-version">v__VERSION__</span></h1>
          <div class="brand-sub">오라클 클라우드 ESP32 VPN 자동 프로비저닝 관리 콘솔</div>
        </div>
      </div>
      <div class="header-actions">
        <label class="auto-refresh">
          <input type="checkbox" id="autoRefresh" checked> 5초 자동 갱신
        </label>
        <button class="btn btn-outline btn-sm" onclick="fetchData()">🔄 새로고침</button>
        <button class="btn btn-primary btn-sm" onclick="openTokenModal()">🔑 토큰 관리</button>
        <button class="btn btn-outline btn-sm" onclick="logout()">로그아웃</button>
      </div>
    </header>

    <!-- Stats Grid -->
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">등록된 전체 장비</div>
        <div class="stat-value" id="statTotal">0 <span class="stat-unit">대</span></div>
      </div>
      <div class="stat-card">
        <div class="stat-label">실시간 온라인 피어 (접속 중)</div>
        <div class="stat-value" style="color: var(--green);" id="statOnline">0 <span class="stat-unit">대</span></div>
      </div>
      <div class="stat-card">
        <div class="stat-label">VPN IP 풀 사용량 (10.10.0.X)</div>
        <div class="stat-value" id="statPool">0 / 0 <span class="stat-unit">할당됨</span></div>
      </div>
    </div>

    <!-- Device List Table -->
    <div class="card">
      <div class="card-header">
        <div class="card-title">📱 등록된 ESP32 / IoT 단말 목록</div>
        <div class="filters">
          <input type="search" id="searchInput" class="filter-input" placeholder="이름 / MAC / IP 검색" oninput="renderDevices()">
          <select id="statusFilter" class="filter-input" onchange="renderDevices()">
            <option value="all">전체</option>
            <option value="online">온라인</option>
            <option value="offline">오프라인</option>
            <option value="revoked">차단</option>
          </select>
          <span style="font-size: 0.85rem; color: var(--text-muted);" id="lastUpdated">업데이트 중...</span>
        </div>
      </div>
      <div class="table-responsive">
        <table>
          <thead>
            <tr>
              <th>접속 상태</th>
              <th>기기 MAC 주소</th>
              <th>할당된 VPN IP</th>
              <th>기기명</th>
              <th>FW 버전</th>
              <th>트래픽 (Rx / Tx)</th>
              <th>최근 핸드셰이크</th>
              <th>관리 (마우스 클릭)</th>
            </tr>
          </thead>
          <tbody id="deviceTableBody">
            <tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 40px;">데이터를 불러오는 중입니다...</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </div>

  <!-- Token Modal -->
  <div class="modal-overlay" id="tokenModal">
    <div class="modal">
      <div class="modal-title">🔑 등록 인증 토큰(Token) 관리</div>
      <div class="modal-body">
        <p style="margin-bottom: 12px;">ESP32 펌웨어의 <code>auth_token</code>에 등록할 비밀 인증키 목록입니다.</p>
        <div id="tokenList" style="margin-bottom: 16px;"></div>
        <button class="btn btn-primary btn-sm" onclick="generateNewToken()">+ 새 토큰 생성하기</button>
      </div>
      <div class="modal-footer">
        <button class="btn btn-outline" onclick="closeTokenModal()">닫기</button>
      </div>
    </div>
  </div>

  <!-- Auth Prompt Modal -->
  <div class="modal-overlay" id="authModal">
    <div class="modal">
      <div class="modal-title">🔒 관리자 인증 필요</div>
      <div class="modal-body">
        <p>관리자 작업을 위해 발급된 <strong>인증 토큰(Enrollment Token)</strong>을 입력해 주세요.</p>
        <input type="password" id="authTokenInput" class="input-field" placeholder="Bearer 토큰 입력...">
      </div>
      <div class="modal-footer">
        <button class="btn btn-primary" onclick="saveAuthToken()">대시보드 로그인</button>
      </div>
    </div>
  </div>

  <div id="toast"></div>

  <script>
    let token = localStorage.getItem('wg_admin_token') || '';

    function showToast(msg, isError = false) {
      const toast = document.getElementById('toast');
      toast.textContent = msg;
      toast.style.borderLeftColor = isError ? 'var(--red)' : 'var(--accent)';
      toast.classList.add('show');
      setTimeout(() => toast.classList.remove('show'), 3500);
    }

    function checkAuth() {
      if (!token) {
        document.getElementById('authModal').classList.add('active');
        return false;
      }
      return true;
    }

    function saveAuthToken() {
      const input = document.getElementById('authTokenInput').value.trim();
      if (!input) return;
      token = input;
      localStorage.setItem('wg_admin_token', token);
      document.getElementById('authModal').classList.remove('active');
      fetchData();
    }

    function logout() {
      localStorage.removeItem('wg_admin_token');
      token = '';
      document.getElementById('authModal').classList.add('active');
    }

    function formatBytes(bytes) {
      if (!bytes || bytes === 0) return '0 B';
      const k = 1024;
      const sizes = ['B', 'KB', 'MB', 'GB'];
      const i = Math.floor(Math.log(bytes) / Math.log(k));
      return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
    }

    function timeAgo(epochSec) {
      if (!epochSec || epochSec === 0) return '기록 없음';
      const now = Math.floor(Date.now() / 1000);
      const diff = now - epochSec;
      if (diff < 10) return '방금 전';
      if (diff < 60) return diff + '초 전';
      if (diff < 3600) return Math.floor(diff / 60) + '분 전';
      if (diff < 86400) return Math.floor(diff / 3600) + '시간 전';
      return Math.floor(diff / 86400) + '일 전';
    }

    async function fetchData() {
      if (!checkAuth()) return;
      try {
        const res = await fetch('/api/admin/devices', {
          headers: { 'Authorization': 'Bearer ' + token }
        });
        if (res.status === 401) {
          showToast('인증 토큰이 유효하지 않습니다.', true);
          logout();
          return;
        }
        const data = await res.json();
        renderDashboard(data);
        document.getElementById('lastUpdated').textContent = '마지막 동기화: ' + new Date().toLocaleTimeString();
      } catch (e) {
        showToast('데이터 조회 실패: ' + e.message, true);
      }
    }

    let lastData = { devices: [] };

    function renderDashboard(data) {
      lastData = data;
      const devs = data.devices || [];
      const pool = data.pool || { used: 0, total: 0 };
      
      document.getElementById('statTotal').innerHTML = `${devs.length} <span class="stat-unit">대</span>`;
      const onlineCount = devs.filter(d => d.is_online).length;
      document.getElementById('statOnline').innerHTML = `${onlineCount} <span class="stat-unit">대</span>`;
      document.getElementById('statPool').innerHTML = `${pool.used} / ${pool.total} <span class="stat-unit">할당됨</span>`;

      renderDevices();
    }

    function matchesFilter(d, query, status) {
      if (status === 'online' && !d.is_online) return false;
      if (status === 'offline' && (d.is_online || d.status === 'revoked')) return false;
      if (status === 'revoked' && d.status !== 'revoked') return false;
      if (!query) return true;
      return [d.name, d.mac, d.ip].some(v => (v || '').toLowerCase().includes(query));
    }

    // Table only; the search box and status filter survive the 5 s auto refresh
    function renderDevices() {
      const all = lastData.devices || [];
      const query = document.getElementById('searchInput').value.trim().toLowerCase();
      const status = document.getElementById('statusFilter').value;
      const devs = all.filter(d => matchesFilter(d, query, status));

      const tbody = document.getElementById('deviceTableBody');
      if (devs.length === 0 && all.length > 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 40px;">검색 결과가 없습니다.</td></tr>';
        return;
      }
      if (devs.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align: center; color: var(--text-muted); padding: 40px;">등록된 IoT 기기가 없습니다.</td></tr>';
        return;
      }

      tbody.innerHTML = devs.map(d => {
        let statusBadge = '';
        if (d.status === 'revoked') {
          statusBadge = '<span class="badge badge-revoked"><span class="pulse-dot"></span> 차단됨</span>';
        } else if (d.status === 'reset') {
          statusBadge = '<span class="badge badge-reset"><span class="pulse-dot"></span> 리셋 대기</span>';
        } else if (d.is_online) {
          statusBadge = '<span class="badge badge-online"><span class="pulse-dot"></span> 온라인</span>';
        } else {
          statusBadge = '<span class="badge badge-offline">오프라인</span>';
        }

        const traffic = `${formatBytes(d.rx_bytes)} / ${formatBytes(d.tx_bytes)}`;
        const handshakeText = timeAgo(d.latest_handshake);

        return `
          <tr>
            <td>${statusBadge}</td>
            <td><span class="mac-tag">${d.mac}</span></td>
            <td><a class="ip-tag" href="http://${escapeHtml(d.ip)}/" target="_blank" rel="noopener" title="VPN 연결 상태에서 기기 웹페이지 열기">${escapeHtml(d.ip)}</a></td>
            <td><strong>${escapeHtml(d.name || '-')}</strong></td>
            <td><code>${escapeHtml(d.firmware || '-')}</code></td>
            <td style="font-family: monospace; font-size: 0.85rem;">${traffic}</td>
            <td style="color: var(--text-muted); font-size: 0.85rem;">${handshakeText}</td>
            <td>
              <div class="actions-cell">
                <button class="btn btn-sm btn-reset" title="새 펌웨어 등록 허용" onclick="actionDevice('reset', '${d.mac}')">🔄 리셋</button>
                <button class="btn btn-sm btn-delete" title="IP 회수 및 완전 제거" onclick="actionDevice('delete', '${d.mac}')">🗑️ 삭제</button>
                ${d.status !== 'revoked'
                  ? `<button class="btn btn-sm btn-revoke" title="기기 차단" onclick="actionDevice('revoke', '${d.mac}')">⛔ 차단</button>`
                  : `<button class="btn btn-sm btn-unrevoke" title="차단 해제 (ESP32 재부팅 시 같은 IP 로 재연결)" onclick="actionDevice('unrevoke', '${d.mac}')">✅ 차단 해제</button>`}
              </div>
            </td>
          </tr>
        `;
      }).join('');
    }

    function escapeHtml(str) {
      return (str || '').replace(/[&<>"']/g, m => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[m]);
    }

    async function actionDevice(action, mac) {
      let confirmMsg = '';
      if (action === 'reset') confirmMsg = `[${mac}] 기기를 리셋하시겠습니까?\\n(할당된 IP는 보존되며 새 공개키로 다시 등록할 수 있게 됩니다)`;
      if (action === 'delete') confirmMsg = `[${mac}] 기기를 완전히 삭제하시겠습니까?\\n(할당된 IP가 풀에 반환되고 WireGuard 피어가 제거됩니다)`;
      if (action === 'revoke') confirmMsg = `[${mac}] 기기를 즉시 차단하시겠습니까?\\n(WireGuard 통신이 중단됩니다)`;

      if (action === 'unrevoke') confirmMsg = `[${mac}] 기기의 차단을 해제하시겠습니까?\\n(ESP32 를 재부팅하면 같은 IP 로 다시 연결됩니다)`;

      if (!confirm(confirmMsg)) return;

      // unblocking is a reset on the server: the device re-enrolls with the same IP on its next boot
      const endpoint = action === 'unrevoke' ? 'reset' : action;
      try {
        const res = await fetch(`/api/admin/${endpoint}`, {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ mac: mac })
        });
        const result = await res.json();
        if (res.ok) {
          showToast(action === 'unrevoke'
            ? `${mac} 차단이 해제되었습니다. ESP32 를 재부팅하면 다시 연결됩니다.`
            : (result.message || '작업이 완료되었습니다.'));
          fetchData();
        } else {
          showToast('작업 실패: ' + (result.error || '오류 발생'), true);
        }
      } catch (e) {
        showToast('통신 오류: ' + e.message, true);
      }
    }

    async function openTokenModal() {
      if (!checkAuth()) return;
      document.getElementById('tokenModal').classList.add('active');
      try {
        const res = await fetch('/api/admin/tokens', {
          headers: { 'Authorization': 'Bearer ' + token }
        });
        const data = await res.json();
        const listDiv = document.getElementById('tokenList');
        listDiv.innerHTML = (data.tokens || []).map(t => `
          <div style="display: flex; justify-content: space-between; align-items: center; background: rgba(15,23,42,0.6); padding: 8px 12px; border-radius: 6px; margin-bottom: 6px; font-family: monospace; font-size: 0.85rem;">
            <span>${t}</span>
            <div style="display: flex; gap: 6px;">
              <button class="btn btn-outline btn-sm" onclick="copyText('${t}')">복사</button>
              <button class="btn btn-sm btn-delete" onclick="removeToken('${t}')">삭제</button>
            </div>
          </div>
        `).join('');
      } catch (e) {
        showToast('토큰 조회 실패: ' + e.message, true);
      }
    }

    function closeTokenModal() {
      document.getElementById('tokenModal').classList.remove('active');
    }

    async function generateNewToken() {
      try {
        const res = await fetch('/api/admin/tokens/new', {
          method: 'POST',
          headers: { 'Authorization': 'Bearer ' + token }
        });
        const data = await res.json();
        if (res.ok) {
          showToast('새 토큰이 생성되었습니다!');
          openTokenModal();
        } else {
          showToast('생성 실패: ' + data.error, true);
        }
      } catch (e) {
        showToast('오류: ' + e.message, true);
      }
    }

    async function removeToken(t) {
      if (!confirm(`토큰 [${t.slice(0, 6)}...] 을(를) 삭제하시겠습니까?
(이 토큰이 들어간 ESP32 는 더 이상 새로 등록할 수 없습니다)`)) return;
      try {
        const res = await fetch('/api/admin/tokens/remove', {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ token: t })
        });
        const data = await res.json();
        if (res.ok) {
          showToast(data.message || '토큰이 삭제되었습니다.');
          if (t === token) {
            // the token this dashboard logged in with is gone
            closeTokenModal();
            logout();
            return;
          }
          openTokenModal();
        } else {
          showToast('삭제 실패: ' + data.error, true);
        }
      } catch (e) {
        showToast('오류: ' + e.message, true);
      }
    }

    function copyText(str) {
      navigator.clipboard.writeText(str).then(() => showToast('클립보드에 복사되었습니다!'));
    }

    // Auto refresh
    setInterval(() => {
      if (document.getElementById('autoRefresh').checked) {
        fetchData();
      }
    }, 5000);

    // Initial load
    if (token) {
      fetchData();
    } else {
      document.getElementById('authModal').classList.add('active');
    }
  </script>
</body>
</html>
"""


# ---- HTTP API & Web Dashboard Handler ----

class EnrollHandler(BaseHTTPRequestHandler):
    server_version = f"wg-enroll-dashboard/{VERSION}"
    sys_version = ""
    timeout = 15

    def log_message(self, fmt, *args):
        log(f"{self.client_address[0]} {fmt % args}")

    def reply(self, status, obj):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def reply_html(self, status, html_content):
        body = html_content.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def check_admin_token(self):
        cfg = self.server.cfg
        auth = self.headers.get("Authorization", "")
        token = auth[7:] if auth.startswith("Bearer ") else ""
        if not token or not any(secrets.compare_digest(token, t) for t in current_tokens(cfg)):
            return False
        return True

    def rate_limited(self):
        cfg = self.server.cfg
        ip = self.client_address[0]
        t = time.monotonic()
        with rate_lock:
            hits = [h for h in rate_hits.get(ip, []) if t - h < 60]
            hits.append(t)
            rate_hits[ip] = hits
            return len(hits) > cfg.get("rate_limit_per_min", 30)

    def do_GET(self):
        # 1. Web Admin Dashboard HTML
        if self.path in ("/", "/admin", "/index.html"):
            return self.reply_html(200, DASHBOARD_HTML.replace("__VERSION__", VERSION))

        # 2. REST API: Device List & WG Live Stats
        if self.path == "/api/admin/devices":
            if not self.check_admin_token():
                return self.reply(401, {"error": "unauthorized"})

            cfg = self.server.cfg
            db = load_json(cfg["db"], {})
            wg_stats = get_wg_stats(cfg)
            now_epoch = int(time.time())

            devices = []
            for mac, d in sorted(db.items(), key=lambda kv: ipaddress.IPv4Address(kv[1]["ip"])):
                pub = d.get("public_key")
                stat = wg_stats.get(pub, {}) if pub else {}
                handshake = stat.get("latest_handshake", 0)
                # Online if handshake occurred within last 180 seconds
                is_online = (pub is not None) and (not d.get("revoked")) and (handshake > 0) and (now_epoch - handshake < 180)

                status = "revoked" if d.get("revoked") else ("active" if pub else "reset")
                devices.append({
                    "mac": mac,
                    "ip": d.get("ip"),
                    "name": d.get("name", ""),
                    "firmware": d.get("firmware", ""),
                    "enrolled_at": d.get("enrolled_at", ""),
                    "last_seen": d.get("last_seen", ""),
                    "status": status,
                    "is_online": is_online,
                    "latest_handshake": handshake,
                    "rx_bytes": stat.get("rx_bytes", 0),
                    "tx_bytes": stat.get("tx_bytes", 0),
                    "endpoint": stat.get("endpoint", ""),
                })

            start = ipaddress.IPv4Address(cfg["pool_start"])
            end = ipaddress.IPv4Address(cfg["pool_end"])
            pool_total = int(end) - int(start) + 1

            return self.reply(200, {
                "devices": devices,
                "pool": {
                    "start": cfg["pool_start"],
                    "end": cfg["pool_end"],
                    "total": pool_total,
                    "used": len(db)
                },
                "tokens_count": len(current_tokens(cfg))
            })

        # 3. REST API: Get Tokens
        if self.path == "/api/admin/tokens":
            if not self.check_admin_token():
                return self.reply(401, {"error": "unauthorized"})
            return self.reply(200, {"tokens": current_tokens(self.server.cfg)})

        self.reply(404, {"error": "not_found"})

    def do_POST(self):
        cfg = self.server.cfg

        # 1. ESP32 Auto Enrollment (Original Logic 100% Preserved)
        if self.path == "/api/enroll":
            if self.rate_limited():
                log(f"{self.client_address[0]} rate limited")
                return self.reply(429, {"error": "rate_limited"})

            auth = self.headers.get("Authorization", "")
            token = auth[7:] if auth.startswith("Bearer ") else ""
            if not token or not any(secrets.compare_digest(token, t) for t in current_tokens(cfg)):
                log(f"{self.client_address[0]} invalid token")
                return self.reply(401, {"error": "invalid_token"})

            try:
                length = int(self.headers.get("Content-Length", "0"))
                if not 0 < length <= MAX_BODY:
                    raise ValueError("size")
                req = json.loads(self.rfile.read(length))
                mac = str(req["mac"]).upper()
                pub = str(req["public_key"])
                name = str(req.get("name", ""))[:32]
                fw = str(req.get("firmware", ""))[:32]
                if not MAC_RE.match(mac) or not KEY_RE.match(pub):
                    raise ValueError("format")
            except (ValueError, KeyError, TypeError, json.JSONDecodeError):
                return self.reply(400, {"error": "bad_request"})

            with db_lock:
                db = load_json(cfg["db"], {})
                dev = db.get(mac)

                if dev and dev.get("revoked"):
                    log(f"{mac} rejected: revoked")
                    return self.reply(403, {"error": "revoked"})
                if dev and dev.get("public_key") and dev["public_key"] != pub:
                    log(f"{mac} rejected: registered with another key (run: wg_enroll.py reset {mac})")
                    return self.reply(409, {"error": "mac_registered_with_other_key"})
                if any(m != mac and d.get("public_key") == pub for m, d in db.items()):
                    log(f"{mac} rejected: public key already used by another device")
                    return self.reply(409, {"error": "key_in_use"})

                if dev is None:
                    ip = allocate_ip(cfg, db)
                    if ip is None:
                        log(f"{mac} rejected: IP pool exhausted")
                        return self.reply(503, {"error": "pool_exhausted"})
                    dev = {"ip": ip, "enrolled_at": now()}
                    db[mac] = dev
                if dev.get("public_key") != pub:
                    # new device, or re-enrollment after `reset`
                    dev["public_key"] = pub
                    dev["preshared_key"] = new_psk()
                    dev["enrolled_at"] = now()
                    log(f"{mac} enrolled: {dev['ip']} name={name!r} fw={fw}")
                dev["name"] = name
                dev["firmware"] = fw
                dev["last_seen"] = now()

                try:
                    apply_peer(cfg, dev)
                    server_key = server_public_key(cfg)
                except subprocess.CalledProcessError as e:
                    log(f"{mac} wg error: {e.stderr.strip()}")
                    return self.reply(500, {"error": "wg_failed"})
                save_json(cfg["db"], db)

            return self.reply(200, {
                "ip": dev["ip"],
                "netmask": cfg["netmask"],
                "server_public_key": server_key,
                "preshared_key": dev["preshared_key"],
                "endpoint": cfg["endpoint"],
                "port": cfg["endpoint_port"],
                "keepalive": cfg["keepalive"],
            })

        # 2. Admin Actions via Web Dashboard
        if self.path.startswith("/api/admin/"):
            if not self.check_admin_token():
                return self.reply(401, {"error": "unauthorized"})

            req = {}
            try:
                length = int(self.headers.get("Content-Length", "0"))
                if length > 0:
                    req = json.loads(self.rfile.read(length))
            except Exception:
                pass

            action = self.path[len("/api/admin/"):]

            # Action: Reset device
            if action == "reset":
                mac = normalize_mac(req.get("mac", ""))
                with db_lock:
                    db = load_json(cfg["db"], {})
                    dev = db.get(mac)
                    if not dev:
                        return self.reply(404, {"error": f"미등록 기기: {mac}"})
                    remove_peer(cfg, dev.get("public_key"))
                    dev.update(public_key=None, preshared_key=None, revoked=False)
                    save_json(cfg["db"], db)
                log(f"admin web reset: {mac}")
                return self.reply(200, {"ok": True, "message": f"{mac} 기기가 리셋되었습니다. 새 키로 재등록이 가능합니다."})

            # Action: Delete device
            if action == "delete":
                mac = normalize_mac(req.get("mac", ""))
                with db_lock:
                    db = load_json(cfg["db"], {})
                    dev = db.pop(mac, None)
                    if not dev:
                        return self.reply(404, {"error": f"미등록 기기: {mac}"})
                    remove_peer(cfg, dev.get("public_key"))
                    save_json(cfg["db"], db)
                log(f"admin web delete: {mac} (freed {dev['ip']})")
                return self.reply(200, {"ok": True, "message": f"{mac} 기기가 삭제되었습니다. ({dev['ip']} 반환 완료)"})

            # Action: Revoke device
            if action == "revoke":
                mac = normalize_mac(req.get("mac", ""))
                with db_lock:
                    db = load_json(cfg["db"], {})
                    dev = db.get(mac)
                    if not dev:
                        return self.reply(404, {"error": f"미등록 기기: {mac}"})
                    remove_peer(cfg, dev.get("public_key"))
                    dev["revoked"] = True
                    save_json(cfg["db"], db)
                log(f"admin web revoke: {mac}")
                return self.reply(200, {"ok": True, "message": f"{mac} 기기가 차단되었습니다."})

            # Action: Generate New Token
            if action == "tokens/new":
                token = secrets.token_urlsafe(24)
                edit_tokens(cfg, lambda tokens: tokens.append(token))
                log(f"admin web new token created")
                return self.reply(200, {"ok": True, "token": token})

            # Action: Remove Token
            if action == "tokens/remove":
                target = req.get("token", "") if isinstance(req, dict) else ""

                def remove(tokens):
                    if target not in tokens:
                        return 404, "없는 토큰입니다."
                    if len(tokens) <= 1:
                        # with no token left, neither devices nor this dashboard could log in
                        return 400, "마지막 토큰은 삭제할 수 없습니다."
                    tokens.remove(target)
                    return 200, None

                status, error = edit_tokens(cfg, remove)
                if error:
                    return self.reply(status, {"error": error})
                log(f"admin web token removed: {target[:6]}...")
                return self.reply(200, {"ok": True, "message": "토큰이 삭제되었습니다."})

            return self.reply(404, {"error": "unknown_admin_action"})

        self.reply(404, {"error": "not_found"})


class EnrollServer(ThreadingHTTPServer):
    def finish_request(self, request, client_address):
        # TLS handshake runs here, in the per-connection thread and with a timeout,
        # so a client that connects and goes silent cannot block accept() for everyone
        request.settimeout(EnrollHandler.timeout)
        try:
            request.do_handshake()
        except OSError as e:
            log(f"{client_address[0]} TLS handshake failed: {e}")
            return
        super().finish_request(request, client_address)


def cmd_serve(cfg):
    restore_peers(cfg)
    httpd = EnrollServer(("0.0.0.0", cfg["listen_port"]), EnrollHandler)
    httpd.cfg = cfg
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(cfg["cert"], cfg["key"])
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True, do_handshake_on_connect=False)
    log(f"wg_enroll v{VERSION} listening on https://0.0.0.0:{cfg['listen_port']}/ (Dashboard) and /api/enroll")
    httpd.serve_forever()


# ---- admin CLI commands ----

def normalize_mac(mac):
    mac = mac.upper().replace("-", ":")
    if not MAC_RE.match(mac):
        sys.exit(f"invalid MAC: {mac} (expected AA:BB:CC:DD:EE:FF)")
    return mac


def cmd_list(cfg):
    db = load_json(cfg["db"], {})
    if not db:
        print("(no devices)")
        return
    print(f"{'MAC':17}  {'IP':13}  {'STATUS':8}  {'NAME':20}  {'FW':8}  {'ENROLLED':19}  LAST SEEN")
    for mac, d in sorted(db.items(), key=lambda kv: ipaddress.IPv4Address(kv[1]["ip"])):
        status = "revoked" if d.get("revoked") else ("active" if d.get("public_key") else "reset")
        print(f"{mac:17}  {d['ip']:13}  {status:8}  {d.get('name', ''):20}  {d.get('firmware', ''):8}  "
              f"{d.get('enrolled_at', ''):19}  {d.get('last_seen', '')}")


def cmd_revoke(cfg, mac):
    mac = normalize_mac(mac)
    with db_lock:
        db = load_json(cfg["db"], {})
        dev = db.get(mac) or sys.exit(f"unknown device {mac}")
        remove_peer(cfg, dev.get("public_key"))
        dev["revoked"] = True
        save_json(cfg["db"], db)
    print(f"{mac} revoked, peer removed ({dev['ip']} stays reserved; `reset` to allow it again)")


def cmd_reset(cfg, mac):
    mac = normalize_mac(mac)
    with db_lock:
        db = load_json(cfg["db"], {})
        dev = db.get(mac) or sys.exit(f"unknown device {mac}")
        remove_peer(cfg, dev.get("public_key"))
        dev.update(public_key=None, preshared_key=None, revoked=False)
        save_json(cfg["db"], db)
    print(f"{mac} reset: it can enroll again with a new key and will keep {dev['ip']}")


def cmd_delete(cfg, mac):
    mac = normalize_mac(mac)
    with db_lock:
        db = load_json(cfg["db"], {})
        dev = db.pop(mac, None) or sys.exit(f"unknown device {mac}")
        remove_peer(cfg, dev.get("public_key"))
        save_json(cfg["db"], db)
    print(f"{mac} deleted, {dev['ip']} is free again")


def cmd_token_new(cfg):
    token = secrets.token_urlsafe(24)
    cfg["tokens"].append(token)
    save_json(CONFIG_PATH, cfg)
    print(token)
    print("added. (the running server picks it up immediately)")


def cmd_token_remove(cfg, token):
    if token not in cfg["tokens"]:
        sys.exit("token not found")
    cfg["tokens"].remove(token)
    save_json(CONFIG_PATH, cfg)
    print("removed. (the running server stops accepting it immediately)")


def main():
    p = argparse.ArgumentParser(description="WireGuard enrollment & Web Admin Dashboard service for ESP32 devices")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve")
    sub.add_parser("list")
    sub.add_parser("revoke").add_argument("mac")
    sub.add_parser("reset").add_argument("mac")
    sub.add_parser("delete").add_argument("mac")
    sub.add_parser("token-new")
    sub.add_parser("token-remove").add_argument("token")
    args = p.parse_args()

    cfg = load_config()
    if args.cmd == "serve":
        cmd_serve(cfg)
    elif args.cmd == "list":
        cmd_list(cfg)
    elif args.cmd == "revoke":
        cmd_revoke(cfg, args.mac)
    elif args.cmd == "reset":
        cmd_reset(cfg, args.mac)
    elif args.cmd == "delete":
        cmd_delete(cfg, args.mac)
    elif args.cmd == "token-new":
        cmd_token_new(cfg)
    elif args.cmd == "token-remove":
        cmd_token_remove(cfg, args.token)


if __name__ == "__main__":
    main()
