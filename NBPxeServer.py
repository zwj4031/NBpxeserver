#!/usr/bin/env python
# -*- coding: utf-8 -*-
from nb_pxe_init import dynamic
import socket
import struct
import sys
import threading
# ================= Nuitka/打包 修复补丁开始 =================
# 修复 Nuitka 使用 --windows-disable-console 打包后
# sys.stdout 和 sys.stderr 为 None 导致的 print() 崩溃问题
class NullWriter:
    def write(self, data):
        pass
    def flush(self):
        pass
    def isatty(self):
        return False

if sys.stdout is None:
    sys.stdout = NullWriter()

if sys.stderr is None:
    sys.stderr = NullWriter()
# ================= Nuitka/打包 修复补丁结束 =================
import time
import os
import configparser
import http.server
import socketserver
import functools
import subprocess
import queue
import uuid
import random
from concurrent.futures import ThreadPoolExecutor
from collections import deque

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from urllib.parse import urlparse, parse_qs

from nb_pxe_init import option as dhcp_option_handler
from nb_pxe_init.option import EXAMPLE_OPTIONS
from nb_pxe_init.client import ClientManager

# ... (log_message, INI_FILENAME, SETTINGS, get_mac_address, get_all_ips, etc. 保持不变) ...
log_queue = queue.Queue()
LOG_FILENAME = 'nbpxe.log'
# 文件: NBPxeServer.py

# ...
ip_to_mac_map = {}
ip_map_lock = threading.Lock()

# =======================[ 新增：失败日志聚合器 ]=======================
failure_aggregator = {}
aggregator_lock = threading.Lock()
stop_aggregator_event = threading.Event()
# =======================[ 修改结束 ]=======================

client_manager = None
# ...

def log_message(message, level='INFO'):
    log_levels = {'DEBUG': 0, 'INFO': 1, 'WARNING': 2, 'ERROR': 3}
    display_level = log_levels.get('DEBUG', 1) 

    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    full_log_entry = f"[{timestamp}] [{level}] {message}"
    try:
        with open(LOG_FILENAME, 'a', encoding='utf-8') as f:
            f.write(full_log_entry + '\n')
    except Exception as e:
        print(f"[CRITICAL LOG ERROR] Failed to write to {LOG_FILENAME}: {e}")
    
    if log_levels.get(level, 1) >= display_level:
        log_queue.put((message, level))

INI_FILENAME = 'NBpxe.ini'
config = configparser.ConfigParser(interpolation=None)
SETTINGS = {}
ARCH_TYPES = {0: 'bios', 6: 'uefi32', 7: 'uefi64', 9: 'uefi64'}

def get_mac_address():
    try:
        mac_num = uuid.getnode()
        mac = mac_num.to_bytes(6, 'big')
        return mac
    except:
        return os.urandom(6)

def get_all_ips():
    ips = ['127.0.0.1']
    try:
        # 使用您最初文件中的方法来获取所有IP地址
        _, _, ip_list = socket.gethostbyname_ex(socket.gethostname())
        ips.extend(ip_list)
    except socket.gaierror:
        # 保持纯本地，不进行任何网络连接尝试
        pass

    # 定义一个已知虚拟网卡/特殊用途IP地址前缀的“黑名单”
    # VMWare, VirtualBox, Hyper-V, WSL, Docker等常用网段
    VIRTUAL_NET_PREFIXES = [
        '192.168.56.', '192.168.64.', '192.168.80.', '192.168.88.', 
        '192.168.122.', '192.168.233.', '192.168.48.', '192.168.177.',
        '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.',
        '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
        '172.29.', '172.30.', '172.31.'
    ]

    def sort_key(ip):
        """
        排序函数，严格按照您的要求：
        1. 虚拟网卡和特殊地址优先级最低。
        2. 然后按标准私有网段排序。
        """
        # 优先级 1: 检查是否为特殊地址或在“黑名单”中
        if ip in ['127.0.0.1']:
            return 100 # 最低优先级
        
        for prefix in VIRTUAL_NET_PREFIXES:
            if ip.startswith(prefix):
                return 50 # 虚拟网卡，次低优先级

        # 优先级 2: 标准私有网段排序 (物理网卡)
        if ip.startswith('192.168.'):
            return 0 # 最高优先级
        elif ip.startswith('172.'):
            try:
                if 16 <= int(ip.split('.')[1]) <= 31:
                    return 1 # 次高优先级
            except (ValueError, IndexError):
                pass
        elif ip.startswith('10.'):
            return 2 # 普通优先级
        
        # 其他所有IP（如公网IP）优先级较低
        return 90

    # 使用排序键对去重后的IP列表进行排序，并为GUI添加 '0.0.0.0' 选项
    # 0.0.0.0 (所有网卡) 作为一个特殊选项，手动添加到列表最前面
    sorted_ips = sorted(list(set(ips)), key=sort_key)
    if '0.0.0.0' not in sorted_ips:
        sorted_ips.append('0.0.0.0') # 确保它存在，但排序后会在后面
        
    return sorted(list(set(ips)), key=sort_key)
    ips = ['127.0.0.1', '0.0.0.0'] # 0.0.0.0 仅用于GUI显示，需要被排到后面
    try:
        _, _, ip_list = socket.gethostbyname_ex(socket.gethostname())
        ips.extend(ip_list)
    except socket.gaierror:
        pass

    # 已知的虚拟网卡/特殊用途IP地址前缀列表
    # VMWare, VirtualBox, Hyper-V, WSL, Docker等常用网段
    VIRTUAL_NET_PREFIXES = [
        '192.168.56.', '192.168.64.', '192.168.80.', '192.168.88.', 
        '192.168.122.', '192.168.233.',
        '172.17.', '172.18.', '172.19.', '172.20.', '172.21.', '172.22.',
        '172.23.', '172.24.', '172.25.', '172.26.', '172.27.', '172.28.',
        '172.29.', '172.30.', '172.31.'
    ]

    def sort_key(ip):
        """
        排序函数，严格按照您的要求：
        1. 虚拟网卡和特殊地址优先级最低。
        2. 然后按标准私有网段排序。
        """
        # 优先级 1: 检查是否为特殊地址或已知虚拟网卡
        if ip in ['0.0.0.0', '127.0.0.1']:
            return 100 # 最低优先级
        
        for prefix in VIRTUAL_NET_PREFIXES:
            if ip.startswith(prefix):
                return 50 # 虚拟网卡，次低优先级

        # 优先级 2: 标准私有网段排序
        if ip.startswith('192.168.'):
            return 0 # 最高优先级
        elif ip.startswith('172.'):
            try:
                # 确保是 172.16.0.0 - 172.31.255.255 范围
                if 16 <= int(ip.split('.')[1]) <= 31:
                    return 1 # 次高优先级
            except (ValueError, IndexError):
                pass
        elif ip.startswith('10.'):
            return 2 # 普通优先级
        
        # 其他所有IP（如公网IP）优先级较低
        return 90

    # 使用新的排序键对去重后的IP列表进行排序
    return sorted(list(set(ips)), key=sort_key)
    ips = ['127.0.0.1']
    try:
        _, _, ip_list = socket.gethostbyname_ex(socket.gethostname())
        ips.extend(ip_list)
    except socket.gaierror:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.1)
                s.connect(("8.8.8.8", 80))
                ips.append(s.getsockname()[0])
        except Exception:
            pass
    def sort_key(ip):
        if ip.startswith('192.168.'): return 0
        if ip.startswith('172.'):
            try:
                if 16 <= int(ip.split('.')[1]) <= 31: return 1
            except (ValueError, IndexError): pass
        if ip.startswith('10.'): return 2
        if ip == '127.0.0.1': return 100
        return 3
    return sorted(list(set(ips)), key=sort_key)

def create_default_ini():
    log_message(f"配置文件 '{INI_FILENAME}' 不存在，正在创建默认配置...")
    all_ips = get_all_ips()
    best_ip = '192.168.1.100'
    if all_ips and all_ips[0] != '127.0.0.1':
        best_ip = all_ips[0]
    config['General'] = {'listen_ip': best_ip, 'server_ip': best_ip}
    try:
        ip_parts = best_ip.split('.'); ip_prefix = ".".join(ip_parts[:-1])
        start_octet = min(int(ip_parts[-1]) + 1, 253)
        pool_start, pool_end = f"{ip_prefix}.{start_octet}", f"{ip_prefix}.254"
    except (ValueError, IndexError):
        pool_start, pool_end = '192.168.1.200', '192.168.1.250'
    config['DHCP'] = {
        'enabled': 'true', 'mode': 'proxy', 'pool_start': pool_start, 'pool_end': pool_end, 'subnet': '255.255.255.0',
        'router': ip_prefix + ".1" if 'ip_prefix' in locals() else '192.168.1.1',
        'dns': ip_prefix + ".1" if 'ip_prefix' in locals() else '192.168.1.1', 'lease_time': '86400'
    }
    config['FileServer'] = {
        'tftp_root': '.', 'http_root': '.', 'smb_root': '.',
        'tftp_enabled': 'true', 'http_enabled': 'true', 'http_port': '80',
        'tftp_multithread': 'true', 'http_multithread': 'true'
    }
    config['BootFiles'] = {'bios': 'ipxe.bios', 'uefi32': 'ipxe32.efi', 'uefi64': 'ipxe.efi', 'ipxe': 'ipxeboot.txt'}
    config['SMB'] = {'enabled': 'false', 'share_name': 'pxe', 'permissions': 'read'}
    config['PXEMenuBIOS'] = {
        'enabled': 'true', 'timeout': '6', 'randomize_timeout': 'false',
        'prompt': 'Press F8 for BIOS Boot Menu',
        'items': f'''; 示例: 菜单文本, 启动文件, 类型(4位Hex), 服务器IP
iPXE (BIOS), ipxe.bios, 8000, %tftpserver%
Boot from Local Disk, , 0000, 0.0.0.0
'''
    }
    config['PXEMenuUEFI'] = {
        'enabled': 'true', 'timeout': '6', 'randomize_timeout': 'false',
        'prompt': 'Press F8 for UEFI Boot Menu',
        'items': f'''; 示例: 菜单文本, 启动文件, 类型(4位Hex), 服务器IP
iPXE (UEFI), ipxe.efi, 8002, %tftpserver%
Windows PE (UEFI), boot/bootmgfw.efi, 8003, %tftpserver%
GRUB4DOS FOR UEFI, g4e.efi, 8004, %tftpserver%
GRUBFM, grubfmx64.efi, 8005, %tftpserver%
Boot from Local Disk, , 0000, 0.0.0.0
'''
    }
    config['PXEMenuIPXE'] = {
        'enabled': 'true', 
        'timeout': '6', 
        'randomize_timeout': 'false',
        'prompt': 'Press F8 for iPXE Boot Menu ...',
        'items': f'''; 示例: 菜单文本, 启动文件, 类型(4位Hex), 服务器IP
iPXEFM(txt), ipxeboot.txt, 8001, %tftpserver%
List Files, %dynamicboot%=ipxefm, 0001, %tftpserver%
Bind PC, %dynamicboot%=whoami, 8002, %tftpserver%
NBPE(WIM), %dynamicboot%=/newbeeplus.wim, 8003, %tftpserver%
NBPE(ISO), %dynamicboot%=/newbeeplus.iso, 8004, %tftpserver%
GRUBFM, %dynamicboot%=/netgrubfm.efi, 8007, %tftpserver%
netboot, https://boot.netboot.xyz, 8005, %tftpserver%
G4E, g4e.efi, 8006, %tftpserver%

'''
    }
    config['DHCPOptions'] = {
        'enabled': 'false',
        'options_text': EXAMPLE_OPTIONS
    }
    with open(INI_FILENAME, 'w', encoding='utf-8') as f: config.write(f)
    log_message(f"默认配置文件 '{INI_FILENAME}' 已创建。")

def load_config_from_ini():
    global SETTINGS
    if not os.path.exists(INI_FILENAME): create_default_ini()
    try:
        config.read(INI_FILENAME, encoding='utf-8')
    except configparser.Error as e:
        log_message(f"配置文件 '{INI_FILENAME}' 解析失败: {e}", "ERROR"); return False
    try:
        g, d, fs, b, s = config['General'], config['DHCP'], config['FileServer'], config['BootFiles'], config['SMB']
        pm_bios, pm_uefi, pm_ipxe = config['PXEMenuBIOS'], config['PXEMenuUEFI'], config['PXEMenuIPXE']
        o = config['DHCPOptions']
        SETTINGS = {
            'listen_ip': g.get('listen_ip', '0.0.0.0'), 'server_ip': g.get('server_ip', get_all_ips()[0]),
            'dhcp_enabled': d.getboolean('enabled', True), 'dhcp_mode': d.get('mode', 'proxy'),
            'ip_pool_start': d.get('pool_start'), 'ip_pool_end': d.get('pool_end'),
            'subnet_mask': d.get('subnet'), 'router_ip': d.get('router'), 'dns_server_ip': d.get('dns'),
            'lease_time': d.getint('lease_time'), 'tftp_root': fs.get('tftp_root'),
            'http_root': fs.get('http_root'), 'smb_root': fs.get('smb_root'),
            'tftp_enabled': fs.getboolean('tftp_enabled'), 'http_enabled': fs.getboolean('http_enabled'),
            'http_port': fs.getint('http_port'), 'tftp_multithread': fs.getboolean('tftp_multithread'),
            'http_multithread': fs.getboolean('http_multithread'), 'bootfile_bios': b.get('bios'),
            'bootfile_uefi32': b.get('uefi32'), 'bootfile_uefi64': b.get('uefi64'), 'bootfile_ipxe': b.get('ipxe'),
            'smb_enabled': s.getboolean('enabled'), 'smb_share_name': s.get('share_name'),
            'smb_permissions': s.get('permissions'), 'pxe_menu_bios_enabled': pm_bios.getboolean('enabled'),
            'pxe_menu_bios_timeout': pm_bios.getint('timeout'),
            'pxe_menu_bios_randomize_timeout': pm_bios.getboolean('randomize_timeout', False),
            'pxe_menu_bios_prompt': pm_bios.get('prompt'),
            'pxe_menu_bios_items': pm_bios.get('items'), 'pxe_menu_uefi_enabled': pm_uefi.getboolean('enabled'),
            'pxe_menu_uefi_timeout': pm_uefi.getint('timeout'),
            'pxe_menu_uefi_randomize_timeout': pm_uefi.getboolean('randomize_timeout', False),
            'pxe_menu_uefi_prompt': pm_uefi.get('prompt'),
            'pxe_menu_uefi_items': pm_uefi.get('items'),
            'pxe_menu_ipxe_enabled': pm_ipxe.getboolean('enabled'),
            'pxe_menu_ipxe_timeout': pm_ipxe.getint('timeout'),
            'pxe_menu_ipxe_randomize_timeout': pm_ipxe.getboolean('randomize_timeout', False),
            'pxe_menu_ipxe_prompt': pm_ipxe.get('prompt'),
            'pxe_menu_ipxe_items': pm_ipxe.get('items'),
            'dhcp_options_enabled': o.getboolean('enabled', False),
            'dhcp_options_text': o.get('options_text', ''),
        }
        dhcp_option_handler.set_global_settings(SETTINGS)
        return True
    except (KeyError, ValueError) as e:
        log_message(f"读取配置文件时发生错误: {e}。请检查 '{INI_FILENAME}' 的格式。", "ERROR"); return False

def save_config_to_ini():
    try:
        g, d, fs, b, s, pm_bios, pm_uefi, pm_ipxe, o = (config['General'], config['DHCP'], config['FileServer'],
                                                  config['BootFiles'], config['SMB'], config['PXEMenuBIOS'],
                                                  config['PXEMenuUEFI'], config['PXEMenuIPXE'], config['DHCPOptions'])
        g['listen_ip'], g['server_ip'] = SETTINGS['listen_ip'], SETTINGS['server_ip']
        d['enabled'], d['mode'] = str(SETTINGS['dhcp_enabled']).lower(), SETTINGS['dhcp_mode']
        d['pool_start'], d['pool_end'] = SETTINGS['ip_pool_start'], SETTINGS['ip_pool_end']
        d['subnet'], d['router'], d['dns'] = SETTINGS['subnet_mask'], SETTINGS['router_ip'], SETTINGS['dns_server_ip']
        d['lease_time'] = str(SETTINGS['lease_time'])
        fs['tftp_root'], fs['http_root'], fs['smb_root'] = SETTINGS['tftp_root'], SETTINGS['http_root'], SETTINGS['smb_root']
        fs['tftp_enabled'], fs['http_enabled'], fs['http_port'] = str(SETTINGS['tftp_enabled']).lower(), str(SETTINGS['http_enabled']).lower(), str(SETTINGS['http_port'])
        fs['tftp_multithread'], fs['http_multithread'] = str(SETTINGS['tftp_multithread']).lower(), str(SETTINGS['http_multithread']).lower()
        b['bios'], b['uefi32'], b['uefi64'], b['ipxe'] = SETTINGS['bootfile_bios'], SETTINGS['bootfile_uefi32'], SETTINGS['bootfile_uefi64'], SETTINGS['bootfile_ipxe']
        s['enabled'], s['share_name'], s['permissions'] = str(SETTINGS['smb_enabled']).lower(), SETTINGS['smb_share_name'], SETTINGS['smb_permissions']
        pm_bios['enabled'], pm_bios['timeout'] = str(SETTINGS['pxe_menu_bios_enabled']).lower(), str(SETTINGS['pxe_menu_bios_timeout'])
        pm_bios['randomize_timeout'] = str(SETTINGS['pxe_menu_bios_randomize_timeout']).lower()
        pm_bios['prompt'], pm_bios['items'] = SETTINGS['pxe_menu_bios_prompt'], SETTINGS['pxe_menu_bios_items']
        pm_uefi['enabled'], pm_uefi['timeout'] = str(SETTINGS['pxe_menu_uefi_enabled']).lower(), str(SETTINGS['pxe_menu_uefi_timeout'])
        pm_uefi['randomize_timeout'] = str(SETTINGS['pxe_menu_uefi_randomize_timeout']).lower()
        pm_uefi['prompt'], pm_uefi['items'] = SETTINGS['pxe_menu_uefi_prompt'], SETTINGS['pxe_menu_uefi_items']
        pm_ipxe['enabled'], pm_ipxe['timeout'] = str(SETTINGS['pxe_menu_ipxe_enabled']).lower(), str(SETTINGS['pxe_menu_ipxe_timeout'])
        pm_ipxe['randomize_timeout'] = str(SETTINGS['pxe_menu_ipxe_randomize_timeout']).lower()
        pm_ipxe['prompt'], pm_ipxe['items'] = SETTINGS['pxe_menu_ipxe_prompt'], SETTINGS['pxe_menu_ipxe_items']
        o['enabled'] = str(SETTINGS['dhcp_options_enabled']).lower()
        o['options_text'] = SETTINGS['dhcp_options_text']
        with open(INI_FILENAME, 'w', encoding='utf-8') as f: config.write(f)
        log_message(f"配置已成功保存到 '{INI_FILENAME}'。")
    except Exception as e: log_message(f"保存配置文件时出错: {e}", "ERROR")

def parse_dhcp_options(pkt_bytes):
    opts = {}
    if len(pkt_bytes) < 240 or pkt_bytes[236:240] != b'\x63\x82\x53\x63': return opts
    i = 240
    while i < len(pkt_bytes):
        code = pkt_bytes[i]; i += 1
        if code == 0: continue
        if code == 255: break
        if i >= len(pkt_bytes): break
        length = pkt_bytes[i]; i += 1
        if i + length > len(pkt_bytes): break
        value = pkt_bytes[i:i + length]; i += length
        opts[code] = value
    return opts

def build_pxe_option43_menu(menu_cfg, tftp_server_ip):
    if not menu_cfg.get('enabled', False): return b''
    menu_items_str = menu_cfg.get('items', '')
    parsed_items, seen_types = [], set()
    for line in menu_items_str.strip().splitlines():
        line = line.strip()
        if not line or line.startswith(';'): continue
        parts = [p.strip() for p in line.split(',', 3)]
        if len(parts) == 4:
            try:
                menu_text, _, type_hex, server_ip_str = parts
                final_server_ip = tftp_server_ip if '%tftpserver%' in server_ip_str.lower() else server_ip_str
                server_type = int(type_hex, 16)
                if server_type in seen_types: continue
                seen_types.add(server_type)
                parsed_items.append({
                    'text': menu_text, 'type_bytes': server_type.to_bytes(2, 'big'),
                    'ip_bytes': socket.inet_aton(final_server_ip)
                })
            except (ValueError, OSError): continue
    if not parsed_items: return b''
    payload = bytearray()
    payload += bytes([6, 1, 0b00000011])
    servers_val = bytearray()
    for item in parsed_items: servers_val += item['type_bytes'] + b'\x01' + item['ip_bytes']
    payload += bytes([8, len(servers_val)]) + servers_val
    menu_val = bytearray()
    for item in parsed_items:
        desc = item['text'].encode('ascii', 'ignore')
        menu_val += item['type_bytes'] + bytes([len(desc)]) + desc
    payload += bytes([9, len(menu_val)]) + menu_val
    max_timeout = menu_cfg.get('timeout', 10)
    if menu_cfg.get('randomize_timeout', False):
        timeout = random.randint(0, max_timeout)
    else:
        timeout = max_timeout
    timeout = max(0, min(255, timeout))
    prompt = menu_cfg.get('prompt', '').encode('ascii', 'ignore') + b'\x00'
    prompt_val = bytes([timeout]) + prompt
    payload += bytes([10, len(prompt_val)]) + prompt_val
    payload += b'\xff'
    return bytes(payload)

def craft_dhcp_response(req_pkt, cfg, assigned_ip='0.0.0.0', is_proxy_req=False):
    if len(req_pkt) < 240: return None
    try:
        xid, chaddr = req_pkt[4:8], req_pkt[28:44]
        client_mac = ":".join(f"{b:02x}" for b in chaddr[:6])
        opts = parse_dhcp_options(req_pkt)
        msg_type = opts.get(53, b'\x00')[0]
    except Exception as e:
        log_message(f"DHCP: 解析请求包失败: {e}", "ERROR"); return None

    user_class = opts.get(77, b'')
    vendor_class_bytes = opts.get(60, b'')
    vendor_class = vendor_class_bytes.decode(errors='ignore')
    is_ipxe_client = b'iPXE' in user_class or b'iPXE' in vendor_class_bytes
    
    if vendor_class:
        log_message(f"DHCP: 客户端 {client_mac} Vendor Class Identifier = '{vendor_class}'")

    if 'MSFT 5.0' in vendor_class:
        log_message(f"DHCP: 客户端 {client_mac} (Windows 获取IP) 请求地址。")
        hostname = opts.get(12, b'').decode(errors='ignore').strip()
        if client_manager:
            client_manager.handle_dhcp_request(client_mac, assigned_ip, 'get_ip', hostname=hostname)
        
        resp_msg_type = 2 if msg_type == 1 else (5 if msg_type == 3 else 0)
        if resp_msg_type == 0: return None
        resp_pkt = bytearray(struct.pack('!BBBB', 2, 1, 6, 0)) + xid + struct.pack('!HH', 0, 0x8000)
        resp_pkt += req_pkt[12:16] + socket.inet_aton(assigned_ip) + b'\x00\x00\x00\x00'
        resp_pkt += req_pkt[24:28] + chaddr + (b'\x00' * (64 + 128)) + b'\x63\x82\x53\x63'
        resp_pkt += bytes([53, 1, resp_msg_type]) + bytes([54, 4]) + socket.inet_aton(cfg['server_ip'])
        if cfg['dhcp_mode'] == 'dhcp' and not is_proxy_req:
            resp_pkt += bytes([1, 4]) + socket.inet_aton(cfg['subnet_mask'])
            resp_pkt += bytes([3, 4]) + socket.inet_aton(cfg['router_ip'])
            resp_pkt += bytes([6, 4]) + socket.inet_aton(cfg['dns_server_ip'])
            resp_pkt += bytes([51, 4]) + cfg['lease_time'].to_bytes(4, 'big')
        if cfg.get('dhcp_options_enabled', False):
            custom_options_bytes = dhcp_option_handler.parse_and_build_dhcp_options(cfg.get('dhcp_options_text', ''))
            if custom_options_bytes: resp_pkt += custom_options_bytes
        resp_pkt += b'\xff'
        return bytes(resp_pkt)

    arch_name = 'bios'
    if 93 in opts and len(opts[93]) >= 2:
        arch_code = struct.unpack('!H', opts[93][:2])[0]
        arch_name = ARCH_TYPES.get(arch_code, 'bios')
    
    if client_manager:
        firmware_display = 'UEFI' if 'uefi' in arch_name else 'BIOS'
        initial_state = 'ipxe' if is_ipxe_client else 'pxe'
        client_manager.handle_dhcp_request(client_mac, assigned_ip, initial_state, firmware_type=firmware_display)
    
    if is_ipxe_client:
        menu_cfg_key_prefix = 'pxe_menu_ipxe'
    else:
        menu_cfg_key_prefix = 'pxe_menu_uefi' if 'uefi' in arch_name else 'pxe_menu_bios'

    has_hostname = 12 in opts
    menu_enabled = cfg.get(f'{menu_cfg_key_prefix}_enabled', False)
    final_server_ip = cfg['server_ip']
    boot_file = ""
    option43 = b''
    is_menu_offer = False

    resp_msg_type = 5 if is_proxy_req else (2 if msg_type == 1 else (5 if msg_type == 3 else 0))
    if resp_msg_type == 0: return None

    selected_item_type = None
    if 43 in opts:
        pxe_opts = opts[43]
        i = 0
        while i < len(pxe_opts) - 1:
            sub_code, sub_len = pxe_opts[i], pxe_opts[i+1]
            if sub_code == 255: break
            if sub_code == 71 and sub_len >= 4:
                selected_item_type = struct.unpack('!H', pxe_opts[i+2:i+4])[0]
                break
            i += 2 + sub_len

    if selected_item_type is not None:
        if client_manager: client_manager.handle_dhcp_request(client_mac, assigned_ip, 'menuselect')
        
        menu_items_str = cfg.get(f'{menu_cfg_key_prefix}_items', '')
        for line in menu_items_str.strip().splitlines():
            parts = [p.strip() for p in line.strip().split(',', 3) if p]
            if len(parts) == 4:
                try:
                    if int(parts[2], 16) == selected_item_type:
                        boot_file = parts[1]

                        # <--- 修改点 1：同样修正这里的 %dynamicboot% 宏
                        # 现在它会使用配置文件中确切的 server_ip 和 http_port
                        if '%dynamicboot%' in boot_file:
                            http_server_uri = f"http://{cfg['server_ip']}:{cfg['http_port']}"
                            replacement_string = f'{http_server_uri}/dynamic.ipxe?bootfile'
                            boot_file = boot_file.replace('%dynamicboot%', replacement_string)
                        
                        server_ip_str = parts[3]
                        if '%tftpserver%' in server_ip_str.lower():
                            final_server_ip = cfg['server_ip']
                        elif server_ip_str and server_ip_str != '0.0.0.0':
                            final_server_ip = server_ip_str
                        else:
                            final_server_ip = cfg['server_ip']
                        break
                except ValueError: 
                    continue
        log_message(f"DHCP: 客户端 {client_mac} 已选择菜单项 {selected_item_type:04x}, 提供文件: '{boot_file or '本地启动'}'")
        option43 = bytes([71, 4]) + selected_item_type.to_bytes(2, 'big') + (0).to_bytes(2, 'big') + b'\xff'
    
    elif menu_enabled and (not has_hostname or menu_cfg_key_prefix in ['pxe_menu_bios', 'pxe_menu_uefi']):
        if is_ipxe_client:
            # <--- 修改点 2：修正这里的动态菜单 URL
            # 直接使用配置文件中的 server_ip 和 http_port 构造 URL，不再依赖 iPXE 变量
            server_ip = cfg['server_ip']
            http_port = cfg['http_port']
            boot_file = f"http://{server_ip}:{http_port}/dynamic.ipxe?bootfile=ipxemenu"
            
            is_menu_offer = False 
            option43 = b'' 
            log_message(f"DHCP: 为iPXE客户端 {client_mac} 提供动态菜单脚本: '{boot_file}'")
            if client_manager:
                client_manager.handle_dhcp_request(client_mac, assigned_ip, 'ipxemenu')
        else:
            # 对于传统的BIOS/UEFI客户端，行为保持不变
            is_menu_offer = True
            menu_config = {
                'enabled': True, 'timeout': cfg.get(f'{menu_cfg_key_prefix}_timeout', 10),
                'randomize_timeout': cfg.get(f'{menu_cfg_key_prefix}_randomize_timeout', False),
                'prompt': cfg.get(f'{menu_cfg_key_prefix}_prompt', 'Boot Menu'),
                'items': cfg.get(f'{menu_cfg_key_prefix}_items', '')
            }
            option43 = build_pxe_option43_menu(menu_config, cfg['server_ip'])
            log_message(f"DHCP: 为 {client_mac} ({arch_name.upper()}) 提供 '{menu_cfg_key_prefix}' 菜单")
            if client_manager:
                client_manager.handle_dhcp_request(client_mac, assigned_ip, 'pxemenu')
    else:
        if is_ipxe_client:
            boot_file = cfg.get('bootfile_ipxe', '')
        else:
            boot_file = cfg.get(f"bootfile_{arch_name}", cfg['bootfile_bios'])
            if boot_file:
                option43 = b'\x06\x01\x08\xff'
        log_message(f"DHCP: 为 {client_mac} 提供默认文件: '{boot_file}'")
    
    resp_pkt = bytearray(struct.pack('!BBBB', 2, 1, 6, 0)) + xid + struct.pack('!HH', 0, 0x8000)
    resp_pkt += req_pkt[12:16] + socket.inet_aton(assigned_ip)
    final_server_ip_bytes = socket.inet_aton(final_server_ip)
    siaddr = b'\x00\x00\x00\x00' if is_menu_offer else final_server_ip_bytes
    file_bytes = boot_file.encode('ascii', 'ignore')
    resp_pkt += siaddr + req_pkt[24:28] + chaddr + (b'\x00' * 64)
    resp_pkt += file_bytes + b'\x00' * (128 - len(file_bytes))
    resp_pkt += b'\x63\x82\x53\x63'

    resp_pkt += bytes([53, 1, resp_msg_type])
    resp_pkt += bytes([54, 4]) + socket.inet_aton(cfg['server_ip'])
    resp_pkt += bytes([60, 9]) + b'PXEClient'
    if 97 in opts: resp_pkt += bytes([97, len(opts[97])]) + opts[97]
    if option43: resp_pkt += bytes([43, len(option43)]) + option43
    
    if not is_menu_offer and boot_file:
        server_ip_str_bytes = final_server_ip.encode('ascii')
        resp_pkt += bytes([66, len(server_ip_str_bytes)]) + server_ip_str_bytes
        resp_pkt += bytes([67, len(file_bytes) + 1]) + file_bytes + b'\x00'
    
    if cfg['dhcp_mode'] == 'dhcp' and not is_proxy_req:
        resp_pkt += bytes([1, 4]) + socket.inet_aton(cfg['subnet_mask'])
        resp_pkt += bytes([3, 4]) + socket.inet_aton(cfg['router_ip'])
        resp_pkt += bytes([6, 4]) + socket.inet_aton(cfg['dns_server_ip'])
        resp_pkt += bytes([51, 4]) + cfg['lease_time'].to_bytes(4, 'big')

    if cfg.get('dhcp_options_enabled', False):
        custom_options_bytes = dhcp_option_handler.parse_and_build_dhcp_options(cfg.get('dhcp_options_text', ''))
        if custom_options_bytes: resp_pkt += custom_options_bytes
    
    resp_pkt += b'\xff'
    return bytes(resp_pkt)
    if len(req_pkt) < 240: return None
    try:
        xid, chaddr = req_pkt[4:8], req_pkt[28:44]
        client_mac = ":".join(f"{b:02x}" for b in chaddr[:6])
        opts = parse_dhcp_options(req_pkt)
        msg_type = opts.get(53, b'\x00')[0]
    except Exception as e:
        log_message(f"DHCP: 解析请求包失败: {e}", "ERROR"); return None

    user_class = opts.get(77, b'')
    vendor_class_bytes = opts.get(60, b'')
    vendor_class = vendor_class_bytes.decode(errors='ignore')
    is_ipxe_client = b'iPXE' in user_class or b'iPXE' in vendor_class_bytes
    
    if vendor_class:
        log_message(f"DHCP: 客户端 {client_mac} Vendor Class Identifier = '{vendor_class}'")

    if 'MSFT 5.0' in vendor_class:
        log_message(f"DHCP: 客户端 {client_mac} (Windows 获取IP) 请求地址。")
        hostname = opts.get(12, b'').decode(errors='ignore').strip()
        if client_manager:
            client_manager.handle_dhcp_request(client_mac, assigned_ip, 'get_ip', hostname=hostname)
        
        resp_msg_type = 2 if msg_type == 1 else (5 if msg_type == 3 else 0)
        if resp_msg_type == 0: return None
        resp_pkt = bytearray(struct.pack('!BBBB', 2, 1, 6, 0)) + xid + struct.pack('!HH', 0, 0x8000)
        resp_pkt += req_pkt[12:16] + socket.inet_aton(assigned_ip) + b'\x00\x00\x00\x00'
        resp_pkt += req_pkt[24:28] + chaddr + (b'\x00' * (64 + 128)) + b'\x63\x82\x53\x63'
        resp_pkt += bytes([53, 1, resp_msg_type]) + bytes([54, 4]) + socket.inet_aton(cfg['server_ip'])
        if cfg['dhcp_mode'] == 'dhcp' and not is_proxy_req:
            resp_pkt += bytes([1, 4]) + socket.inet_aton(cfg['subnet_mask'])
            resp_pkt += bytes([3, 4]) + socket.inet_aton(cfg['router_ip'])
            resp_pkt += bytes([6, 4]) + socket.inet_aton(cfg['dns_server_ip'])
            resp_pkt += bytes([51, 4]) + cfg['lease_time'].to_bytes(4, 'big')
        if cfg.get('dhcp_options_enabled', False):
            custom_options_bytes = dhcp_option_handler.parse_and_build_dhcp_options(cfg.get('dhcp_options_text', ''))
            if custom_options_bytes: resp_pkt += custom_options_bytes
        resp_pkt += b'\xff'
        return bytes(resp_pkt)

    arch_name = 'bios'
    if 93 in opts and len(opts[93]) >= 2:
        arch_code = struct.unpack('!H', opts[93][:2])[0]
        arch_name = ARCH_TYPES.get(arch_code, 'bios')
    
    if client_manager:
        firmware_display = 'UEFI' if 'uefi' in arch_name else 'BIOS'
        initial_state = 'ipxe' if is_ipxe_client else 'pxe'
        client_manager.handle_dhcp_request(client_mac, assigned_ip, initial_state, firmware_type=firmware_display)
    
    if is_ipxe_client:
        menu_cfg_key_prefix = 'pxe_menu_ipxe'
    else:
        menu_cfg_key_prefix = 'pxe_menu_uefi' if 'uefi' in arch_name else 'pxe_menu_bios'

    has_hostname = 12 in opts
    menu_enabled = cfg.get(f'{menu_cfg_key_prefix}_enabled', False)
    final_server_ip = cfg['server_ip']
    boot_file = ""
    option43 = b''
    is_menu_offer = False

    resp_msg_type = 5 if is_proxy_req else (2 if msg_type == 1 else (5 if msg_type == 3 else 0))
    if resp_msg_type == 0: return None

    selected_item_type = None
    if 43 in opts:
        pxe_opts = opts[43]
        i = 0
        while i < len(pxe_opts) - 1:
            sub_code, sub_len = pxe_opts[i], pxe_opts[i+1]
            if sub_code == 255: break
            if sub_code == 71 and sub_len >= 4:
                selected_item_type = struct.unpack('!H', pxe_opts[i+2:i+4])[0]
                break
            i += 2 + sub_len

    if selected_item_type is not None:
        if client_manager: client_manager.handle_dhcp_request(client_mac, assigned_ip, 'menuselect')
        
        menu_items_str = cfg.get(f'{menu_cfg_key_prefix}_items', '')
        for line in menu_items_str.strip().splitlines():
            parts = [p.strip() for p in line.strip().split(',', 3) if p]
            if len(parts) == 4:
                try:
                    if int(parts[2], 16) == selected_item_type:
                        boot_file = parts[1]

                        if '%dynamicboot%' in boot_file:
                            replacement_string = 'http://${booturl}/dynamic.ipxe?bootfile'
                            boot_file = boot_file.replace('%dynamicboot%', replacement_string)
                        
                        server_ip_str = parts[3]
                        if '%tftpserver%' in server_ip_str.lower():
                            final_server_ip = cfg['server_ip']
                        elif server_ip_str and server_ip_str != '0.0.0.0':
                            final_server_ip = server_ip_str
                        else:
                            final_server_ip = cfg['server_ip']
                        break
                except ValueError: 
                    continue
        log_message(f"DHCP: 客户端 {client_mac} 已选择菜单项 {selected_item_type:04x}, 提供文件: '{boot_file or '本地启动'}'")
        option43 = bytes([71, 4]) + selected_item_type.to_bytes(2, 'big') + (0).to_bytes(2, 'big') + b'\xff'
    
    elif menu_enabled and (not has_hostname or menu_cfg_key_prefix in ['pxe_menu_bios', 'pxe_menu_uefi']):
        # =======================[ 核心修改开始 ]=======================
        if is_ipxe_client:
            # 对于iPXE客户端，我们不再发送Option 43。
            # 我们将boot_file设置为动态脚本的URL，iPXE将自动下载并执行它。
            # "ipxemenu"是一个我们自定义的信号，告诉dynamic.py生成主菜单。
            boot_file = 'http://${booturl}/dynamic.ipxe?bootfile=ipxemenu'
            is_menu_offer = False #这不是一个传统的PXE菜单offer
            option43 = b'' # 确保清空option43
            log_message(f"DHCP: 为iPXE客户端 {client_mac} 提供动态菜单脚本: '{boot_file}'")
            if client_manager:
                client_manager.handle_dhcp_request(client_mac, assigned_ip, 'ipxemenu')
        else:
            # 对于传统的BIOS/UEFI客户端，继续使用旧的Option 43方法
            is_menu_offer = True
            menu_config = {
                'enabled': True, 'timeout': cfg.get(f'{menu_cfg_key_prefix}_timeout', 10),
                'randomize_timeout': cfg.get(f'{menu_cfg_key_prefix}_randomize_timeout', False),
                'prompt': cfg.get(f'{menu_cfg_key_prefix}_prompt', 'Boot Menu'),
                'items': cfg.get(f'{menu_cfg_key_prefix}_items', '')
            }
            option43 = build_pxe_option43_menu(menu_config, cfg['server_ip'])
            log_message(f"DHCP: 为 {client_mac} ({arch_name.upper()}) 提供 '{menu_cfg_key_prefix}' 菜单")
            if client_manager:
                client_manager.handle_dhcp_request(client_mac, assigned_ip, 'pxemenu')
        # =======================[ 核心修改结束 ]=======================
    else:
        if is_ipxe_client:
            boot_file = cfg.get('bootfile_ipxe', '')
        else:
            boot_file = cfg.get(f"bootfile_{arch_name}", cfg['bootfile_bios'])
            if boot_file:
                option43 = b'\x06\x01\x08\xff'
        log_message(f"DHCP: 为 {client_mac} 提供默认文件: '{boot_file}'")
    
    resp_pkt = bytearray(struct.pack('!BBBB', 2, 1, 6, 0)) + xid + struct.pack('!HH', 0, 0x8000)
    resp_pkt += req_pkt[12:16] + socket.inet_aton(assigned_ip)
    final_server_ip_bytes = socket.inet_aton(final_server_ip)
    siaddr = b'\x00\x00\x00\x00' if is_menu_offer else final_server_ip_bytes
    file_bytes = boot_file.encode('ascii', 'ignore')
    resp_pkt += siaddr + req_pkt[24:28] + chaddr + (b'\x00' * 64)
    resp_pkt += file_bytes + b'\x00' * (128 - len(file_bytes))
    resp_pkt += b'\x63\x82\x53\x63'

    resp_pkt += bytes([53, 1, resp_msg_type])
    resp_pkt += bytes([54, 4]) + socket.inet_aton(cfg['server_ip'])
    resp_pkt += bytes([60, 9]) + b'PXEClient'
    if 97 in opts: resp_pkt += bytes([97, len(opts[97])]) + opts[97]
    if option43: resp_pkt += bytes([43, len(option43)]) + option43
    
    if not is_menu_offer and boot_file:
        server_ip_str_bytes = final_server_ip.encode('ascii')
        resp_pkt += bytes([66, len(server_ip_str_bytes)]) + server_ip_str_bytes
        resp_pkt += bytes([67, len(file_bytes) + 1]) + file_bytes + b'\x00'
    
    if cfg['dhcp_mode'] == 'dhcp' and not is_proxy_req:
        resp_pkt += bytes([1, 4]) + socket.inet_aton(cfg['subnet_mask'])
        resp_pkt += bytes([3, 4]) + socket.inet_aton(cfg['router_ip'])
        resp_pkt += bytes([6, 4]) + socket.inet_aton(cfg['dns_server_ip'])
        resp_pkt += bytes([51, 4]) + cfg['lease_time'].to_bytes(4, 'big')

    if cfg.get('dhcp_options_enabled', False):
        custom_options_bytes = dhcp_option_handler.parse_and_build_dhcp_options(cfg.get('dhcp_options_text', ''))
        if custom_options_bytes: resp_pkt += custom_options_bytes
    
    resp_pkt += b'\xff'
    return bytes(resp_pkt)
    if len(req_pkt) < 240: return None
    try:
        xid, chaddr = req_pkt[4:8], req_pkt[28:44]
        client_mac = ":".join(f"{b:02x}" for b in chaddr[:6])
        opts = parse_dhcp_options(req_pkt)
        msg_type = opts.get(53, b'\x00')[0]
    except Exception as e:
        log_message(f"DHCP: 解析请求包失败: {e}", "ERROR"); return None

    user_class = opts.get(77, b'')
    vendor_class_bytes = opts.get(60, b'')
    vendor_class = vendor_class_bytes.decode(errors='ignore')
    is_ipxe_client = b'iPXE' in user_class or b'iPXE' in vendor_class_bytes
    
    if vendor_class:
        log_message(f"DHCP: 客户端 {client_mac} Vendor Class Identifier = '{vendor_class}'")

    if 'MSFT 5.0' in vendor_class:
        log_message(f"DHCP: 客户端 {client_mac} (Windows 获取IP) 请求地址。")
        hostname = opts.get(12, b'').decode(errors='ignore').strip()
        if client_manager:
            client_manager.handle_dhcp_request(client_mac, assigned_ip, 'get_ip', hostname=hostname)
        
        resp_msg_type = 2 if msg_type == 1 else (5 if msg_type == 3 else 0)
        if resp_msg_type == 0: return None
        resp_pkt = bytearray(struct.pack('!BBBB', 2, 1, 6, 0)) + xid + struct.pack('!HH', 0, 0x8000)
        resp_pkt += req_pkt[12:16] + socket.inet_aton(assigned_ip) + b'\x00\x00\x00\x00'
        resp_pkt += req_pkt[24:28] + chaddr + (b'\x00' * (64 + 128)) + b'\x63\x82\x53\x63'
        resp_pkt += bytes([53, 1, resp_msg_type]) + bytes([54, 4]) + socket.inet_aton(cfg['server_ip'])
        if cfg['dhcp_mode'] == 'dhcp' and not is_proxy_req:
            resp_pkt += bytes([1, 4]) + socket.inet_aton(cfg['subnet_mask'])
            resp_pkt += bytes([3, 4]) + socket.inet_aton(cfg['router_ip'])
            resp_pkt += bytes([6, 4]) + socket.inet_aton(cfg['dns_server_ip'])
            resp_pkt += bytes([51, 4]) + cfg['lease_time'].to_bytes(4, 'big')
        if cfg.get('dhcp_options_enabled', False):
            custom_options_bytes = dhcp_option_handler.parse_and_build_dhcp_options(cfg.get('dhcp_options_text', ''))
            if custom_options_bytes: resp_pkt += custom_options_bytes
        resp_pkt += b'\xff'
        return bytes(resp_pkt)

    arch_name = 'bios'
    if 93 in opts and len(opts[93]) >= 2:
        arch_code = struct.unpack('!H', opts[93][:2])[0]
        arch_name = ARCH_TYPES.get(arch_code, 'bios')
    
    if client_manager:
        firmware_display = 'UEFI' if 'uefi' in arch_name else 'BIOS'
        initial_state = 'ipxe' if is_ipxe_client else 'pxe'
        client_manager.handle_dhcp_request(client_mac, assigned_ip, initial_state, firmware_type=firmware_display)
    
    if is_ipxe_client:
        menu_cfg_key_prefix = 'pxe_menu_ipxe'
    else:
        menu_cfg_key_prefix = 'pxe_menu_uefi' if 'uefi' in arch_name else 'pxe_menu_bios'

    has_hostname = 12 in opts
    menu_enabled = cfg.get(f'{menu_cfg_key_prefix}_enabled', False)
    final_server_ip = cfg['server_ip']
    boot_file = ""
    option43 = b''
    is_menu_offer = False

    resp_msg_type = 5 if is_proxy_req else (2 if msg_type == 1 else (5 if msg_type == 3 else 0))
    if resp_msg_type == 0: return None

    selected_item_type = None
    if 43 in opts:
        pxe_opts = opts[43]
        i = 0
        while i < len(pxe_opts) - 1:
            sub_code, sub_len = pxe_opts[i], pxe_opts[i+1]
            if sub_code == 255: break
            if sub_code == 71 and sub_len >= 4:
                selected_item_type = struct.unpack('!H', pxe_opts[i+2:i+4])[0]
                break
            i += 2 + sub_len

    if selected_item_type is not None:
        if client_manager: client_manager.handle_dhcp_request(client_mac, assigned_ip, 'menuselect')
        
        menu_items_str = cfg.get(f'{menu_cfg_key_prefix}_items', '')
        for line in menu_items_str.strip().splitlines():
            parts = [p.strip() for p in line.strip().split(',', 3) if p]
            if len(parts) == 4:
                try:
                    if int(parts[2], 16) == selected_item_type:
                        boot_file = parts[1]

                        if '%dynamicboot%' in boot_file:
                            replacement_string = 'http://${booturl}/dynamic.ipxe?bootfile'
                            boot_file = boot_file.replace('%dynamicboot%', replacement_string)
                        
                        server_ip_str = parts[3]
                        if '%tftpserver%' in server_ip_str.lower():
                            final_server_ip = cfg['server_ip']
                        elif server_ip_str and server_ip_str != '0.0.0.0':
                            final_server_ip = server_ip_str
                        else:
                            final_server_ip = cfg['server_ip']
                        break
                except ValueError: 
                    continue
        log_message(f"DHCP: 客户端 {client_mac} 已选择菜单项 {selected_item_type:04x}, 提供文件: '{boot_file or '本地启动'}'")
        option43 = bytes([71, 4]) + selected_item_type.to_bytes(2, 'big') + (0).to_bytes(2, 'big') + b'\xff'
    
    elif menu_enabled and (not has_hostname or menu_cfg_key_prefix in ['pxe_menu_bios', 'pxe_menu_uefi']):
        is_menu_offer = True
        menu_config = {
            'enabled': True, 'timeout': cfg.get(f'{menu_cfg_key_prefix}_timeout', 10),
            'randomize_timeout': cfg.get(f'{menu_cfg_key_prefix}_randomize_timeout', False),
            'prompt': cfg.get(f'{menu_cfg_key_prefix}_prompt', 'Boot Menu'),
            'items': cfg.get(f'{menu_cfg_key_prefix}_items', '')
        }
        option43 = build_pxe_option43_menu(menu_config, cfg['server_ip'])
        log_message(f"DHCP: 为 {client_mac} ({arch_name.upper()}) 提供 '{menu_cfg_key_prefix}' 菜单")
        
        if client_manager:
            menu_state = 'ipxemenu' if is_ipxe_client else 'pxemenu'
            client_manager.handle_dhcp_request(client_mac, assigned_ip, menu_state)

    else:
        if is_ipxe_client:
            boot_file = cfg.get('bootfile_ipxe', '')
        else:
            boot_file = cfg.get(f"bootfile_{arch_name}", cfg['bootfile_bios'])
            if boot_file:
                option43 = b'\x06\x01\x08\xff'
        log_message(f"DHCP: 为 {client_mac} 提供默认文件: '{boot_file}'")
    
    resp_pkt = bytearray(struct.pack('!BBBB', 2, 1, 6, 0)) + xid + struct.pack('!HH', 0, 0x8000)
    resp_pkt += req_pkt[12:16] + socket.inet_aton(assigned_ip)
    final_server_ip_bytes = socket.inet_aton(final_server_ip)
    siaddr = b'\x00\x00\x00\x00' if is_menu_offer else final_server_ip_bytes
    file_bytes = boot_file.encode('ascii', 'ignore')
    resp_pkt += siaddr + req_pkt[24:28] + chaddr + (b'\x00' * 64)
    resp_pkt += file_bytes + b'\x00' * (128 - len(file_bytes))
    resp_pkt += b'\x63\x82\x53\x63'

    resp_pkt += bytes([53, 1, resp_msg_type])
    resp_pkt += bytes([54, 4]) + socket.inet_aton(cfg['server_ip'])
    resp_pkt += bytes([60, 9]) + b'PXEClient'
    if 97 in opts: resp_pkt += bytes([97, len(opts[97])]) + opts[97]
    if option43: resp_pkt += bytes([43, len(option43)]) + option43
    
    if not is_menu_offer and boot_file:
        server_ip_str_bytes = final_server_ip.encode('ascii')
        resp_pkt += bytes([66, len(server_ip_str_bytes)]) + server_ip_str_bytes
        resp_pkt += bytes([67, len(file_bytes) + 1]) + file_bytes + b'\x00'
    
    if cfg['dhcp_mode'] == 'dhcp' and not is_proxy_req:
        resp_pkt += bytes([1, 4]) + socket.inet_aton(cfg['subnet_mask'])
        resp_pkt += bytes([3, 4]) + socket.inet_aton(cfg['router_ip'])
        resp_pkt += bytes([6, 4]) + socket.inet_aton(cfg['dns_server_ip'])
        resp_pkt += bytes([51, 4]) + cfg['lease_time'].to_bytes(4, 'big')

    if cfg.get('dhcp_options_enabled', False):
        custom_options_bytes = dhcp_option_handler.parse_and_build_dhcp_options(cfg.get('dhcp_options_text', ''))
        if custom_options_bytes: resp_pkt += custom_options_bytes
    
    resp_pkt += b'\xff'
    return bytes(resp_pkt)

dhcp_thread, proxy_thread, tftp_thread, http_thread, dhcp_detector_thread = None, None, None, None, None
stop_event = threading.Event()

def detect_other_dhcp_servers(stop_evt):
    log_message("DHCP探测器: 开始扫描局域网中的其它DHCP服务器(持续15秒)...")
    listen_ip = SETTINGS.get('listen_ip', '0.0.0.0')
    server_ip = SETTINGS.get('server_ip')
    bind_ip = listen_ip if listen_ip != '0.0.0.0' else ''
    discover_pkt = bytearray(b'\x01\x01\x06\x00')
    discover_pkt += os.urandom(4)
    discover_pkt += b'\x00\x00\x80\x00'
    discover_pkt += b'\x00' * 16
    discover_pkt += b'\x00\x11\x22\x33\x44\x55' + b'\x00'*10
    discover_pkt += b'\x00' * 192
    discover_pkt += b'\x63\x82\x53\x63'
    discover_pkt += b'\x35\x01\x01'
    discover_pkt += b'\x37\x05\x01\x03\x06\x0c\x0f'
    discover_pkt += b'\x0c\x08NBPXE-Scan'
    discover_pkt += b'\xff'
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    try:
        sock.bind((bind_ip, 68))
    except Exception as e:
        log_message(f"DHCP探测器: 无法绑定到端口68进行检测: {e}", "ERROR")
        sock.close()
        return
    start_time = time.time()
    found_server = False
    try:
        while not stop_evt.is_set() and time.time() - start_time < 15 and not found_server:
            log_message("DHCP探测器: 正在发送DHCPDISCOVER广播包...")
            sock.sendto(discover_pkt, ('255.255.255.255', 67))
            listen_start_time = time.time()
            detected_servers = set()
            while time.time() - listen_start_time < 3:
                if stop_evt.is_set(): break
                try:
                    sock.settimeout(1.0)
                    data, _ = sock.recvfrom(1024)
                    if len(data) > 240:
                        opts = parse_dhcp_options(data)
                        if opts.get(53) == b'\x02':
                            server_id_bytes = opts.get(54)
                            if server_id_bytes:
                                server_id = socket.inet_ntoa(server_id_bytes)
                                if server_id != server_ip and server_id != listen_ip:
                                    detected_servers.add(server_id)
                except socket.timeout:
                    continue
                except Exception as e:
                    log_message(f"DHCP探测器: 接收探测响应时出错: {e}", "ERROR")
            if detected_servers:
                for srv_ip in detected_servers:
                    log_message(f"警告: 在局域网中发现另一个DHCP服务器, 地址为 {srv_ip}！", "WARNING")
                log_message("建议: 为避免IP地址冲突, 请在本软件中使用“代理(Proxy)”模式, 或停用网络中的其它DHCP服务器。", "WARNING")
                found_server = True
            if not found_server and not stop_evt.is_set():
                time.sleep(2)
    finally:
        if not found_server and not stop_evt.is_set():
            log_message("DHCP探测器: 扫描结束, 未发现其它DHCP服务器。")
        sock.close()
        if client_manager:
            client_manager.remove_probe_client()

# --- [核心修改] run_dhcp_server ---
def run_dhcp_server(cfg, stop_evt, client_mgr):
    mac_to_ip, offered_ips = {}, {}
    ip_pool = deque()
    if cfg['dhcp_mode'] == 'dhcp':
        try:
            start_int = struct.unpack('!I', socket.inet_aton(cfg['ip_pool_start']))[0]
            end_int = struct.unpack('!I', socket.inet_aton(cfg['ip_pool_end']))[0]
            ip_pool.extend([socket.inet_ntoa(struct.pack('!I', i)) for i in range(start_int, end_int + 1)])
        except Exception as e:
            log_message(f"DHCP (67): IP池创建失败: {e}", "ERROR"); return

    def get_lease_from_pool(mac):
        if mac in offered_ips and offered_ips[mac]['expires'] > time.time(): return offered_ips[mac]['ip']
        if not ip_pool: log_message("DHCP (67): IP池已耗尽!", "WARNING"); return None
        ip = ip_pool.popleft(); offered_ips[mac] = {'ip': ip, 'expires': time.time() + 60}; return ip

    def confirm_lease(mac, req_ip):
        if mac in mac_to_ip and mac_to_ip[mac] == req_ip: return req_ip
        if mac in offered_ips and offered_ips[mac]['ip'] == req_ip:
            mac_to_ip[mac] = req_ip; del offered_ips[mac]; return req_ip
        if req_ip in ip_pool:
            mac_to_ip[mac] = req_ip; ip_pool.remove(req_ip); return req_ip
        return None

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1); sock.settimeout(1.0)
    try:
        sock.bind((cfg['listen_ip'], 67)); log_message(f"DHCP: 监听器已在 {cfg['listen_ip']}:67 启动 ({cfg['dhcp_mode']} 模式)")
    except Exception as e: log_message(f"DHCP (67): 致命错误 - 无法绑定端口: {e}", "ERROR"); return
    
    while not stop_evt.is_set():
        try:
            data, addr = sock.recvfrom(1024)
            mac = ":".join(f"{b:02x}" for b in data[28:34])
            opts = parse_dhcp_options(data)
            msg_type = opts.get(53, b'\x00')[0]
            
            ip_to_assign = '0.0.0.0'
            if cfg['dhcp_mode'] == 'dhcp':
                # 1. 检查静态绑定
                static_ip = client_mgr.get_ip_for_mac(mac)
                if static_ip:
                    ip_to_assign = static_ip
                    log_message(f"DHCP: 发现静态绑定: MAC {mac} -> IP {static_ip}", "INFO")
                else:
                    # 2. 如果没有静态绑定，执行动态分配逻辑
                    if msg_type == 1: # DHCPDISCOVER
                        ip_to_assign = get_lease_from_pool(mac)
                    elif msg_type == 3: # DHCPREQUEST
                        req_ip = socket.inet_ntoa(opts[50]) if 50 in opts else None
                        if req_ip:
                            ip_to_assign = confirm_lease(mac, req_ip)
                
                if not ip_to_assign: 
                    continue
            
            response_pkt = craft_dhcp_response(data, cfg, assigned_ip=ip_to_assign)
            if response_pkt: sock.sendto(response_pkt, ('255.255.255.255', 68))
        except socket.timeout: 
            continue
        except Exception as e: 
            log_message(f"DHCP (67): 循环中发生错误: {e}", "ERROR")
            
    sock.close(); log_message("DHCP (67): 监听器已停止。")

# ... (run_proxy_listener, tftp, http, smb, a NBpxeApp class 保持不变, 此处省略以节省篇幅) ...
def run_proxy_listener(cfg, stop_evt):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); sock.settimeout(1.0)
    try:
        sock.bind((cfg['listen_ip'], 4011)); log_message(f"ProxyDHCP: 监听器已在 {cfg['listen_ip']}:4011 启动")
    except Exception as e: log_message(f"ProxyDHCP (4011): 致命错误 - 无法绑定端口: {e}", "ERROR"); return

    while not stop_evt.is_set():
        try:
            data, addr = sock.recvfrom(1024)
            mac = ":".join(f"{b:02x}" for b in data[28:34])
            client_ip_from_packet = socket.inet_ntoa(data[12:16])
            if client_ip_from_packet != '0.0.0.0':
                with ip_map_lock:
                    ip_to_mac_map[client_ip_from_packet] = mac

            response_pkt = craft_dhcp_response(data, cfg, assigned_ip=client_ip_from_packet, is_proxy_req=True)
            if response_pkt: sock.sendto(response_pkt, addr)
        except socket.timeout: continue
        except Exception as e: log_message(f"ProxyDHCP (4011): 循环中发生错误: {e}", "ERROR")
    sock.close(); log_message("ProxyDHCP (4011): 监听器已停止。")

def log_aggregated_failures():
    """
    这个函数在后台独立运行，像一个管家。
    定期检查失败聚合器，只报告那些持续存在且未被成功传输所清除的真实失败。
    """
    while not stop_aggregator_event.is_set():
        # 每15秒工作一次
        stop_aggregator_event.wait(15)
        if stop_aggregator_event.is_set():
            break

        with aggregator_lock:
            now = time.time()
            # 遍历键的副本以允许在循环中删除
            for key, data in list(failure_aggregator.items()):
                # 如果最后的失败记录发生在12秒前，我们就认为这是一个持续的真失败
                if now - data['timestamp'] > 12:
                    ip, filename = key.split(':', 1)
                    count = data['count']
                    # 打印汇总后的唯一错误日志
                    log_message(f"TFTP: [传输失败] 客户端 {ip} 请求 '{filename}' 多次超时 ({count}次尝试)", "ERROR")
                    # 清理掉这个已报告的条目
                    del failure_aggregator[key]

def run_tftp_server(cfg, stop_evt):
    tftp_root = os.path.realpath(cfg['tftp_root'])
    if not os.path.exists(tftp_root):
        try:
            os.makedirs(tftp_root)
            log_message(f"TFTP: 已创建根目录 '{tftp_root}'")
        except OSError as e:
            log_message(f"TFTP: 创建根目录失败: {e}", "ERROR")
            return

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.0)
    try:
        sock.bind((cfg['listen_ip'], 69))
    except Exception as e:
        log_message(f"TFTP: 致命错误 - 无法绑定端口 69: {e}", "ERROR")
        return

    use_multithread = cfg.get('tftp_multithread', True)
    executor = ThreadPoolExecutor(max_workers=20, thread_name_prefix='TFTP') if use_multithread else None
    log_message(f"TFTP: 服务器已在 {cfg['listen_ip']}:69 启动 ({'多线程' if use_multithread else '单线程'}, 根目录: '{tftp_root}')")

    def handle_request(initial_data, client_addr):
        filepath = None
        filename = None
        transfer_successful = False
        opcode = 0
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as tsock:
                tsock.settimeout(5)

                if len(initial_data) < 4: return
                opcode = struct.unpack('!H', initial_data[:2])[0]
                parts = initial_data[2:].split(b'\x00')
                filename = parts[0].decode('ascii', 'ignore')
                client_ip = client_addr[0]
                
                if opcode == 1: # READ (下载)
                    if client_manager:
                        client_manager.handle_file_transfer_start(client_ip, filename)

                    _filename = filename.replace('\\', '/').lstrip('/')
                    filepath = os.path.realpath(os.path.join(tftp_root, _filename))

                    if not filepath.startswith(tftp_root) or not os.path.isfile(filepath):
                        log_message(f"TFTP: [拒绝] {client_addr} 请求了非法或不存在的文件 '{filename}'", "WARNING")
                        tsock.sendto(struct.pack('!HH', 5, 1) + b'File not found\x00', client_addr); return
                    
                    log_message(f"TFTP: [GET] {client_addr} 请求 '{filename}'")
                    file_size = os.path.getsize(filepath)
                    
                    blksize = 512 # 默认块大小
                    is_modern_client = len(parts) > 3 and parts[1].lower() == b'octet'
                    
                    if is_modern_client:
                        options = {parts[i].lower(): parts[i+1] for i in range(2, len(parts) - 1, 2)}
                        oack_parts = []
                        negotiated_blksize = 512
                        
                        if b'blksize' in options:
                            try:
                                negotiated_blksize = max(512, min(int(options[b'blksize']), 1428))
                                oack_parts.append(b'blksize\x00' + str(negotiated_blksize).encode() + b'\x00')
                            except (ValueError, IndexError): pass
                        if b'tsize' in options: oack_parts.append(b'tsize\x00' + str(file_size).encode() + b'\x00')

                        if oack_parts:
                            oack_pkt = bytearray(struct.pack('!H', 6))
                            for part in oack_parts:
                                oack_pkt.extend(part)
                            
                            tsock.sendto(oack_pkt, client_addr)
                            
                            try:
                                tsock.settimeout(2.0)
                                ack_data, ack_addr = tsock.recvfrom(512)
                                client_addr = ack_addr # 更新客户端地址
                                if len(ack_data) >= 4:
                                    ack_opcode, ack_block_num = struct.unpack('!HH', ack_data[:4])
                                    if ack_opcode == 4 and ack_block_num == 0:
                                        log_message(f"TFTP: {client_addr} 已确认OACK (blksize={negotiated_blksize})。开始快速传输。", "INFO")
                                        blksize = negotiated_blksize
                                    else:
                                        log_message(f"TFTP: {client_addr} 对OACK响应异常，回退至标准模式。", "WARNING")
                                else:
                                    log_message(f"TFTP: {client_addr} 发送了无效的OACK确认，回退至标准模式。", "WARNING")
                            except socket.timeout:
                                log_message(f"TFTP: {client_addr} 未确认OACK，回退至标准模式。", "INFO")
                            
                            tsock.settimeout(5.0)

                    with open(filepath, 'rb') as f:
                        block_num = 1
                        while not stop_evt.is_set():
                            chunk = f.read(blksize)
                            data_pkt = struct.pack('!HH', 3, block_num) + chunk
                            
                            for retry in range(5):
                                if stop_evt.is_set(): return
                                tsock.sendto(data_pkt, client_addr)
                                try:
                                    ack_data, ack_addr = tsock.recvfrom(512)
                                    if len(ack_data) >= 4:
                                        ack_opcode, ack_block_num = struct.unpack('!HH', ack_data[:4])
                                        if ack_opcode == 4 and ack_block_num == block_num:
                                            client_addr = ack_addr
                                            break
                                except socket.timeout:
                                    continue
                            else:
                                log_message(f"TFTP: [传输失败] 等待 {client_addr} 对块 {block_num} 的ACK多次超时", "ERROR")
                                return
                            
                            if len(chunk) < blksize:
                                transfer_successful = True
                                log_message(f"TFTP: [成功] 文件 '{os.path.basename(filepath)}' -> {client_addr} 传输完成。")
                                break
                            block_num = (block_num + 1) % 65536
                
                elif opcode == 2: # 上传逻辑保持不变
                    log_message(f"TFTP: [WRITE] 收到来自 {client_addr} 对 '{filename}' 的上传请求。", "INFO")
                    sanitized_filename = filename.replace('\\', '/').lstrip('/')
                    if not sanitized_filename or '..' in sanitized_filename.split('/'):
                        log_message(f"TFTP: [拒绝] 收到来自 {client_addr} 的无效或恶意文件名 '{filename}'", "WARNING")
                        tsock.sendto(struct.pack('!HH', 5, 4) + b'Illegal TFTP operation\x00', client_addr); return
                    
                    filepath = os.path.join(tftp_root, sanitized_filename)
                    if not os.path.realpath(filepath).startswith(os.path.realpath(tftp_root)):
                        log_message(f"TFTP: [拒绝] 检测到来自 {client_addr} 的目录遍历尝试 '{filename}'", "WARNING")
                        tsock.sendto(struct.pack('!HH', 5, 2) + b'Access violation\x00', client_addr); return
                    
                    if os.path.exists(filepath):
                        log_message(f"TFTP: [警告] 文件 '{filepath}' 已存在。客户端 {client_addr} 即将覆盖该文件。", "WARNING")
                    
                    try:
                        dir_path = os.path.dirname(filepath)
                        if not os.path.exists(dir_path): os.makedirs(dir_path)
                    except OSError as e:
                        log_message(f"TFTP: [拒绝] 无法为 '{sanitized_filename}' 创建目录: {e}", "ERROR")
                        tsock.sendto(struct.pack('!HH', 5, 2) + b'Access violation\x00', client_addr); return
                    
                    tsock.sendto(struct.pack('!HH', 4, 0), client_addr)
                    expected_block_num = 1
                    total_bytes_written = 0
                    with open(filepath, 'wb') as f:
                        while True:
                            data, addr = tsock.recvfrom(516)
                            if len(data) < 4: continue
                            opcode_data, block_num = struct.unpack('!HH', data[:4])
                            if opcode_data == 5: log_message(f"TFTP: [写入中断] 客户端 {addr} 报告错误。", "WARNING"); return
                            if opcode_data != 3 or addr != client_addr: continue
                            if block_num == expected_block_num:
                                chunk = data[4:]; f.write(chunk); total_bytes_written += len(chunk)
                                tsock.sendto(struct.pack('!HH', 4, block_num), client_addr)
                                expected_block_num = (expected_block_num + 1) % 65536
                                if len(chunk) < 512:
                                    log_message(f"TFTP: [写入成功] 文件 '{sanitized_filename}' ({total_bytes_written}字节) 已从 {client_addr} 接收完毕。")
                                    transfer_successful = True
                                    break
                            elif block_num < expected_block_num:
                                tsock.sendto(struct.pack('!HH', 4, block_num), client_addr)
                
        except socket.timeout:
            log_message(f"TFTP: [超时] 与客户端 {client_addr} 的通信超时。", "ERROR")
        except ConnectionResetError:
            log_message(f"TFTP: 客户端 {client_addr} 已关闭连接 (可能传输已完成)。", "INFO")
            transfer_successful = True
        except Exception as e:
            log_message(f"TFTP: 处理来自 {client_addr} 的请求时发生意外错误: {e}", "ERROR")
        finally:
            if client_manager and filename and transfer_successful:
                if opcode == 1:
                    client_manager.handle_file_transfer_complete(client_ip, filename)
                elif opcode == 2:
                    client_manager.handle_file_upload_complete(client_ip, filename)

    try:
        while not stop_evt.is_set():
            try:
                data, addr = sock.recvfrom(1500)
                if use_multithread and executor:
                    executor.submit(handle_request, data, addr)
                else:
                    threading.Thread(target=handle_request, args=(data, addr), daemon=True).start()
            except socket.timeout:
                continue
    finally:
        if executor: executor.shutdown(wait=False)
        sock.close()
        log_message("TFTP: 服务器已停止。")

class RangeRequestHandler(http.server.SimpleHTTPRequestHandler):
    # 关键修改：使用HTTP/1.1协议（httpdisk需要）
    protocol_version = 'HTTP/1.1'
    
    def __init__(self, *args, client_manager_instance=None, **kwargs):
        self.client_manager = client_manager_instance
        super().__init__(*args, **kwargs)

    def do_HEAD(self):
        """处理HEAD请求 - httpdisk需要此方法来获取文件信息"""
        if self.path.startswith('/dynamic.ipxe'):
            self.send_response(200)
            self.send_header("Content-type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        fpath = self.translate_path(self.path)

        if os.path.isdir(fpath):
            super().do_HEAD()
            return

        if not os.path.isfile(fpath):
            self.send_error(404, "File not found")
            return

        try:
            fs = os.stat(fpath)
            size = fs.st_size
            mtime = fs.st_mtime
            
            self.send_response(200)
            self.send_header("Content-type", self.guess_type(fpath))
            self.send_header("Content-Length", str(size))
            self.send_header("Accept-Ranges", "bytes")
            # 添加Last-Modified头部，某些客户端需要这个
            self.send_header("Last-Modified", self.date_time_string(mtime))
            # 添加ETag头部，提高缓存兼容性
            etag = f'"{size}-{int(mtime)}"'
            self.send_header("ETag", etag)
            self.end_headers()
            log_message(f"HTTP: [HEAD] {self.path} -> {self.client_address[0]}")
        except OSError:
            self.send_error(404, "File not found")

    def do_GET(self):
        if self.path.startswith('/dynamic.ipxe'):
            try:
                parsed_path = urlparse(self.path)
                params = parse_qs(parsed_path.query)
                client_ip = self.client_address[0]
                
                script_content = dynamic.generate_dynamic_script(
                    params=params,
                    client_ip=client_ip
                )
                
                encoded_script = script_content.encode('utf-8')
                self.send_response(200)
                self.send_header("Content-type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(encoded_script)))
                self.end_headers()
                self.wfile.write(encoded_script)

            except Exception as e:
                log_message(f"HTTP: [Dynamic Script] 生成脚本时出错: {e}", "ERROR")
                error_message = b"#!ipxe\necho Error generating dynamic script on server.\nsanboot --no-describe --drive 0x80\n"
                self.send_response(500)
                self.send_header("Content-type", "text/plain")
                self.send_header("Content-Length", str(len(error_message)))
                self.end_headers()
                self.wfile.write(error_message)
            
            return

        fpath = self.translate_path(self.path)

        if os.path.isdir(fpath):
            log_message(f"HTTP: [目录浏览] 客户端 {self.client_address[0]} 正在浏览 '{self.path}'")
            super().do_GET()
            return

        if not os.path.isfile(fpath):
            self.send_error(404, "File not found")
            return

        filename = os.path.basename(fpath)
        client_ip = self.client_address[0]
        if self.client_manager:
            self.client_manager.handle_file_transfer_start(client_ip, filename)
        
        transfer_successful = False
        try:
            with open(fpath, 'rb') as f:
                fs = os.fstat(f.fileno())
                size = fs.st_size
                mtime = fs.st_mtime
                range_header = self.headers.get('Range')
                
                if not range_header:
                    self.send_response(200)
                    self.send_header("Content-type", self.guess_type(fpath))
                    self.send_header("Content-Length", str(size))
                    self.send_header("Accept-Ranges", "bytes")
                    # 添加Last-Modified和ETag头部
                    self.send_header("Last-Modified", self.date_time_string(mtime))
                    etag = f'"{size}-{int(mtime)}"'
                    self.send_header("ETag", etag)
                    self.end_headers()
                    self.copyfile(f, self.wfile)
                    log_message(f"HTTP: [200 GET] {self.path} -> {self.client_address[0]}")
                else:
                    self.send_response(206)
                    self.send_header("Accept-Ranges", "bytes")
                    try:
                        start_str, end_str = range_header.replace('bytes=', '').split('-')
                        start = int(start_str) if start_str else 0
                        end = int(end_str) if end_str else size - 1
                        if range_header.startswith('bytes=-'):
                            start = size - int(end_str)
                            end = size - 1
                    except ValueError:
                        self.send_error(400, "Invalid Range header")
                        return

                    if start >= size or end >= size or start > end:
                        self.send_response(416)
                        self.send_header("Content-Range", f"bytes */{size}")
                        self.end_headers()
                        return
                        
                    self.send_header("Content-type", self.guess_type(fpath))
                    self.send_header("Content-Range", f"bytes {start}-{end}/{size}")
                    content_length = end - start + 1
                    self.send_header("Content-Length", str(content_length))
                    # 添加Last-Modified和ETag头部
                    self.send_header("Last-Modified", self.date_time_string(mtime))
                    etag = f'"{size}-{int(mtime)}"'
                    self.send_header("ETag", etag)
                    self.end_headers()
                    
                    f.seek(start)
                    self.copyfile(f, self.wfile, length=content_length)
                    log_message(f"HTTP: [206 Partial] {self.path} ({start}-{end}) -> {self.client_address[0]}")
            
            transfer_successful = True
        except (BrokenPipeError, ConnectionResetError):
            transfer_successful = True
        except OSError:
            self.send_error(404, "File not found")
        finally:
            if self.client_manager and transfer_successful:
                self.client_manager.handle_file_transfer_complete(client_ip, filename)

    def copyfile(self, source, outputfile, length=None):
        bytes_to_send = length if length is not None else -1
        sent = 0
        while bytes_to_send < 0 or sent < bytes_to_send:
            buf_size = 65536
            if bytes_to_send > 0:
                buf_size = min(buf_size, bytes_to_send - sent)
            buf = source.read(buf_size)
            if not buf:
                break
            outputfile.write(buf)
            sent += len(buf)

class ThreadPoolTCPServer(socketserver.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True):
        super().__init__(server_address, RequestHandlerClass, bind_and_activate)
        self.executor = ThreadPoolExecutor(max_workers=20, thread_name_prefix='HTTP')
    def process_request(self, request, client_address):
        self.executor.submit(self.process_request_thread, request, client_address)
    def process_request_thread(self, request, client_address):
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.shutdown_request(request)
    def server_close(self):
        super().server_close()
        if hasattr(self, 'executor'):
            self.executor.shutdown(wait=True)

def run_http_server(cfg, stop_evt):
    http_root_dir = os.path.realpath(cfg['http_root'])
    
    if not os.path.exists(http_root_dir):
        try:
            os.makedirs(http_root_dir)
            log_message(f"HTTP: 已创建根目录 '{http_root_dir}'")
        except OSError as e:
            log_message(f"HTTP: 创建根目录失败: {e}", "ERROR")
            return

    class DirectoryAwareHandler(RangeRequestHandler):
        def __init__(self, *args, **kwargs):
            os.chdir(http_root_dir)
            super().__init__(*args, **kwargs)

    Handler = functools.partial(DirectoryAwareHandler, client_manager_instance=client_manager)
    
    use_multithread = cfg.get('http_multithread', True)
    http_server_class = ThreadPoolTCPServer if use_multithread else socketserver.TCPServer
    socketserver.TCPServer.allow_reuse_address = True
    
    try:
        with http_server_class((cfg['listen_ip'], cfg['http_port']), Handler) as httpd:
            log_message(f"HTTP: 服务器已在 http://{cfg['server_ip']}:{cfg['http_port']}/ 启动 ({'多线程' if use_multithread else '单线程'}, 根目录: {http_root_dir})")
            server_thread = threading.Thread(target=httpd.serve_forever)
            server_thread.daemon = True
            server_thread.start()
            stop_evt.wait()
            httpd.shutdown()
    except Exception as e:
        log_message(f"HTTP: 致命错误 - 无法启动服务器: {e}", "ERROR")
        
    log_message("HTTP: 服务器已停止。")

def manage_smb_share(settings, start=True):
    if os.name != 'nt':
        if start and settings.get('smb_enabled'):
            log_message("SMB: 自动共享管理仅在Windows上受支持。")
        return
    share_name, share_path = settings.get('smb_share_name'), os.path.realpath(settings.get('smb_root'))
    if not share_name or not share_path: return
    creation_flags = subprocess.CREATE_NO_WINDOW
    try: subprocess.run(['net', 'share', share_name, '/delete'], check=False, capture_output=True, creationflags=creation_flags)
    except FileNotFoundError: log_message("SMB: 'net' 命令未找到。", "ERROR"); return
    if not start: log_message(f"SMB: 共享 '{share_name}' 已停止。"); return
    if settings.get('smb_enabled'):
        if not os.path.exists(share_path):
            try: os.makedirs(share_path); log_message(f"SMB: 已创建根目录 '{share_path}'")
            except OSError as e: log_message(f"SMB: 创建根目录失败: {e}", "ERROR"); return
        try:
            permissions = '/grant:Everyone,FULL' if settings.get('smb_permissions') == 'full' else '/grant:Everyone,READ'
            perm_text = '完全控制' if 'FULL' in permissions else '只读'
            cmd = ['net', 'share', f'{share_name}={share_path}', permissions]
            subprocess.run(cmd, check=True, capture_output=True, text=True, creationflags=creation_flags)
            log_message(f"SMB: 已将 '{share_path}' 共享为 '{share_name}' ({perm_text})。访问路径: \\\\{settings['server_ip']}\\{share_name}")
        except subprocess.CalledProcessError as e:
            log_message(f"SMB: 创建共享失败。请以管理员身份运行。详情: {e.stderr.strip()}", "ERROR")

def is_smb_share_active(share_name):
    if os.name != 'nt' or not SETTINGS.get('smb_enabled'): return False
    try:
        result = subprocess.run(['net', 'share'], capture_output=True, text=True, check=True, encoding='utf-8', errors='ignore', creationflags=subprocess.CREATE_NO_WINDOW)
        return share_name in result.stdout
    except (subprocess.CalledProcessError, FileNotFoundError): return False

# --- [核心修改] start_services ---
def start_services():
    global dhcp_thread, tftp_thread, http_thread, proxy_thread, stop_event, dhcp_detector_thread
    stop_services()
    stop_event = threading.Event()
    log_message("--- 正在启动所有已启用的服务 ---")
    current_settings = SETTINGS.copy()
    
    # 将 client_manager 实例传递给 dynamic 模块
    dynamic.initialize_dynamic_scripting(current_settings, client_manager_instance=client_manager)
    
    manage_smb_share(current_settings, start=True)
    if current_settings['dhcp_enabled']:
        # 将 client_manager 实例传递给 DHCP 服务器线程
        dhcp_thread = threading.Thread(target=run_dhcp_server, args=(current_settings, stop_event, client_manager), daemon=True)
        dhcp_thread.start()
        proxy_thread = threading.Thread(target=run_proxy_listener, args=(current_settings, stop_event), daemon=True); proxy_thread.start()
        if current_settings['dhcp_mode'] == 'dhcp':
            dhcp_detector_thread = threading.Thread(target=detect_other_dhcp_servers, args=(stop_event,), daemon=True)
            dhcp_detector_thread.start()
    if current_settings['tftp_enabled']:
        tftp_thread = threading.Thread(target=run_tftp_server, args=(current_settings, stop_event), daemon=True); tftp_thread.start()
    if current_settings['http_enabled']:
        http_thread = threading.Thread(target=run_http_server, args=(current_settings, stop_event), daemon=True); http_thread.start()

# ... (stop_services, ConfigWindow, NBpxeApp 和 main 部分保持不变) ...
def stop_services():
    if 'stop_event' in globals() and not stop_event.is_set():
        log_message("--- 正在停止所有服务 ---"); stop_event.set()
    for t in [dhcp_thread, proxy_thread, tftp_thread, http_thread, dhcp_detector_thread]:
        if t and t.is_alive(): t.join(timeout=1.5)
    manage_smb_share(SETTINGS.copy(), start=False)
    
    if client_manager:
        client_manager.set_all_clients_offline_in_ini()

    log_message("--- 所有服务已停止 ---")

# ================================================================= #
# ======================== GUI-spezifischer Code ===================== #
# ================================================================= #

class ConfigWindow(tk.Toplevel):
    def __init__(self, parent):
        super().__init__(parent)
        self.title("配置")
        self.geometry("640x700")
        self.transient(parent)
        self.grab_set()
        self.settings_vars = {}
        
        self._ip_update_job = None

        notebook = ttk.Notebook(self)
        notebook.pack(pady=10, padx=10, expand=True, fill="both")
        general_frame = ttk.Frame(notebook, padding="10")
        path_frame = ttk.Frame(notebook, padding="10")
        boot_files_frame = ttk.Frame(notebook, padding="10")
        pxe_bios_frame = ttk.Frame(notebook, padding="10")
        pxe_uefi_frame = ttk.Frame(notebook, padding="10")
        pxe_ipxe_frame = ttk.Frame(notebook, padding="10")
        dhcp_options_frame = ttk.Frame(notebook, padding="10")
        notebook.add(general_frame, text="常规")
        notebook.add(path_frame, text="服务")
        notebook.add(boot_files_frame, text="引导文件")
        notebook.add(pxe_bios_frame, text="PXE 菜单 (BIOS)")
        notebook.add(pxe_uefi_frame, text="PXE 菜单 (UEFI)")
        notebook.add(pxe_ipxe_frame, text="iPXE 菜单")
        notebook.add(dhcp_options_frame, text="DHCP 自定义选项")
        self.create_general_tab(general_frame)
        self.create_path_tab(path_frame)
        self.create_boot_files_tab(boot_files_frame)
        self.create_pxe_menu_tab(pxe_bios_frame, 'bios')
        self.create_pxe_menu_tab(pxe_uefi_frame, 'uefi')
        self.create_pxe_menu_tab(pxe_ipxe_frame, 'ipxe')
        dhcp_option_handler.create_dhcp_options_tab(dhcp_options_frame, self.settings_vars, SETTINGS)
        
        self._enforce_ipxe_menu_dependency()

        button_frame = ttk.Frame(self)
        button_frame.pack(pady=5, padx=10, fill='x')
        ttk.Button(button_frame, text="保存并关闭", command=self.save_and_close).pack(side="right", padx=5)
        ttk.Button(button_frame, text="取消", command=self.destroy).pack(side="right")

    def _enforce_ipxe_menu_dependency(self, *args):
        is_bios_enabled = self.settings_vars.get('pxe_menu_bios_enabled', tk.BooleanVar(value=False)).get()
        is_uefi_enabled = self.settings_vars.get('pxe_menu_uefi_enabled', tk.BooleanVar(value=False)).get()

        if is_bios_enabled or is_uefi_enabled:
            if 'pxe_menu_ipxe_enabled' in self.settings_vars:
                self.settings_vars['pxe_menu_ipxe_enabled'].set(True)

    def _recalculate_dhcp_pool(self, basis_ip):
        try:
            ip_parts = basis_ip.split('.')
            if len(ip_parts) != 4 or not all(p.isdigit() and 0 <= int(p) <= 255 for p in ip_parts):
                return
            
            ip_prefix = ".".join(ip_parts[:-1])
            server_octet = int(ip_parts[-1])
            
            start_octet = server_octet + 100
            
            if start_octet > 254:
                start_octet = 101
            
            end_octet = min(start_octet + 49, 254)

            if start_octet > end_octet:
                end_octet = start_octet

            pool_start = f"{ip_prefix}.{start_octet}"
            pool_end = f"{ip_prefix}.{end_octet}"
            router = f"{ip_prefix}.1"
            dns = router

            if 'ip_pool_start' in self.settings_vars: self.settings_vars['ip_pool_start'].set(pool_start)
            if 'ip_pool_end' in self.settings_vars: self.settings_vars['ip_pool_end'].set(pool_end)
            if 'router_ip' in self.settings_vars: self.settings_vars['router_ip'].set(router)
            if 'dns_server_ip' in self.settings_vars: self.settings_vars['dns_server_ip'].set(dns)
        except (ValueError, IndexError):
            pass

    def _perform_ip_update(self):
        self._ip_update_job = None
        listen_ip_val = self.settings_vars['listen_ip'].get()
        
        listen_ip = '0.0.0.0' if '0.0.0.0' in listen_ip_val else listen_ip_val
        
        new_server_ip = listen_ip
        if listen_ip == '0.0.0.0':
            all_ips = get_all_ips()
            real_ips = [ip for ip in all_ips if ip not in ['127.0.0.1', '0.0.0.0']]
            new_server_ip = real_ips[0] if real_ips else ''

        if new_server_ip:
            if self.settings_vars['server_ip'].get() != new_server_ip:
                self.settings_vars['server_ip'].set(new_server_ip)
            
            self._recalculate_dhcp_pool(new_server_ip)

    def _schedule_ip_update(self, *args):
        if self._ip_update_job is not None:
            self.after_cancel(self._ip_update_job)
        
        self._ip_update_job = self.after(150, self._perform_ip_update)

    def create_general_tab(self, parent):
        parent.columnconfigure(1, weight=1)
        ttk.Label(parent, text="监听IP地址:").grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ips = get_all_ips(); ip_options = ['0.0.0.0 (所有网卡)'] + ips
        self.settings_vars['listen_ip'] = tk.StringVar(value=SETTINGS.get('listen_ip'))
        ip_combo = ttk.Combobox(parent, textvariable=self.settings_vars['listen_ip'], values=ip_options)
        ip_combo.grid(row=0, column=1, columnspan=3, sticky="ew", padx=5, pady=5)
        
        self.settings_vars['listen_ip'].trace_add('write', self._schedule_ip_update)

        ttk.Label(parent, text="本机服务器IP:").grid(row=1, column=0, sticky="w", padx=5, pady=5)
        self.settings_vars['server_ip'] = tk.StringVar(value=SETTINGS.get('server_ip'))
        server_ip_combo = ttk.Combobox(parent, textvariable=self.settings_vars['server_ip'], values=ips)
        server_ip_combo.grid(row=1, column=1, columnspan=3, sticky="ew", padx=5, pady=5)
        
        ttk.Label(parent, text="(用于通告给客户端，如TFTP Server IP)").grid(row=2, column=1, sticky="w", padx=5, pady=2, columnspan=3)
        ttk.Separator(parent, orient='horizontal').grid(row=3, column=0, columnspan=4, sticky='ew', pady=15)
        self.settings_vars['dhcp_enabled'] = tk.BooleanVar(value=SETTINGS.get('dhcp_enabled'))
        dhcp_enabled_check = ttk.Checkbutton(parent, text="启用 DHCP 服务", variable=self.settings_vars['dhcp_enabled'], command=self.toggle_dhcp_controls)
        dhcp_enabled_check.grid(row=4, column=0, columnspan=4, sticky="w", pady=(0, 10))
        self.dhcp_mode_label = ttk.Label(parent, text="DHCP 模式:")
        self.dhcp_mode_label.grid(row=5, column=0, sticky="w", padx=5, pady=10)
        self.settings_vars['dhcp_mode'] = tk.StringVar(value=SETTINGS.get('dhcp_mode'))
        self.radio_frame = ttk.Frame(parent)
        self.radio_frame.grid(row=5, column=1, columnspan=3, sticky="w")
        self.dhcp_radio = ttk.Radiobutton(self.radio_frame, text="DHCP (完整模式)", variable=self.settings_vars['dhcp_mode'], value='dhcp')
        self.dhcp_radio.pack(side="left")
        self.proxy_radio = ttk.Radiobutton(self.radio_frame, text="Proxy (代理模式)", variable=self.settings_vars['dhcp_mode'], value='proxy')
        self.proxy_radio.pack(side="left", padx=(10,0))
        self.dhcp_settings_frame = ttk.LabelFrame(parent, text="DHCP (完整模式) 设置", padding="10")
        self.dhcp_settings_frame.grid(row=6, column=0, columnspan=4, sticky="ew", pady=(10, 0), padx=2)
        self.dhcp_settings_frame.columnconfigure(1, weight=1); self.dhcp_settings_frame.columnconfigure(3, weight=1)
        fields = [("地址池起始:", 'ip_pool_start', 0, 0), ("地址池结束:", 'ip_pool_end', 0, 2),
                  ("子网掩码 (Opt 1):", 'subnet_mask', 1, 0), ("租约 (秒, Opt 51):", 'lease_time', 1, 2),
                  ("网关 (Opt 3):", 'router_ip', 2, 0), ("DNS (Opt 6):", 'dns_server_ip', 2, 2)]
        for label, key, r, c in fields:
            ttk.Label(self.dhcp_settings_frame, text=label).grid(row=r, column=c, sticky="w", pady=2, padx=5)
            VarClass = tk.IntVar if 'lease_time' in key else tk.StringVar
            self.settings_vars[key] = VarClass(value=SETTINGS.get(key))
            ttk.Entry(self.dhcp_settings_frame, textvariable=self.settings_vars[key]).grid(row=r, column=c+1, sticky="ew", pady=2, padx=5)
        self.settings_vars['dhcp_mode'].trace_add('write', self.toggle_dhcp_fields); self.toggle_dhcp_controls()

    def create_path_tab(self, parent):
        parent.columnconfigure(1, weight=1)
        def browse_directory(path_var):
            directory = filedialog.askdirectory()
            if directory: path_var.set(os.path.normpath(directory))
        def set_all_paths():
            self.settings_vars['tftp_root'].set('.')
            self.settings_vars['http_root'].set('.')
            self.settings_vars['smb_root'].set('.')
        tftp_frame = ttk.Frame(parent)
        tftp_frame.grid(row=0, column=0, columnspan=3, sticky="ew")
        self.settings_vars['tftp_enabled'] = tk.BooleanVar(value=SETTINGS.get('tftp_enabled'))
        ttk.Checkbutton(tftp_frame, text="启用 TFTP 服务", variable=self.settings_vars['tftp_enabled']).pack(side="left")
        self.settings_vars['tftp_multithread'] = tk.BooleanVar(value=SETTINGS.get('tftp_multithread'))
        ttk.Checkbutton(tftp_frame, text="多线程处理", variable=self.settings_vars['tftp_multithread']).pack(side="left", padx=(15,0))
        ttk.Label(parent, text="TFTP 根目录:").grid(row=1, column=0, sticky="w", pady=5)
        self.settings_vars['tftp_root'] = tk.StringVar(value=SETTINGS.get('tftp_root'))
        ttk.Entry(parent, textvariable=self.settings_vars['tftp_root']).grid(row=1, column=1, sticky="ew", pady=5)
        ttk.Button(parent, text="浏览...", command=lambda: browse_directory(self.settings_vars['tftp_root'])).grid(row=1, column=2, padx=5, pady=5)
        ttk.Separator(parent).grid(row=2, columnspan=3, sticky='ew', pady=10)
        http_frame = ttk.Frame(parent); http_frame.grid(row=3, column=0, columnspan=3, sticky="ew")
        self.settings_vars['http_enabled'] = tk.BooleanVar(value=SETTINGS.get('http_enabled'))
        ttk.Checkbutton(http_frame, text="启用 HTTP 服务", variable=self.settings_vars['http_enabled']).pack(side="left")
        self.settings_vars['http_multithread'] = tk.BooleanVar(value=SETTINGS.get('http_multithread'))
        ttk.Checkbutton(http_frame, text="多线程处理", variable=self.settings_vars['http_multithread']).pack(side="left", padx=(15,0))
        ttk.Label(parent, text="HTTP 端口:").grid(row=4, column=0, sticky="w", pady=5)
        self.settings_vars['http_port'] = tk.IntVar(value=SETTINGS.get('http_port'))
        ttk.Entry(parent, textvariable=self.settings_vars['http_port'], width=10).grid(row=4, column=1, sticky="w", pady=5)
        ttk.Label(parent, text="HTTP 根目录:").grid(row=5, column=0, sticky="w", pady=5)
        self.settings_vars['http_root'] = tk.StringVar(value=SETTINGS.get('http_root'))
        ttk.Entry(parent, textvariable=self.settings_vars['http_root']).grid(row=5, column=1, sticky="ew", pady=5)
        ttk.Button(parent, text="浏览...", command=lambda: browse_directory(self.settings_vars['http_root'])).grid(row=5, column=2, padx=5, pady=5)
        ttk.Separator(parent).grid(row=6, columnspan=3, sticky='ew', pady=10)
        self.settings_vars['smb_enabled'] = tk.BooleanVar(value=SETTINGS.get('smb_enabled'))
        ttk.Checkbutton(parent, text="启用 SMB 文件共享 (仅Windows)", variable=self.settings_vars['smb_enabled']).grid(row=7, column=0, columnspan=3, sticky="w")
        ttk.Label(parent, text="SMB 共享名称:").grid(row=8, column=0, sticky="w", pady=5)
        self.settings_vars['smb_share_name'] = tk.StringVar(value=SETTINGS.get('smb_share_name'))
        ttk.Entry(parent, textvariable=self.settings_vars['smb_share_name']).grid(row=8, column=1, sticky="ew", pady=5)
        ttk.Label(parent, text="共享权限:").grid(row=9, column=0, sticky="w", pady=5)
        self.settings_vars['smb_permissions'] = tk.StringVar(value=SETTINGS.get('smb_permissions', 'read'))
        smb_perm_frame = ttk.Frame(parent); smb_perm_frame.grid(row=9, column=1, sticky="w")
        ttk.Radiobutton(smb_perm_frame, text="只读", variable=self.settings_vars['smb_permissions'], value='read').pack(side="left")
        ttk.Radiobutton(smb_perm_frame, text="可写", variable=self.settings_vars['smb_permissions'], value='full').pack(side="left", padx=(10,0))
        ttk.Label(parent, text="SMB 根目录:").grid(row=10, column=0, sticky="w", pady=5)
        self.settings_vars['smb_root'] = tk.StringVar(value=SETTINGS.get('smb_root'))
        ttk.Entry(parent, textvariable=self.settings_vars['smb_root']).grid(row=10, column=1, sticky="ew", pady=5)
        ttk.Button(parent, text="浏览...", command=lambda: browse_directory(self.settings_vars['smb_root'])).grid(row=10, column=2, padx=5, pady=5)
        ttk.Separator(parent).grid(row=11, columnspan=3, sticky='ew', pady=15)
        ttk.Button(parent, text="一键设置为当前目录", command=set_all_paths).grid(row=12, column=1, sticky="w", pady=10)

    def create_boot_files_tab(self, parent):
        parent.columnconfigure(1, weight=1)
        new_description = """这些文件仅作为后备选项使用。
当对应客户端类型 (BIOS, UEFI, 或 iPXE) 的“菜单”功能被禁用时，服务器将提供这里指定的文件。"""
        ttk.Label(parent, text=new_description, wraplength=500, justify=tk.LEFT).grid(row=0, column=0, columnspan=3, sticky="w", pady=(5,15), padx=5)
        files_map = [("BIOS 启动文件:", 'bootfile_bios'), ("UEFI32 启动文件:", 'bootfile_uefi32'),
                     ("UEFI64 启动文件:", 'bootfile_uefi64'), ("iPXE 脚本文件:", 'bootfile_ipxe')]
        for i, (label, key) in enumerate(files_map):
            ttk.Label(parent, text=label).grid(row=i+1, column=0, sticky="w", pady=5, padx=5)
            self.settings_vars[key] = tk.StringVar(value=SETTINGS.get(key))
            ttk.Entry(parent, textvariable=self.settings_vars[key]).grid(row=i+1, column=1, sticky="ew", pady=5, padx=5)

    def create_pxe_menu_tab(self, parent, arch_type):
        parent.columnconfigure(1, weight=1)
        enabled_key = f'pxe_menu_{arch_type}_enabled'
        self.settings_vars[enabled_key] = tk.BooleanVar(value=SETTINGS.get(enabled_key))
        
        menu_check_text = f"为 {arch_type.upper()} 客户端启用此菜单"
        if arch_type == 'ipxe':
            menu_check_text = "为 iPXE 环境启用此菜单"

        check_frame = ttk.Frame(parent)
        check_frame.grid(row=0, column=0, columnspan=2, sticky="w", pady=5)
        
        menu_check = ttk.Checkbutton(check_frame, text=menu_check_text, variable=self.settings_vars[enabled_key])
        menu_check.pack(side="left")

        if arch_type in ['bios', 'uefi']:
            menu_check.config(command=self._enforce_ipxe_menu_dependency)
            ttk.Label(check_frame, text="(依赖iPXE菜单，将自动启用)", foreground="grey").pack(side="left", padx=5)

        pxe_menu_frame = ttk.LabelFrame(parent, text="菜单设置", padding="10")
        pxe_menu_frame.grid(row=1, column=0, columnspan=2, sticky="ew", pady=5); pxe_menu_frame.columnconfigure(1, weight=1)
        prompt_key, timeout_key, items_key = f'pxe_menu_{arch_type}_prompt', f'pxe_menu_{arch_type}_timeout', f'pxe_menu_{arch_type}_items'
        ttk.Label(pxe_menu_frame, text="菜单提示文本:").grid(row=0, column=0, sticky="w", pady=5)
        self.settings_vars[prompt_key] = tk.StringVar(value=SETTINGS.get(prompt_key))
        ttk.Entry(pxe_menu_frame, textvariable=self.settings_vars[prompt_key]).grid(row=0, column=1, sticky="ew", pady=5)
        ttk.Label(pxe_menu_frame, text="菜单超时 (秒):").grid(row=1, column=0, sticky="w", pady=5)
        timeout_frame = ttk.Frame(pxe_menu_frame)
        timeout_frame.grid(row=1, column=1, sticky="ew", pady=5)
        self.settings_vars[timeout_key] = tk.IntVar(value=SETTINGS.get(timeout_key))
        ttk.Entry(timeout_frame, textvariable=self.settings_vars[timeout_key], width=10).pack(side="left")
        randomize_key = f'pxe_menu_{arch_type}_randomize_timeout'
        self.settings_vars[randomize_key] = tk.BooleanVar(value=SETTINGS.get(randomize_key))
        ttk.Checkbutton(timeout_frame, text="客户机时间随机分配", variable=self.settings_vars[randomize_key]).pack(side="left", padx=(10, 0))
        items_frame = ttk.LabelFrame(pxe_menu_frame, text="启动菜单项定义", padding=5)
        items_frame.grid(row=2, column=0, columnspan=2, sticky='ew', pady=(10,5))
        menu_items_text = scrolledtext.ScrolledText(items_frame, wrap=tk.WORD, height=10, width=60)
        menu_items_text.pack(fill="both", expand=True); menu_items_text.insert(tk.END, SETTINGS.get(items_key, ''))
        self.settings_vars[items_key + '_widget'] = menu_items_text
        ttk.Label(pxe_menu_frame, text="格式: 菜单文本, 启动文件, 类型(4位Hex), 服务器IP", justify=tk.LEFT, foreground='grey').grid(row=3, column=0, columnspan=2, sticky='w', pady=(5,0))

    def toggle_widget_state(self, widgets, state):
        for widget in widgets:
            if isinstance(widget, (scrolledtext.ScrolledText, tk.Text)): widget.config(state=state)
            else:
                try: widget.config(state=state)
                except tk.TclError: pass
    
    def toggle_dhcp_fields(self, *args):
        is_dhcp_mode = self.settings_vars['dhcp_mode'].get() == 'dhcp'
        state = 'normal' if is_dhcp_mode else 'disabled'
        self.toggle_widget_state(self.dhcp_settings_frame.winfo_children(), state)

    def toggle_dhcp_controls(self, *args):
        is_enabled = self.settings_vars['dhcp_enabled'].get()
        state = 'normal' if is_enabled else 'disabled'
        widgets_to_toggle = [self.dhcp_mode_label, self.dhcp_radio, self.proxy_radio, self.dhcp_settings_frame]
        self.toggle_widget_state(widgets_to_toggle, state)
        if is_enabled: self.toggle_dhcp_fields()
        else: self.toggle_widget_state(self.dhcp_settings_frame.winfo_children(), 'disabled')

    def save_and_close(self):
        if self._ip_update_job is not None:
            self.after_cancel(self._ip_update_job)
            self._ip_update_job = None

        temp_settings = {}
        for key, var in self.settings_vars.items():
            if key.endswith('_widget'):
                widget = var; base_key = key.replace('_widget', '')
                temp_settings[base_key] = widget.get("1.0", tk.END).strip()
            else:
                try:
                    val = var.get()
                    if key == 'listen_ip' and val == '0.0.0.0 (所有网卡)': val = '0.0.0.0'
                    temp_settings[key] = val
                except (tk.TclError, ValueError): temp_settings[key] = 0 if isinstance(var, tk.IntVar) else ""
        SETTINGS.update(temp_settings); save_config_to_ini(); self.destroy()

class NBpxeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("NBPXE 服务器 20251119")
        self.root.geometry("800x600")
        main_frame = ttk.Frame(root, padding="10")
        main_frame.pack(fill="both", expand=True)
        status_frame = ttk.LabelFrame(main_frame, text="服务状态", padding="10")
        status_frame.pack(fill="x", pady=5)
        self.create_status_widgets(status_frame)
        paned_window = ttk.PanedWindow(main_frame, orient=tk.VERTICAL)
        paned_window.pack(fill="both", expand=True, pady=5)
        client_list_frame = ttk.LabelFrame(paned_window, text="客户端列表", padding="10")
        global client_manager
        client_manager = ClientManager(client_list_frame, log_message, settings=SETTINGS) # Pass settings
        client_manager.pack(fill="both", expand=True)
        log_frame = ttk.LabelFrame(paned_window, text="实时日志", padding="10")
        self.log_text = scrolledtext.ScrolledText(log_frame, wrap=tk.WORD, state='disabled', height=5)
        self.log_text.pack(fill="both", expand=True)
        self.log_text.tag_config('warning', foreground='orange', font=('Helvetica', 9, 'bold'))
        self.log_text.tag_config('error', foreground='red', font=('Helvetica', 9, 'bold'))
        self.log_text.tag_config('debug', foreground='grey')
        paned_window.add(client_list_frame, weight=3)
        paned_window.add(log_frame, weight=1)
        control_frame = ttk.Frame(main_frame, padding="5")
        control_frame.pack(fill="x")
        self.create_control_widgets(control_frame)
        self.process_log_queue()
        self.update_status_display()
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
             
       
       
    
    def create_status_widgets(self, parent):
        self.status_labels = {}
        services = ["DHCP", "TFTP", "HTTP", "SMB"]
        for i, service in enumerate(services):
            ttk.Label(parent, text=f"{service}:").grid(row=0, column=i*2, sticky="w", padx=(0, 5))
            self.status_labels[service] = ttk.Label(parent, text="■ 已停止", foreground="red", font=('Helvetica', 9, 'bold'))
            self.status_labels[service].grid(row=0, column=i*2+1, sticky="w", padx=(0, 20))
    
    def create_control_widgets(self, parent):
        ttk.Button(parent, text="启动 / 重启服务", command=start_services).pack(side="left", padx=5, pady=5)
        ttk.Button(parent, text="停止所有服务", command=stop_services).pack(side="left", padx=5, pady=5)
        ttk.Button(parent, text="修改配置", command=lambda: ConfigWindow(self.root)).pack(side="left", padx=5, pady=5)
        ttk.Button(parent, text="重置配置文件", command=self.reset_ini_file).pack(side="left", padx=(15, 5), pady=5)
        ttk.Button(parent, text="退出程序", command=self.on_closing).pack(side="right", padx=5, pady=5)

    def reset_ini_file(self):
        if messagebox.askyesno("重置配置?", f"您确定要删除配置文件 '{INI_FILENAME}' 吗?\n\n程序将在操作后关闭，请您手动重启以便生成新的默认配置。"):
            stop_services()
            try:
                if os.path.exists(INI_FILENAME):
                    os.remove(INI_FILENAME)
                messagebox.showinfo("重置成功", f"配置文件 '{INI_FILENAME}' 已被删除。\n程序即将关闭，请手动重启。")
                self.on_closing(force=True)
            except Exception as e:
                messagebox.showerror("删除失败", f"无法删除配置文件 '{INI_FILENAME}': {e}")

    def on_closing(self, force=False):
        if force or messagebox.askokcancel("退出", "您确定要退出 NBPXE 服务器吗？"):
            if client_manager:
                client_manager.stop_monitoring()
            stop_services()
            self.root.destroy()
    
    def process_log_queue(self):
        try:
            while True:
                msg, level = log_queue.get_nowait()
                tag = level.lower() if level in ['WARNING', 'ERROR', 'DEBUG'] else ''
                self.log_text.config(state='normal')
                self.log_text.insert(tk.END, msg + '\n', tag)
                self.log_text.see(tk.END)
                self.log_text.config(state='disabled')
        except queue.Empty: pass
        finally:
            self.root.after(100, self.process_log_queue)

    def update_status_display(self):
        is_dhcp_running = dhcp_thread and dhcp_thread.is_alive()
        is_proxy_running = proxy_thread and proxy_thread.is_alive()
        if SETTINGS.get('dhcp_enabled'):
            if is_dhcp_running and is_proxy_running:
                mode = SETTINGS.get('dhcp_mode', 'proxy').upper()
                self.status_labels["DHCP"].config(text=f"● 运行中 ({mode})", foreground="green")
            else: self.status_labels["DHCP"].config(text="■ 未启动", foreground="orange")
        else: self.status_labels["DHCP"].config(text="■ 已禁用", foreground="grey")
        is_tftp_running = tftp_thread and tftp_thread.is_alive()
        if SETTINGS.get('tftp_enabled'):
            text, color = ("● 运行中", "green") if is_tftp_running else ("■ 未启动", "orange")
            self.status_labels["TFTP"].config(text=text, foreground=color)
        else: self.status_labels["TFTP"].config(text="■ 已禁用", foreground="grey")
        is_http_running = http_thread and http_thread.is_alive()
        if SETTINGS.get('http_enabled'):
            text, color = ("● 运行中", "green") if is_http_running else ("■ 未启动", "orange")
            self.status_labels["HTTP"].config(text=text, foreground=color)
        else: self.status_labels["HTTP"].config(text="■ 已禁用", foreground="grey")
        if SETTINGS.get('smb_enabled'):
            if is_smb_share_active(SETTINGS.get('smb_share_name')):
                self.status_labels["SMB"].config(text="● 共享中", foreground="green")
            else: self.status_labels["SMB"].config(text="■ 未共享", foreground="orange")
        else: self.status_labels["SMB"].config(text="■ 已禁用", foreground="grey")
        self.root.after(1000, self.update_status_display)

if __name__ == '__main__':
    if not load_config_from_ini():
        root = tk.Tk(); root.withdraw()
        messagebox.showerror("配置错误", f"无法加载或创建 '{INI_FILENAME}'。\n请检查文件权限或内容。\n程序即将退出。")
        sys.exit(1)
    
    log_message(f"日志文件保存在: {os.path.abspath(LOG_FILENAME)}")
    root = tk.Tk()
    app = NBpxeApp(root)
    root.mainloop()
