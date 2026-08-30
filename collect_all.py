import requests
import base64
import json
import re
from urllib.parse import urlparse, unquote, parse_qs
from datetime import datetime

headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept-Encoding': 'gzip, deflate'
}

# ==================== 配置参数 ====================
TIMEOUT = 15
GROUP_SIZE = 500                    # 每组节点数量

OUTPUT_RAW = 'valid_content_all.yaml'      # 分组前完整文件（YAML格式）
OUTPUT_PREFIX = 'valid_content_all'        # 分组后文件前缀，最终为 valid_content_all_1.yaml ...

# Mihomo 支持的协议类型（小写）
MIHOMO_SUPPORTED = {
    'ss', 'ss2022', 'vmess', 'vless', 'trojan',
    'hysteria', 'hysteria2', 'tuic', 'wireguard',
    'snell', 'http', 'socks5', 'ssh', 'mieru',
    'direct', 'reject', 'dns'
}

# URL scheme 到 Clash type 的映射
URL_SCHEMES = {
    'ss': 'ss', 'vmess': 'vmess', 'vless': 'vless',
    'trojan': 'trojan', 'hysteria': 'hysteria',
    'hysteria2': 'hysteria2', 'tuic': 'tuic',
    'socks5': 'socks5', 'http': 'http'
}

# ==================== 工具函数 ====================

def is_valid_url(url):
    """验证URL格式是否合法"""
    try:
        r = urlparse(url)
        return r.scheme in ['http', 'https'] and bool(r.netloc)
    except:
        return False

def safe_b64_decode(text):
    """安全的Base64解码，失败返回None"""
    try:
        padding = 4 - len(text) % 4
        if padding != 4:
            text += '=' * padding
        return base64.b64decode(text).decode('utf-8')
    except Exception:
        return None

def parse_vmess(b64_data, idx):
    """解析 vmess:// Base64内容"""
    try:
        raw = safe_b64_decode(b64_data)
        if not raw:
            return None
        data = json.loads(raw)
        if not data.get('add'):
            return None
        proxy = {
            'name': data.get('ps', f'VMess-{idx}'),
            'type': 'vmess',
            'server': data['add'],
            'port': int(data.get('port', 0)),
            'uuid': data.get('id', ''),
            'alterId': int(data.get('aid', 0)),
            'cipher': data.get('scy', 'auto'),
            'tls': data.get('tls', '') == 'tls',
            'network': data.get('net', 'tcp'),
            'udp': True
        }
        # ws/grpc 额外参数
        if proxy['network'] == 'ws':
            proxy['ws-opts'] = {
                'path': data.get('path', '/'),
                'headers': {'Host': data.get('host', '')}
            }
        elif proxy['network'] == 'grpc':
            proxy['grpc-opts'] = {'grpc-service-name': data.get('path', '')}
        return proxy
    except Exception:
        return None

def parse_ss(url, idx):
    """解析 ss:// 链接"""
    try:
        p = urlparse(url)
        server, port = p.hostname, p.port
        # 尝试 method:password 格式
        if p.username and p.password:
            method = unquote(p.username)
            password = unquote(p.password)
        else:
            # Base64 编码的 userinfo
            userinfo = safe_b64_decode(p.username or '')
            if not userinfo or ':' not in userinfo:
                return None
            method, password = userinfo.split(':', 1)
        name = unquote(p.fragment) if p.fragment else f'SS-{idx}'
        if not all([server, port, method, password]):
            return None
        return {
            'name': name, 'type': 'ss', 'server': server, 'port': port,
            'cipher': method, 'password': password
        }
    except Exception:
        return None

def parse_standard_url(url, idx, ptype):
    """解析 trojan / vless / hysteria2 / tuic / http / socks5"""
    try:
        p = urlparse(url)
        name = unquote(p.fragment) if p.fragment else f'{ptype.upper()}-{idx}'
        proxy = {
            'name': name,
            'type': ptype,
            'server': p.hostname,
            'port': p.port or (443 if ptype in ('trojan', 'vless', 'hysteria2', 'tuic') else 80),
            'udp': True
        }
        if ptype == 'trojan':
            proxy['password'] = unquote(p.username or '')
            proxy['tls'] = True
        elif ptype == 'vless':
            proxy['uuid'] = p.username
        elif ptype == 'hysteria2':
            proxy['password'] = unquote(p.username or '')
            proxy['up'] = '50 Mbps'
            proxy['down'] = '100 Mbps'
        elif ptype == 'tuic':
            proxy['uuid'] = p.username
            proxy['password'] = unquote(p.password or '')
        elif ptype in ('http', 'socks5') and p.username:
            proxy['username'] = unquote(p.username)
            proxy['password'] = unquote(p.password or '')
        return proxy
    except Exception:
        return None

def url_to_proxy(url, idx):
    """将单条URL转换为Clash proxy字典"""
    if '://' not in url:
        return None
    scheme = url.split('://')[0].lower()
    # 明确不支持的协议直接丢弃
    if scheme in ('ssr', 'brook', 'relay'):
        return None
    if scheme == 'vmess':
        return parse_vmess(url.split('://')[1], idx)
    elif scheme == 'ss':
        return parse_ss(url, idx)
    elif scheme in URL_SCHEMES:
        return parse_standard_url(url, idx, URL_SCHEMES[scheme])
    return None

def extract_proxies_from_yaml(text):
    """简易YAML解析器：提取 proxies: 下的节点列表"""
    proxies = []
    lines = text.splitlines()
    in_proxies = False
    current = {}
    
    for raw in lines:
        line = raw.rstrip()
        if not line or line.startswith('#'):
            continue
        
        # 检测 proxies: 起始
        if line.strip() in ('proxies:', 'Proxy:'):
            in_proxies = True
            continue
        
        if not in_proxies:
            continue
            
        indent = len(line) - len(line.lstrip())
        stripped = line.strip()
        
        # 顶级新section，结束proxies
        if indent == 0 and stripped.endswith(':') and stripped not in ('proxies:', 'Proxy:'):
            if current and 'type' in current:
                proxies.append(current)
            in_proxies = False
            current = {}
            continue
        
        # 新节点开始
        if indent == 2 and stripped.startswith('- '):
            if current and 'type' in current:
                proxies.append(current)
            current = {}
            if stripped.startswith('- name:'):
                current['name'] = stripped.split(':', 1)[1].strip().strip('"\'')
            elif stripped.startswith('- {'):
                try:
                    current = json.loads(stripped[2:].strip())
                except:
                    current = {}
        # 节点属性
        elif indent == 4 and current is not None and ':' in stripped:
            k, v = stripped.split(':', 1)
            k, v = k.strip(), v.strip().strip('"\'')
            # 类型转换
            if v.lower() == 'true':
                v = True
            elif v.lower() == 'false':
                v = False
            else:
                try:
                    v = int(v)
                except ValueError:
                    try:
                        v = float(v)
                    except ValueError:
                        pass
            current[k] = v
    
    if current and 'type' in current:
        proxies.append(current)
    return proxies

def proxy_to_yaml_lines(proxy):
    """将单个proxy字典转为YAML行列表"""
    lines = [f"  - name: {json.dumps(proxy.get('name', 'Unnamed'))}"]
    done = {'name'}
    
    # 优先字段顺序
    priority = ['type', 'server', 'port', 'uuid', 'cipher', 'password',
                'alterId', 'tls', 'sni', 'servername', 'network', 'udp',
                'flow', 'up', 'down', 'skip-cert-verify']
    for k in priority:
        if k in proxy and k not in done:
            v = proxy[k]
            if isinstance(v, str):
                lines.append(f"    {k}: {json.dumps(v)}")
            elif isinstance(v, bool):
                lines.append(f"    {k}: {str(v).lower()}")
            else:
                lines.append(f"    {k}: {v}")
            done.add(k)
    
    # 其余字段
    for k, v in proxy.items():
        if k in done:
            continue
        if isinstance(v, str):
            lines.append(f"    {k}: {json.dumps(v)}")
        elif isinstance(v, bool):
            lines.append(f"    {k}: {str(v).lower()}")
        elif isinstance(v, (int, float)):
            lines.append(f"    {k}: {v}")
        elif isinstance(v, dict):
            lines.append(f"    {k}:")
            for k2, v2 in v.items():
                if isinstance(v2, str):
                    lines.append(f"      {k2}: {json.dumps(v2)}")
                elif isinstance(v2, bool):
                    lines.append(f"      {k2}: {str(v2).lower()}")
                elif isinstance(v2, dict):
                    lines.append(f"      {k2}:")
                    for k3, v3 in v2.items():
                        lines.append(f"        {k3}: {json.dumps(v3)}")
    return lines

def build_clash_yaml(proxies, group_name="Proxy"):
    """生成标准Clash/Mihomo YAML配置文本"""
    lines = [
        "# Mihomo / Clash Meta 配置文件",
        f"# 生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"# 节点数量: {len(proxies)}",
        ""
    ]
    
    lines.append("proxies:")
    for p in proxies:
        lines.extend(proxy_to_yaml_lines(p))
    
    lines.extend([
        "",
        "proxy-groups:",
        f"  - name: {json.dumps(group_name)}",
        "    type: select",
        "    proxies:"
    ])
    for p in proxies:
        lines.append(f"      - {json.dumps(p.get('name', 'Unnamed'))}")
    
    return '\n'.join(lines)

def save_yaml(proxies, filepath):
    """保存为YAML文件"""
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(build_clash_yaml(proxies))
    return filepath

# ==================== 主程序 ====================

# 获取原始URL列表
sub_all_clash_url = 'https://raw.githubusercontent.com/maimengmeng/collectSub/main/sub/sub_all_clash.txt'
try:
    response = requests.get(sub_all_clash_url, headers=headers, timeout=10)
    response.raise_for_status()
    raw_urls = response.text.splitlines()
    print(f"原始列表包含 {len(raw_urls)} 个URL")
except Exception as e:
    print(f"获取URL列表失败: {e}")
    exit()

# 预处理URL列表
valid_urls = [url.strip() for url in raw_urls if is_valid_url(url.strip())]
print(f"经过格式验证的有效URL数量：{len(valid_urls)}")

all_proxies = []      # 所有解析后的节点
success_count = 0
processed_count = 0

for url in valid_urls:
    processed_count += 1
    
    # 显示进度
    if processed_count % 10 == 0:
        print(f"[进度] 已处理 {processed_count} 个 | 成功 {success_count} 个 ")
    
    try:
        resp = requests.get(url, headers=headers, timeout=TIMEOUT)
        resp.raise_for_status()
        text = resp.text.strip()
        
        # 内容有效性检查（保留YAML格式内容）
        if len(text) < 10:
            continue
        # 若包含DOMAIN且不是标准Clash配置，则跳过
        if "DOMAIN" in text and 'proxies:' not in text and 'Proxy:' not in text:
            continue
            
        # 编码检测 & Base64解码
        resp.encoding = resp.apparent_encoding
        decoded = safe_b64_decode(resp.text) or resp.text
        
        proxies = []
        
        # 判断内容类型并提取节点
        if 'proxies:' in decoded or 'Proxy:' in decoded:
            # 标准Clash YAML配置
            proxies = extract_proxies_from_yaml(decoded)
        else:
            # 作为URL列表处理（逐行解析）
            line_idx = 0
            for line in decoded.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                p = url_to_proxy(line, line_idx)
                if p:
                    proxies.append(p)
                    line_idx += 1
        
        # 过滤Mihomo不支持的协议类型
        filtered = [p for p in proxies if p.get('type', '').lower() in MIHOMO_SUPPORTED]
        
        if filtered:
            all_proxies.extend(filtered)
            success_count += 1
            
    except requests.exceptions.RequestException:
        continue
    except Exception:
        continue

# 去重：根据 name + server + port
seen = set()
unique_proxies = []
for p in all_proxies:
    key = (p.get('name', ''), p.get('server', ''), p.get('port', 0))
    if key not in seen:
        seen.add(key)
        unique_proxies.append(p)

total = len(unique_proxies)
print(f"\n{'='*50}")
print(f"去重前节点数：{len(all_proxies)}")
print(f"去重后节点数：{total}")

if total == 0:
    print("未获取到任何有效节点，程序结束")
    exit()

# ---------- 保存分组前完整文件 ----------
save_yaml(unique_proxies, OUTPUT_RAW)
print(f"分组前完整YAML已保存：{OUTPUT_RAW}")

# ---------- 分组保存，每500个一组 ----------
group_num = (total + GROUP_SIZE - 1) // GROUP_SIZE
print(f"\n节点分组：共 {total} 个节点，分为 {group_num} 组（每组最多 {GROUP_SIZE} 个）")

for i in range(group_num):
    start = i * GROUP_SIZE
    end = min(start + GROUP_SIZE, total)
    group_proxies = unique_proxies[start:end]
    
    suffix = i + 1
    filepath = f"{OUTPUT_PREFIX}_{suffix}.yaml"
    save_yaml(group_proxies, filepath)
    print(f"  第 {suffix} 组 ({start+1} - {end}) 已保存：{filepath}")

# ---------- 最终结果报告 ----------
print(f"\n{'='*50}")
print(f"最终结果：")
print(f"  处理URL总数：{processed_count}")
print(f"  成功获取订阅数：{success_count}")
print(f"  有效节点总数：{total}")
print(f"  分组数量：{group_num}")
print(f"  分组前文件：{OUTPUT_RAW}")
print(f"  分组后文件：{OUTPUT_PREFIX}_1.yaml ~ {OUTPUT_PREFIX}_{group_num}.yaml")
print(f"{'='*50}")
