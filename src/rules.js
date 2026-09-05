// ============================================================
// DSH Security Guard - detection rule library
// 28 built-in rules covering token theft, data exfil, code
// execution, obfuscation, network, filesystem, process,
// supply-chain, persistence and privilege escalation.
// ============================================================

export const RULE_CATEGORIES = {
  'token-theft': 'Token 窃取',
  'data-exfil': '数据外发',
  'credential-access': '凭据访问',
  'code-execution': '代码执行',
  'obfuscation': '代码混淆',
  'network': '网络行为',
  'filesystem': '文件系统',
  'process': '进程操作',
  'supply-chain': '供应链攻击',
  'persistence': '持久化植入',
  'privilege-escalation': '权限提升',
}

export const SEVERITY_WEIGHTS = {
  info: 1,
  low: 2,
  medium: 5,
  high: 10,
  critical: 25,
}

export const CATEGORY_WEIGHTS = {
  'token-theft': 3,
  'data-exfil': 3,
  'credential-access': 2.5,
  'code-execution': 2,
  'privilege-escalation': 2,
}

export const SEVERITY_COLORS = {
  info: '#3b82f6',
  low: '#22c55e',
  medium: '#eab308',
  high: '#f97316',
  critical: '#ef4444',
}

/**
 * SecurityRule = {
 *   id, name, severity, category, description,
 *   patterns: RegExp[],
 *   filePatterns?: string[]  // e.g. ['package.json']
 *   enabled?: boolean
 * }
 */
export const DEFAULT_RULES = [
  // ====== 1. Token theft ======
  {
    id: 'TOK-001',
    name: '硬编码 API Key / Token',
    severity: 'critical',
    category: 'token-theft',
    description: '检测到硬编码的 API Key、Access Token 或 Secret 字符串',
    patterns: [
      /['"]\s*sk-[a-zA-Z0-9]{20,}\s*['"]/,
      /['"]\s*ghp_[a-zA-Z0-9]{30,}\s*['"]/,
      /['"]\s*glpat-[a-zA-Z0-9\-]{20,}\s*['"]/,
      /['"]\s*AKIA[0-9A-Z]{16}\s*['"]/,
      /['"]\s*[0-9a-zA-Z/+]{40}\s*['"].{0,50}secret/i,
      /api[_-]?key\s*[:=]\s*['"][^'"]{10,}['"]/i,
      /access[_-]?token\s*[:=]\s*['"][^'"]{10,}['"]/i,
    ],
  },
  {
    id: 'TOK-002',
    name: 'Token 外发（HTTP 请求携带敏感信息）',
    severity: 'critical',
    category: 'token-theft',
    description: '检测到将本地 Token/凭据通过 HTTP 发送到外部地址',
    patterns: [
      /fetch\s*\(\s*['"`][^'"`]*(?:http|https):\/\/[^'"`]*['"`].*headers.*Authorization/i,
      /axios\.[a-z]+\s*\(\s*['"`][^'"`]*(?:http|https):\/\/[^'"`]*['"`].*headers.*Authorization/i,
      /new\s+XMLHttpRequest\(\).*open\s*\(\s*['"`](?:POST|PUT)['"`].*send\s*\(\s*.*token/i,
      /navigator\.sendBeacon\s*\(\s*['"`][^'"`]*http/i,
    ],
  },
  {
    id: 'TOK-003',
    name: '读取 DSH 会话/凭据文件',
    severity: 'high',
    category: 'credential-access',
    description: '尝试读取 DSH 的会话存储、凭据文件或 SSH/云厂商凭据',
    patterns: [
      /readFile.*(?:\.dsh|sessions|credentials|config\.json|cordis\.patch)/i,
      /readdir.*(?:\.dsh|sessions)/i,
      /fs\.[a-z]*.*(?:\.env|\.ssh|id_rsa|id_ed25519|\.aws|\.azure)/i,
      /require\s*\(\s*['"`]os['"`]\s*\).*homedir.*readFile/i,
    ],
  },
  {
    id: 'TOK-004',
    name: '环境变量凭据读取',
    severity: 'low',
    category: 'credential-access',
    description: '读取或导出环境变量中的敏感信息（单条读取为常规实践，批量导出需关注）',
    patterns: [
      /Object\.keys\s*\(\s*process\.env\s*\)/,
      /JSON\.stringify\s*\(\s*process\.env\s*\)/,
      /process\.env\.[A-Z_0-9]*(?:KEY|TOKEN|SECRET|PASS)/i,
    ],
  },

  // ====== 2. Data exfiltration ======
  {
    id: 'EXF-001',
    name: '可疑外发域名',
    severity: 'high',
    category: 'data-exfil',
    description: '检测到向已知可疑域名、临时域名或非回环原始 IP 地址外发数据',
    patterns: [
      /['"`][^'"`]*(?:pastebin|webhook\.site|requestbin|hookbin|ngrok\.io|serveo\.net|localhost\.run)['"`]/i,
      /['"`](?!(?:127\.|0\.0\.0\.0|::ffff:127\.))[^'"`]*\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}['"`]/,
      /['"`][^'"`]*\.tk\b|\.ml\b|\.ga\b|\.cf\b|\.gq\b['"`]/i,
    ],
  },
  {
    id: 'EXF-002',
    name: '隐蔽数据外发（DNS/ICMP 隧道）',
    severity: 'critical',
    category: 'data-exfil',
    description: '检测到使用 DNS 查询或 ICMP 包携带敏感数据',
    patterns: [
      /dns\.resolve.*\+\s*.*(?:token|key|secret)/i,
      /child_process.*ping.*-p.*[a-zA-Z0-9]{20,}/i,
      /dgram\.createSocket.*icmp/i,
    ],
  },
  {
    id: 'EXF-003',
    name: '剪贴板读取与外发',
    severity: 'high',
    category: 'data-exfil',
    description: '读取用户剪贴板内容并可能外发',
    patterns: [
      /navigator\.clipboard\.readText/,
      /clipboardy\.[a-z]+/,
      /execa.*(?:xclip|xsel|pbpaste)/,
    ],
  },

  // ====== 3. Code execution ======
  {
    id: 'EXE-001',
    name: '动态代码执行（eval / Function / vm）',
    severity: 'high',
    category: 'code-execution',
    description: '使用 eval、new Function 或 vm 模块执行动态代码',
    patterns: [
      /\beval\s*\(/,
      /new\s+Function\s*\(/,
      /require\s*\(\s*['"`]vm['"`]\s*\)/,
      /vm\.runInNewContext|vm\.runInThisContext|vm\.Script/,
      /setTimeout\s*\(\s*['"`].*['"`]/,
      /setInterval\s*\(\s*['"`].*['"`]/,
    ],
  },
  {
    id: 'EXE-002',
    name: '子进程执行（shell 命令）',
    severity: 'medium',
    category: 'process',
    description: '使用 child_process 执行系统命令',
    patterns: [
      /require\s*\(\s*['"`]child_process['"`]\s*\)/,
      /child_process\.(?:exec|execSync|spawn|fork)/,
      /spawn\s*\(\s*['"`]\s*(?:bash|sh|cmd|powershell|python|curl|wget)['"`]/i,
    ],
  },
  {
    id: 'EXE-003',
    name: '远程代码加载（require from URL）',
    severity: 'critical',
    category: 'code-execution',
    description: '从远程 URL 动态加载并执行代码',
    patterns: [
      /require\s*\(\s*['"`]https?:\/\//,
      /import\s*\(\s*['"`]https?:\/\//,
      /fetch.*then\s*\(\s*.*eval/,
      /new\s+Function\s*\(\s*await\s+fetch/,
    ],
  },

  // ====== 4. Obfuscation ======
  {
    id: 'OBF-001',
    name: '代码混淆（高熵字符串）',
    severity: 'medium',
    category: 'obfuscation',
    description: '检测到疑似混淆的代码（超长 Base64、Hex 转义、fromCharCode 拼接）',
    patterns: [
      /['"`][A-Za-z0-9+/]{100,}={0,2}['"`]/,
      /['"`][\\x0-9a-f]{50,}['"`]/i,
      /String\.fromCharCode\s*\(\s*\d{2,3}(?:\s*,\s*\d{2,3}){10,}\s*\)/,
    ],
  },
  {
    id: 'OBF-002',
    name: '自定义解码/解压后执行',
    severity: 'high',
    category: 'obfuscation',
    description: '检测到先解码/解压再执行的代码模式',
    patterns: [
      /atob\s*\(.*\).*eval/,
      /Buffer\.from\s*\(.*['"`].*['"`].*\).*toString\s*\(\s*\).*eval/,
      /zlib\.(?:inflate|gunzip|brotliDecompress).*eval/,
      /JSON\.parse\s*\(\s*.*decode/,
    ],
  },
  {
    id: 'OBF-003',
    name: 'JSFuck / 极简混淆',
    severity: 'medium',
    category: 'obfuscation',
    description: '使用 []()!+ 等字符构造的极简混淆代码',
    patterns: [
      /\[\]\[!+\(\)\]{50,}/,
    ],
  },

  // ====== 5. Network ======
  {
    id: 'NET-001',
    name: '未授权网络监听/代理',
    severity: 'high',
    category: 'network',
    description: '创建网络服务器或代理，可能形成中间人攻击面',
    patterns: [
      /createServer\s*\(\s*\)/,
      /http\.(?:createServer|Server)/,
      /net\.createServer/,
      /https?\.createServer/,
      /proxy\s*\(\s*\{.*target/,
    ],
  },
  {
    id: 'NET-002',
    name: 'WebSocket 外发连接',
    severity: 'medium',
    category: 'network',
    description: '检测到 WebSocket 连接到外部服务器',
    patterns: [
      /new\s+WebSocket\s*\(\s*['"`][^'"`]*ws/i,
      /ws\.(?:connect|WebSocket)/,
    ],
  },
  {
    id: 'NET-003',
    name: '代理配置篡改',
    severity: 'medium',
    category: 'network',
    description: '读取或修改系统代理设置，可能劫持流量',
    patterns: [
      /HTTP_PROXY|HTTPS_PROXY|ALL_PROXY/i,
      /process\.env\.[A-Z_]*PROXY/i,
      /proxy.*http.*agent/i,
    ],
  },

  // ====== 6. Filesystem ======
  {
    id: 'FS-001',
    name: '越界文件写入（工作区外）',
    severity: 'high',
    category: 'filesystem',
    description: '尝试向工作区外或敏感系统路径写入文件',
    patterns: [
      /writeFile.*(?:\/etc\/|C:\\Windows\\|~\/\.|\.\.\/\.\.\/)/i,
      /fs\.appendFile.*\/(?:bashrc|zshrc|profile|crontab)/i,
      /copyFile.*\/(?:\.ssh|\.gnupg|\.aws)/i,
    ],
  },
  {
    id: 'FS-002',
    name: '删除/篡改系统文件',
    severity: 'critical',
    category: 'filesystem',
    description: '检测到删除或篡改系统关键文件的行为',
    patterns: [
      /fs\.unlink.*(?:\/etc\/|C:\\Windows\\|\.dsh\/)/i,
      /fs\.rmdir.*(?:\/etc\/|C:\\Windows\\)/i,
      /rm\s+-rf/,
    ],
  },
  {
    id: 'FS-003',
    name: '文件搜索遍历（全盘扫描）',
    severity: 'medium',
    category: 'filesystem',
    description: '递归搜索用户目录寻找敏感文件',
    patterns: [
      /glob\s*\(\s*['"`]\*\*\/.env['"`]/,
      /readdir.*homedir.*recursive/,
      /find.*-name.*\.ssh/,
    ],
  },

  // ====== 7. Process ======
  {
    id: 'PRO-001',
    name: '进程注入/内存操作',
    severity: 'critical',
    category: 'process',
    description: '尝试注入其他进程或读取进程内存',
    patterns: [
      /ptrace|process_vm_readv|\/proc\/\d+\/mem/,
      /frida|inject.*process/,
    ],
  },
  {
    id: 'PRO-002',
    name: '权限提升（sudo/setuid）',
    severity: 'critical',
    category: 'privilege-escalation',
    description: '尝试获取 root 权限或修改权限位',
    patterns: [
      /sudo|doas|pkexec/,
      /fs\.chmod.*0o4\d\d\d/,
      /setuid|setgid/,
      /child_process.*sudo/,
    ],
  },

  // ====== 8. Supply chain ======
  {
    id: 'SUP-001',
    name: '可疑依赖安装脚本（postinstall/preinstall）',
    severity: 'high',
    category: 'supply-chain',
    description: 'package.json 中的 install 脚本执行可疑命令',
    patterns: [
      /"(?:postinstall|preinstall|install)"\s*:\s*"[^"]*(?:curl|wget|fetch|eval|exec|bash|sh |python )/i,
    ],
    filePatterns: ['package.json'],
  },
  {
    id: 'SUP-002',
    name: '依赖混淆（typosquatting）',
    severity: 'medium',
    category: 'supply-chain',
    description: '检测到可能与知名包名混淆的依赖名',
    patterns: [
      /"lodashs"|"expresss"|"reactt"|"axiosx"|"vuee"|"angularr"/i,
    ],
    filePatterns: ['package.json'],
  },
  {
    id: 'SUP-003',
    name: 'Git 仓库投毒（.git 目录篡改）',
    severity: 'high',
    category: 'supply-chain',
    description: '篡改 Git 钩子或配置文件植入后门',
    patterns: [
      /writeFile.*\.git\/hooks/,
      /fs\.appendFile.*\.git\/config/,
      /exec.*git.*config.*url/,
    ],
  },

  // ====== 9. Persistence ======
  {
    id: 'PER-001',
    name: '启动项/计划任务植入',
    severity: 'high',
    category: 'persistence',
    description: '添加自启动项或计划任务实现持久化',
    patterns: [
      /crontab.*-e/,
      /writeFile.*\/Library\/LaunchAgents/,
      /writeFile.*%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup/i,
      /reg.*add.*HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run/i,
    ],
  },
  {
    id: 'PER-002',
    name: 'Shell 配置文件篡改',
    severity: 'high',
    category: 'persistence',
    description: '修改 .bashrc/.zshrc 等配置文件植入后门',
    patterns: [
      /appendFile.*\.(?:bashrc|zshrc|profile)/,
      /writeFile.*\.(?:bashrc|zshrc|profile)/,
      /echo.*>>.*\.(?:bashrc|zshrc)/,
    ],
  },

  // ====== 10. Privilege / DSH service access ======
  {
    id: 'PRIV-001',
    name: '请求敏感 DSH 服务',
    severity: 'high',
    category: 'privilege-escalation',
    description: '插件声明注入敏感服务（fs/subprocess/web/credentials）',
    patterns: [
      /inject\s*[:=]\s*\[[^\]]*(?:['"`]fs['"`]|['"`]subprocess['"`]|['"`]web['"`]|['"`]credentials['"`])/i,
    ],
  },
  {
    id: 'PRIV-002',
    name: '拦截/替换 DSH 核心服务',
    severity: 'critical',
    category: 'privilege-escalation',
    description: '检测到插件尝试拦截或替换 DSH 核心服务',
    patterns: [
      /ctx\.on\s*\(\s*['"`]internal\/get['"`]\s*\)/,
      /ctx\.intercept/,
      /ctx\.provide\s*\(\s*['"`](?:llm|sessions|tools)['"`]/,
    ],
  },
]