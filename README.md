# 🔒 DSH Security Guard

DeepSeek Harness（`dsh`）插件生态安全卫士。标准 dsh 插件包，安装后自动开始工作：
静态扫描已安装插件、28 条规则风险评分、模型可调用扫描工具、本地 Web 仪表盘、可选远程规则更新。

## 功能

| 模块 | 功能 |
|------|------|
| 静态扫描器 | 28 条规则覆盖偷 Token、数据外发、动态执行、混淆、网络、供应链、持久化、提权等 |
| 启动自检 | 安装后自动扫描 profile 下已安装的 dsh 插件包 |
| DSH 工具 | 为模型注册 `security_scan_plugins` / `security_scan_plugin` / `security_guard_report` |
| 告警 | 控制台 + 事件总线 + 可选 Webhook，带等级过滤和限流 |
| Web 仪表盘 | `GET /security-guard` 可视化面板；`POST /api/security-guard/*` JSON API |
| 规则更新 | 支持 `remoteSources` 远程规则 JSON，可选定时自动更新 |

## 安装

```bash
# 先完全退出 DSH Host
dsh plugin --profile web add ./dsh-security-guard-2.1.0.tgz
```

重启 DSH 即可，无需额外配置。

## 使用

1. 对话：“扫描一下我的插件安全” / “检查哪些插件有风险” / “扫描 dsh-labnana”。
2. 模型调用 `security_scan_plugins` / `security_scan_plugin` 返回风险报告。
3. 浏览器访问 `http://127.0.0.1:<DSH端口>/security-guard` 打开仪表盘。

## 检测规则（28 条）

- TOK-001~004：硬编码 Token / Token 外发 / 读取 DSH 凭据 / 环境变量凭据
- EXF-001~003：可疑外发域名 / DNS-ICMP 隧道 / 剪贴板读取外发
- EXE-001~003：动态代码执行 / 子进程执行 / 远程代码加载
- OBF-001~003：高熵字符串 / 解码后执行 / JSFuck 极简混淆
- NET-001~003：未授权监听 / WebSocket 外发 / 代理配置篡改
- FS-001~003：越界文件写入 / 删除系统文件 / 全盘文件搜索
- PRO-001~002：进程注入 / 权限提升
- SUP-001~003：可疑 install 脚本 / 依赖混淆 / Git 仓库投毒
- PER-001~002：启动项植入 / Shell 配置篡改
- PRIV-001~002：请求敏感 DSH 服务 / 拦截核心服务

## 配置（cordis.patch.yml）

```yaml
- insert:
    - id: dsh-security-guard
      name: dsh-security-guard
      config:
        enabled: true
        scanOnStart: true
        autoUpdateRules: true
        enableWebPanel: true
        webPanelPath: /security-guard
        maxFileSize: 1048576
        includeNodeModules: false
        whitelist: []
        remoteSources: []
        autoUpdateInterval: 0
        minLevel: warning
        channels:
          - console
        webhookUrl: ""
```

- `remoteSources`: 远程规则 JSON URL 列表，例如 `["https://example.com/rules.json"]`
- `autoUpdateInterval`: 规则自动更新间隔（分钟），0 表示不自动更新
- `enableWebPanel` / `webPanelPath`: 是否启用 Web 仪表盘及其路径

## 兼容性

- Node >= 20（使用全局 `fetch`）
- DeepSeek Harness 官方插件加载方式（`dsh.bundle.patch` + `cordis.patch.yml`）
- 零第三方运行时依赖；`@deepseek-ai/dsh-tools` 由 DSH Host 提供，缺失时自动跳过工具注册

## 许可

MIT
