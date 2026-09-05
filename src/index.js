// ============================================================
// DSH Security Guard - main entry
// Standard DeepSeek Harness plugin: exports name/inject/apply.
// Provides:
//   - static scanner as DSH tools (security_scan_plugins, ...)
//   - startup scan of installed dsh plugin packages
//   - local web report endpoint /plugins/dsh-security-guard/*
// ============================================================

import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { execFile } from 'node:child_process'
import { promisify } from 'node:util'
import { fileURLToPath } from 'node:url'
import { installSettingsSection, settingsNamespace } from '@deepseek-ai/dsh-settings'
import z from '@deepseek-ai/schemastery'
import { SecurityScanner } from './scanner.js'
import { SEVERITY_WEIGHTS } from './rules.js'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

const require = createRequire(import.meta.url)
const pkg = require('../package.json')
const execFileAsync = promisify(execFile)

const SETTINGS_NS = settingsNamespace('dsh-security-guard')
const SettingsSchema = z.object({
  enabled: z.boolean().default(true).description('启用大肥鱼安全卫士'),
  scanOnStart: z.boolean().default(true).description('启动 DSH 后自动扫描已安装插件'),
  popupEnabled: z.boolean().default(true).description('在 DSH 内弹出风险提醒'),
  popupMinIntervalMinutes: z.number().min(1).max(120).default(10).description('弹窗最小间隔（分钟）'),
  minLevel: z.string().default('warning').description('告警等级：warning / critical / emergency'),
  enableWebPanel: z.boolean().default(true).description('挂载本地 Web 仪表盘'),
})

export const name = 'dsh-security-guard'
// This plugin only consumes optional DSH services through ctx.inject at
// runtime; it does not need a top-level service injection.
export const inject = []

const LEVELS = ['info', 'warning', 'critical', 'emergency']

const DEFAULT_CONFIG = Object.freeze({
  enabled: true,
  scanOnStart: true,
  maxFileSize: 1024 * 1024,
  includeNodeModules: false,
  whitelist: Object.freeze([]),
  minLevel: 'warning',
  channels: Object.freeze(['console']),
  webhookUrl: '',
  rateLimitMs: 3000,
  autoUpdateRules: true,
  enableWebPanel: true,
  webPanelPath: '/security-guard',
  remoteSources: Object.freeze([]),
  autoUpdateInterval: 0,
})

function normalizeConfig(config = {}) {
  const whitelist = Array.isArray(config.whitelist)
    ? config.whitelist.filter((x) => typeof x === 'string')
    : []
  const channels = Array.isArray(config.channels) && config.channels.length > 0
    ? config.channels.filter((x) => ['console', 'eventBus', 'webhook'].includes(x))
    : ['console']
  return {
    enabled: config.enabled !== false,
    scanOnStart: config.scanOnStart !== false,
    scanner: {
      maxFileSize: Number(config.maxFileSize ?? DEFAULT_CONFIG.maxFileSize) || DEFAULT_CONFIG.maxFileSize,
      includeNodeModules: config.includeNodeModules === true,
      whitelist,
      remoteSources: Array.isArray(config.remoteSources) ? config.remoteSources : [],
      autoUpdateInterval: Number(config.autoUpdateInterval ?? DEFAULT_CONFIG.autoUpdateInterval) || 0,
    },
    alarm: {
      minLevel: LEVELS.includes(config.minLevel) ? config.minLevel : DEFAULT_CONFIG.minLevel,
      channels,
      webhookUrl: typeof config.webhookUrl === 'string' ? config.webhookUrl : '',
      rateLimitMs: Number(config.rateLimitMs ?? DEFAULT_CONFIG.rateLimitMs) || DEFAULT_CONFIG.rateLimitMs,
    },
    autoUpdateRules: config.autoUpdateRules !== false,
    enableWebPanel: config.enableWebPanel !== false,
    webPanelPath: typeof config.webPanelPath === 'string' && config.webPanelPath.startsWith('/')
      ? config.webPanelPath
      : DEFAULT_CONFIG.webPanelPath,
  }
}

function dshHome() {
  return process.env.DSH_HOME || path.join(os.homedir(), '.dsh')
}

function policyFile() {
  return path.join(dshHome(), 'dsh-security-guard-policy.json')
}

function loadPolicy() {
  const fallback = { whitelist: [], blacklist: [] }
  try {
    if (!existsSync(policyFile())) return fallback
    const data = JSON.parse(readFileSync(policyFile(), 'utf8'))
    return {
      whitelist: Array.isArray(data.whitelist) ? data.whitelist.filter((x) => typeof x === 'string') : [],
      blacklist: Array.isArray(data.blacklist) ? data.blacklist.filter((x) => typeof x === 'string') : [],
    }
  } catch {
    return fallback
  }
}

function savePolicy(policy) {
  try {
    mkdirSync(path.dirname(policyFile()), { recursive: true })
    writeFileSync(policyFile(), JSON.stringify(policy, null, 2), 'utf8')
    return true
  } catch {
    return false
  }
}


function pushRoot(roots, root) {
  if (root && !roots.includes(root)) roots.push(root)
}

function pluginRoots(cwd = process.cwd()) {
  const roots = []
  const home = dshHome()

  const profilesDir = path.join(home, 'profiles')
  if (existsSync(profilesDir)) {
    try {
      for (const profile of readdirSync(profilesDir, { withFileTypes: true })) {
        if (!profile.isDirectory()) continue
        const profileDir = path.join(profilesDir, profile.name)
        pushRoot(roots, path.join(profileDir, 'node_modules'))
        pushRoot(roots, path.join(profileDir, 'plugins'))
      }
    } catch { /* ignore */ }
  }

  pushRoot(roots, path.join(home, 'node_modules'))
  pushRoot(roots, path.join(home, 'plugins'))
  pushRoot(roots, path.join(cwd, 'node_modules'))

  if (process.env.DSH_PLUGIN_PATH) {
    for (const segment of process.env.DSH_PLUGIN_PATH.split(path.delimiter)) {
      if (segment && segment.trim()) pushRoot(roots, segment.trim())
    }
  }

  return roots
}

function createAlarm(config, ctx, logger) {
  let lastAlarmAt = 0
  const history = []

  function notify(event) {
    if (LEVELS.indexOf(event.level) < LEVELS.indexOf(config.minLevel)) return
    const now = Date.now()
    if (now - lastAlarmAt < config.rateLimitMs) return
    lastAlarmAt = now
    history.push(event)
    if (history.length > 200) history.shift()

    for (const channel of config.channels) {
      try {
        if (channel === 'console') {
          const color = event.level === 'emergency' ? '\x1b[41m\x1b[37m'
            : event.level === 'critical' ? '\x1b[31m'
            : event.level === 'warning' ? '\x1b[33m'
            : '\x1b[36m'
          logger.info(`${color}[SecurityGuard][${event.level.toUpperCase()}] ${event.message}\x1b[0m`)
        } else if (channel === 'eventBus' && typeof ctx.emit === 'function') {
          ctx.emit('security-guard/alarm', event)
        } else if (channel === 'webhook' && config.webhookUrl) {
          fetch(config.webhookUrl, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify(event),
          }).catch((err) => logger.warn(`[SecurityGuard] webhook failed: ${err instanceof Error ? err.message : String(err)}`))
        }
      } catch (err) {
        logger.warn(`[SecurityGuard] alarm channel failed: ${err instanceof Error ? err.message : String(err)}`)
      }
    }
  }

  return {
    notify,
    history,
    clear() {
      history.length = 0
      lastAlarmAt = 0
    },
  }
}

function isLoopback(address) {
  return address === '127.0.0.1' || address === '::1' || address === '::ffff:127.0.0.1'
}

function sendJson(res, status, body) {
  const payload = JSON.stringify(body)
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(payload),
  })
  res.end(payload)
}

function summarizeForTool(report) {
  if (!report) return null
  return {
    ok: true,
    scannedAt: report.scannedAt,
    pluginCount: report.pluginCount,
    riskScore: report.riskScore,
    riskLevel: report.riskLevel,
    findingsCount: report.findings.length,
    topFindings: report.findings.slice(0, 50).map((f) => ({
      ruleId: f.ruleId,
      ruleName: f.ruleName,
      severity: f.severity,
      category: f.category,
      pluginName: f.pluginName,
      filePath: f.filePath,
      line: f.line,
      match: f.match,
    })),
    pluginSummaries: (report.plugins ?? []).map((p) => ({
      pluginName: p.pluginName,
      riskScore: p.riskScore,
      riskLevel: p.riskLevel,
      findingsCount: p.findings.length,
      skipped: p.skipped,
      reason: p.reason ?? '',
    })),
  }
}

function reportText(report) {
  if (!report) return 'SecurityGuard: no scan report yet.'
  const lines = [
    `SecurityGuard scan: ${report.pluginCount} plugins, ${report.findings.length} findings, risk ${report.riskLevel} (score ${report.riskScore})`,
  ]
  for (const f of report.findings.slice(0, 10)) {
    lines.push(`- [${f.ruleId}][${f.severity}] ${f.pluginName ?? ''} ${f.filePath}:${f.line} ${f.match}`)
  }
  if (report.findings.length > 10) lines.push(`... and ${report.findings.length - 10} more`)
  return lines.join('\n')
}

async function loadDefineTool() {
  try {
    const mod = await import('@deepseek-ai/dsh-tools')
    return typeof mod.defineTool === 'function' ? mod.defineTool : null
  } catch {
    return null
  }
}

async function deletePluginViaCli(pluginName, logger) {
  try {
    const dshPkg = require.resolve('@deepseek-ai/dsh/package.json')
    const dshBin = path.join(path.dirname(dshPkg), 'lib/bin.js')
    const profile = process.env.DSH_PROFILE || 'web'
    const env = { ...process.env, DSH_HOME: dshHome() }
    const { stdout, stderr } = await execFileAsync(process.execPath, [dshBin, 'plugin', '--profile', profile, 'remove', pluginName], {
      env,
      timeout: 120000,
      windowsHide: true,
    })
    return { ok: true, stdout: String(stdout), stderr: String(stderr) }
  } catch (err) {
    logger.warn(`[SecurityGuard] deletePlugin failed: ${err instanceof Error ? err.message : String(err)}`)
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
}

async function deletePluginViaMarket(pluginName, webServerService, logger) {
  try {
    const port = webServerService?.port
    if (!port) throw new Error('webServer port unavailable')
    const res = await fetch(`http://127.0.0.1:${port}/dsh-market/uninstall`, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: `http://127.0.0.1:${port}`,
      },
      body: JSON.stringify({ name: pluginName }),
    })
    const data = await res.json().catch(() => ({}))
    if (!res.ok) return { ok: false, error: data.error || `HTTP ${res.status}` }
    return { ok: true, market: true, ...data }
  } catch (err) {
    logger.warn(`[SecurityGuard] deletePlugin via market failed: ${err instanceof Error ? err.message : String(err)}`)
    return { ok: false, error: err instanceof Error ? err.message : String(err) }
  }
}

function profileName() {
  return process.env.DSH_PROFILE || 'web'
}

function cleanupProfileBundle(pluginName, logger) {
  try {
    const file = path.join(dshHome(), 'profiles', profileName(), 'package.json')
    const pkg = JSON.parse(readFileSync(file, 'utf8'))
    const bundles = pkg?.dsh?.profile?.bundles
    if (Array.isArray(bundles) && bundles.includes(pluginName)) {
      pkg.dsh.profile.bundles = bundles.filter((x) => x !== pluginName)
      writeFileSync(file, JSON.stringify(pkg, null, 2), 'utf8')
      logger.info(`[SecurityGuard] removed ${pluginName} from profile bundles`)
    }
  } catch (err) {
    logger.warn(`[SecurityGuard] failed to clean bundle entry for ${pluginName}: ${err instanceof Error ? err.message : String(err)}`)
  }
}

async function scanPackageFile(packagePath, packageName, scanner) {
  if (typeof packagePath !== 'string' || packagePath.trim().length === 0) {
    throw new Error('package path is required')
  }
  const file = path.resolve(packagePath)
  if (!existsSync(file)) {
    throw new Error(`package file not found: ${file}`)
  }
  const ext = path.extname(file).toLowerCase()
  const lower = file.toLowerCase()
  const isTarGz = lower.endsWith('.tar.gz')
  const isTgz = ext === '.tgz' || isTarGz
  const isZip = ext === '.zip'
  if (!isTgz && !isZip) {
    throw new Error('unsupported package format: use .tgz / .tar.gz / .zip')
  }

  const tempDir = mkdtempSync(path.join(os.tmpdir(), 'dsh-security-guard-pkg-'))
  try {
    const tarArgs = isTgz
      ? ['-xzf', file, '-C', tempDir]
      : ['-xf', file, '-C', tempDir]
    await execFileAsync('tar', tarArgs, { timeout: 120000, windowsHide: true })

    // npm tgz extracts into a single top-level `package/` directory.
    const entries = readdirSync(tempDir, { withFileTypes: true })
    const dirs = entries.filter((e) => e.isDirectory()).map((e) => e.name)
    let root = tempDir
    if (dirs.length === 1 && !existsSync(path.join(tempDir, 'package.json'))) {
      root = path.join(tempDir, dirs[0])
    }

    const name = packageName || path.basename(file).replace(/(\.tgz|\.tar\.gz|\.zip)$/i, '')
    const report = await scanner.scanPlugin(root, name)
    return report
  } finally {
    try { rmSync(tempDir, { recursive: true, force: true }) } catch { /* ignore */ }
  }
}





export function apply(ctx, config = {}) {
  const logger = ctx.logger ?? console
  const cfg = normalizeConfig(config)

  let liveSettings = () => config
  try {
    installSettingsSection(ctx, SETTINGS_NS, SettingsSchema, config ?? {}, {
      setSource: (source) => { liveSettings = source },
      onChange: () => { logger.info('[SecurityGuard] DSH settings updated') },
    })
  } catch (err) {
    logger.warn(`[SecurityGuard] settings registration failed: ${err instanceof Error ? err.message : String(err)}`)
  }


  if (cfg.enabled === false) {
    logger.info('[SecurityGuard] disabled by config')
    return
  }

  const scanner = new SecurityScanner(cfg.scanner)
  if (cfg.autoUpdateRules) {
    scanner.startAutoUpdate(() => logger.info('[SecurityGuard] rules auto-updated'))
  }

  let webServerService = null


  const policy = loadPolicy()
  const updateScannerPolicy = () => {
    scanner.config.whitelist = Array.from(new Set([...cfg.scanner.whitelist, ...policy.whitelist]))
    scanner.config.blacklist = policy.blacklist.slice()
  }
  updateScannerPolicy()


  const alarm = createAlarm(cfg.alarm, ctx, logger)
  const store = {
    latest: null,
    history: [],
    scanning: null,
  }

  function rememberReport(report) {
    store.latest = report
    store.history.push(report)
    if (store.history.length > 20) store.history.shift()
    return report
  }

  function scanAllPlugins(options = {}) {
    if (store.scanning) return store.scanning
    store.scanning = (async () => {
      try {
        const report = await scanner.scanInstalledPlugins(pluginRoots(), {
          includeNodeModules: options.includeNodeModules === true || cfg.scanner.includeNodeModules,
        })
        report.pluginRoots = pluginRoots()
        rememberReport(report)

        if (report.riskLevel === 'critical') {
          alarm.notify({
            id: `AUTO-${Date.now()}`,
            timestamp: new Date().toISOString(),
            level: 'emergency',
            type: 'scan',
            message: `DSH 插件扫描发现严重风险：${report.pluginCount} 个插件，${report.findings.length} 个风险命中，评分 ${report.riskScore}`,
            details: { riskLevel: report.riskLevel, topFindings: report.findings.slice(0, 10) },
          })
        } else if (report.riskLevel === 'high') {
          alarm.notify({
            id: `AUTO-${Date.now()}`,
            timestamp: new Date().toISOString(),
            level: 'critical',
            type: 'scan',
            message: `DSH 插件扫描发现高风险：${report.pluginCount} 个插件，${report.findings.length} 个风险命中，评分 ${report.riskScore}`,
            details: { riskLevel: report.riskLevel },
          })
        } else {
          logger.info(`[SecurityGuard] startup scan finished: ${report.pluginCount} plugins, risk ${report.riskLevel} (score ${report.riskScore})`)
        }
        return report
      } finally {
        store.scanning = null
      }
    })()
    return store.scanning
  }

  async function scanOnePlugin(input, options = {}) {
    const target = typeof input === 'string' ? input.trim() : ''
    if (!target) {
      const err = new Error('plugin name or path is required')
      err.code = 'BAD_ARGS'
      throw err
    }

    let pluginPath = target
    let pluginName = target
    if (!path.isAbsolute(target)) {
      // Try to resolve package names (including @scope/pkg) and relative paths
      // from the same roots dsh uses.
      for (const root of pluginRoots()) {
        const candidate = path.join(root, target)
        if (existsSync(candidate)) {
          pluginPath = candidate
          break
        }
      }
      if (pluginPath === target) pluginPath = path.resolve(target)
    }
    if (!existsSync(pluginPath)) {
      const err = new Error(`plugin not found: ${target}`)
      err.code = 'NOT_FOUND'
      throw err
    }

    const report = await scanner.scanPlugin(pluginPath, pluginName)
    report.findings = report.findings.map((f) => ({ ...f, pluginName: report.pluginName }))
    rememberReport(report)

    if (report.riskLevel === 'critical' || report.riskLevel === 'high') {
      alarm.notify({
        id: `SCAN-${Date.now()}`,
        timestamp: new Date().toISOString(),
        level: report.riskLevel === 'critical' ? 'emergency' : 'critical',
        type: 'scan',
        pluginName: report.pluginName,
        message: `插件 ${report.pluginName} 扫描完成：${report.findings.length} 个风险，评分 ${report.riskScore}（${report.riskLevel}）`,
        details: { riskLevel: report.riskLevel, riskScore: report.riskScore },
      })
    }

    return summarizeForTool({ pluginCount: 1, scannedAt: report.scannedAt, riskScore: report.riskScore, riskLevel: report.riskLevel, findings: report.findings, plugins: [report] })
  }

  function makeTool(def, execute) {
    return { ...def, execute }
  }

  // ----- DSH tools -----
  if (typeof ctx.inject === 'function') {
    ctx.inject(['tools'], (sctx) => {
      if (!sctx?.effect || typeof sctx.tools?.register !== 'function') return
      sctx.effect(() => {
        const disposers = []
        let disposed = false

        Promise.resolve(loadDefineTool()).then((defineTool) => {
          if (disposed) return

          const scanAllDef = {
            name: 'security_scan_plugins',
            description: 'Scan all installed DeepSeek Harness (DSH) plugin packages with the SecurityGuard static analyzer. Returns the overall risk level, risk score, top findings and a per-plugin summary. Use this when the user asks "scan my plugins", "check plugin security", "有哪些插件有风险", etc.',
            parameters: {
              refresh: { type: 'boolean', description: 'Set true to force a fresh scan; by default a cached/current report is reused when available.' },
              includeNodeModules: { type: 'boolean', description: 'Set true to also scan node_modules directories of each plugin (slower and noisier).' },
            },
            output: {
              schema: {
                type: 'object',
                additionalProperties: false,
                properties: {
                  ok: { type: 'boolean' },
                  scannedAt: { type: 'string' },
                  pluginCount: { type: 'number' },
                  riskScore: { type: 'number' },
                  riskLevel: { type: 'string' },
                  findingsCount: { type: 'number' },
                  topFindings: { type: 'array', items: { type: 'object', additionalProperties: true } },
                  pluginSummaries: { type: 'array', items: { type: 'object', additionalProperties: true } },
                },
              },
              render(args, value) {
                return [{ type: 'text', text: reportText(value) }]
              },
            },
          }

          const scanOneDef = {
            name: 'security_scan_plugin',
            description: 'Scan one DeepSeek Harness (DSH) plugin by package name or local path with the SecurityGuard static analyzer. Returns the plugin risk level, risk score and findings. Use this when the user asks about a specific plugin ("扫描 xxx 插件").',
            parameters: {
              plugin: { type: 'string', required: true, description: 'Plugin package name (e.g. dsh-labnana) or an absolute/local path to the plugin directory.' },
              includeNodeModules: { type: 'boolean', description: 'Set true to also scan node_modules directories of the plugin (slower and noisier).' },
            },
            output: {
              schema: {
                type: 'object',
                additionalProperties: false,
                properties: {
                  ok: { type: 'boolean' },
                  scannedAt: { type: 'string' },
                  pluginCount: { type: 'number' },
                  riskScore: { type: 'number' },
                  riskLevel: { type: 'string' },
                  findingsCount: { type: 'number' },
                  topFindings: { type: 'array', items: { type: 'object', additionalProperties: true } },
                  pluginSummaries: { type: 'array', items: { type: 'object', additionalProperties: true } },
                },
              },
              render(args, value) {
                return [{ type: 'text', text: reportText(value) }]
              },
            },
          }

            const scanPackageDef = {
              name: 'security_scan_package',
              description: 'Scan a downloaded DSH plugin installation package (.tgz / .tar.gz / .zip) before installing it. Extracts the package to a temp directory, runs the SecurityGuard static analyzer, and returns the risk level, score and findings.',
              parameters: {
                package: { type: 'string', required: true, description: 'Local path to the downloaded package file, e.g. C:/Users/me/Downloads/dsh-foo-1.0.0.tgz' },
                packageName: { type: 'string', description: 'Optional package name override shown in the report.' },
                includeNodeModules: { type: 'boolean', description: 'Set true to also scan node_modules inside the package (slower and noisier).' },
              },
              output: {
                schema: {
                  type: 'object',
                  additionalProperties: false,
                  properties: {
                    ok: { type: 'boolean' },
                    scannedAt: { type: 'string' },
                    pluginCount: { type: 'number' },
                    riskScore: { type: 'number' },
                    riskLevel: { type: 'string' },
                    findingsCount: { type: 'number' },
                    topFindings: { type: 'array', items: { type: 'object', additionalProperties: true } },
                    pluginSummaries: { type: 'array', items: { type: 'object', additionalProperties: true } },
                  },
                },
                render(args, value) {
                  return [{ type: 'text', text: reportText(value) }]
                },
              },
            }


          const reportDef = {
            name: 'security_guard_report',
            description: 'Get the latest SecurityGuard scan report without rescanning. Use this when the user asks "current security report" or "上次扫描结果".',
            parameters: {},
            output: {
              schema: {
                type: 'object',
                additionalProperties: false,
                properties: {
                  ok: { type: 'boolean' },
                  scannedAt: { type: 'string' },
                  pluginCount: { type: 'number' },
                  riskScore: { type: 'number' },
                  riskLevel: { type: 'string' },
                  findingsCount: { type: 'number' },
                  topFindings: { type: 'array', items: { type: 'object', additionalProperties: true } },
                  pluginSummaries: { type: 'array', items: { type: 'object', additionalProperties: true } },
                },
              },
              render(args, value) {
                return [{ type: 'text', text: reportText(value) }]
              },
            },
          }

          const wrap = (def) => (defineTool ? defineTool(def) : def)

          try {
            disposers.push(
              sctx.tools.register(wrap(makeTool(scanAllDef, async (args) => {
                if (args?.refresh === true || !store.latest) {
                  const report = await scanAllPlugins({ includeNodeModules: args?.includeNodeModules === true })
                  return summarizeForTool(report)
                }
                return summarizeForTool(store.latest)
              }))),
            )
            disposers.push(
              sctx.tools.register(wrap(makeTool(scanOneDef, async (args) => {
                return await scanOnePlugin(args?.plugin, { includeNodeModules: args?.includeNodeModules === true })
              }))),
            )
              disposers.push(
                sctx.tools.register(wrap(makeTool(scanPackageDef, async (args) => {
                  const report = await scanPackageFile(args?.package, args?.packageName, scanner)
                  report.findings = (report.findings ?? []).map((f) => ({ ...f, pluginName: report.pluginName }))
                  return summarizeForTool({
                    pluginCount: 1,
                    scannedAt: report.scannedAt,
                    riskScore: report.riskScore,
                    riskLevel: report.riskLevel,
                    findings: report.findings,
                    plugins: [report],
                  })
                }))),
              )

            disposers.push(
              sctx.tools.register(wrap(makeTool(reportDef, async () => {
                if (!store.latest) {
                  const report = await scanAllPlugins()
                  return summarizeForTool(report)
                }
                return summarizeForTool(store.latest)
              }))),
            )
          } catch (err) {
            logger.warn(`[SecurityGuard] tool registration failed: ${err instanceof Error ? err.message : String(err)}`)
          }
        }).catch((err) => {
          logger.warn(`[SecurityGuard] dsh-tools unavailable, tools not registered: ${err instanceof Error ? err.message : String(err)}`)
        })

        return () => {
          disposed = true
          for (const dispose of disposers) {
            try { dispose?.() } catch { /* ignore */ }
          }
        }
      })
    })

    ctx.inject(['webServer'], (sctx) => {
      if (!sctx?.effect || typeof sctx.webServer?.register !== 'function') return
        webServerService = sctx.webServer

      sctx.effect(() => {
        const webDisposers = []

        webDisposers.push(sctx.webServer.register({
          kind: 'prefix',
          path: '/plugins/dsh-security-guard',
          handler: (req, res) => {
            try {
              if (!isLoopback(req.socket?.remoteAddress)) {
                sendJson(res, 403, { error: 'local access only' })
                return
              }
              const url = new URL(req.url ?? '/', 'http://127.0.0.1')
              if (url.pathname === '/plugins/dsh-security-guard/report') {
                if (req.method !== 'GET') {
                  sendJson(res, 405, { error: 'method not allowed' })
                  return
                }
                if (!store.latest) {
                  sendJson(res, 404, { error: 'no scan report yet; call POST /plugins/dsh-security-guard/scan first' })
                  return
                }
                sendJson(res, 200, store.latest)
                return
              }
              if (url.pathname === '/plugins/dsh-security-guard/scan') {
                if (req.method !== 'POST') {
                  sendJson(res, 405, { error: 'method not allowed' })
                  return
                }
                scanAllPlugins().then((report) => sendJson(res, 200, report)).catch((err) => {
                  sendJson(res, 500, { error: err instanceof Error ? err.message : String(err) })
                })
                return
              }
              sendJson(res, 404, { error: 'unknown endpoint' })
            } catch (err) {
              sendJson(res, 500, { error: err instanceof Error ? err.message : String(err) })
            }
          },
        }))

        if (cfg.enableWebPanel) {
          webDisposers.push(sctx.webServer.register({
            kind: 'exact',
            path: cfg.webPanelPath,
            handler: (req, res) => {
              try {
                if (!isLoopback(req.socket?.remoteAddress)) {
                  sendJson(res, 403, { error: 'local access only' })
                  return
                }
                const html = readFileSync(path.join(__dirname, 'web/panel.html'), 'utf8')
                res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })
                res.end(html)
              } catch (err) {
                sendJson(res, 500, { error: err instanceof Error ? err.message : String(err) })
              }
            },
          }))

          webDisposers.push(sctx.webServer.register({
            kind: 'prefix',
            path: '/api/security-guard',
            handler: async (req, res) => {
              try {
                if (!isLoopback(req.socket?.remoteAddress)) {
                  sendJson(res, 403, { error: 'local access only' })
                  return
                }
                const url = new URL(req.url ?? '/', 'http://127.0.0.1')
                const method = url.pathname.replace('/api/security-guard/', '').replace(/^\//, '')
                if (req.method !== 'POST') {
                  sendJson(res, 405, { error: 'method not allowed' })
                  return
                }
                let body = {}
                try {
                  const chunks = []
                  for await (const chunk of req) chunks.push(chunk)
                  const raw = Buffer.concat(chunks).toString('utf8')
                  if (raw) body = JSON.parse(raw)
                } catch { body = {} }

                let result
                switch (method) {
                  case 'getStats':
                    result = {
                      totalRules: scanner.getStats().totalRules,
                      matchCount: 0,
                      skipCount: 0,
                      scannedPlugins: store.latest?.pluginCount ?? 0,
                      blockedEvents: 0,
                      riskyPlugins: store.latest?.plugins?.filter((p) => p.riskLevel === 'high' || p.riskLevel === 'critical').length ?? 0,
                    }
                    break
                  case 'getSecurityLog':
                    result = alarm.history.map((e) => ({ id: e.id, timestamp: e.timestamp, level: e.level, type: e.type, pluginName: e.pluginName ?? null, message: e.message, details: e.details ?? null }))
                    break
                  case 'clearSecurityLog':
                    alarm.clear()
                    result = { ok: true }
                    break
                  case 'getRules':
                    result = scanner.getRules()
                    break
                  case 'addRule':
                    result = { ok: scanner.addRule(body?.rule ?? {}) }
                    break
                  case 'deleteRule':
                    result = { ok: scanner.deleteRule(body?.ruleId) }
                    break
                  case 'getIsolationPolicy':
                    result = {
                      blockedServices: ['fs', 'subprocess', 'web'],
                      allowedHosts: ['localhost', '127.0.0.1', 'api.deepseek.com', 'github.com', 'registry.npmjs.org'],
                      maxFileWriteScope: 'workspace',
                    }
                    break
                  case 'getScanHistory':
                    result = store.history.map((r) => ({ pluginName: r.pluginCount ? `all(${r.pluginCount})` : r.pluginName, riskLevel: r.riskLevel, riskScore: r.riskScore, scannedAt: r.scannedAt }))
                    break
                  case 'scanAll': {
                    const report = await scanAllPlugins({})
                    result = {
                      results: (report.plugins ?? []).map((p) => ({
                        pluginName: p.pluginName,
                        riskLevel: p.riskLevel,
                        riskScore: p.riskScore,
                        findingsCount: p.findings.length,
                        skipped: p.skipped,
                        reason: p.reason ?? '',
                        findings: (p.findings ?? []).slice(0, 20).map((f) => ({
                          ruleId: f.ruleId,
                          ruleName: f.ruleName,
                          severity: f.severity,
                          category: f.category,
                          filePath: f.filePath,
                          line: f.line,
                          match: f.match,
                          recommendation: f.recommendation ?? '请人工审查此插件的安全风险',
                        })),
                      })),
                      pluginCount: report.pluginCount,
                      riskLevel: report.riskLevel,
                      riskScore: report.riskScore,
                      scannedAt: report.scannedAt,
                    }
                    break
                  }
                    case 'scanPackage': {
                      const report = await scanPackageFile(body?.package, body?.packageName, scanner)
                      report.findings = (report.findings ?? []).map((f) => ({ ...f, pluginName: report.pluginName }))
                      result = {
                        results: [{
                          pluginName: report.pluginName,
                          riskLevel: report.riskLevel,
                          riskScore: report.riskScore,
                          findingsCount: report.findings.length,
                          skipped: report.skipped,
                          reason: report.reason ?? '',
                          findings: report.findings.slice(0, 20).map((f) => ({
                            ruleId: f.ruleId,
                            ruleName: f.ruleName,
                            severity: f.severity,
                            category: f.category,
                            filePath: f.filePath,
                            line: f.line,
                            match: f.match,
                            recommendation: f.recommendation ?? '请人工审查此插件的安全风险',
                          })),
                        }],
                        pluginCount: 1,
                        riskLevel: report.riskLevel,
                        riskScore: report.riskScore,
                        scannedAt: report.scannedAt,
                      }
                      break
                    }

                  case 'updateRules':
                    result = await scanner.updateRules()
                    break
                  case 'setEmergencyMode':
                    result = { ok: true, enabled: Boolean(body?.enable) }
                    break
                  case 'setRuleEnabled':
                    result = { ok: scanner.setRuleEnabled(body?.ruleId, body?.enabled !== false) }
                    break
                  case 'getPolicy':
                    result = { whitelist: policy.whitelist.slice(), blacklist: policy.blacklist.slice() }
                    break
                  case 'setWhitelist': {
                    const items = Array.isArray(body?.items) ? body.items.filter((x) => typeof x === 'string') : []
                    policy.whitelist = items
                    savePolicy(policy)
                    updateScannerPolicy()
                    result = { ok: true, whitelist: policy.whitelist.slice() }
                    break
                  }
                  case 'setBlacklist': {
                    const items = Array.isArray(body?.items) ? body.items.filter((x) => typeof x === 'string') : []
                    policy.blacklist = items
                    savePolicy(policy)
                    updateScannerPolicy()
                    result = { ok: true, blacklist: policy.blacklist.slice() }
                    break
                  }
                  case 'addWhitelist': {
                    const item = typeof body?.item === 'string' ? body.item : ''
                    if (item && !policy.whitelist.includes(item)) {
                      policy.whitelist.push(item)
                      savePolicy(policy)
                      updateScannerPolicy()
                    }
                    result = { ok: true, whitelist: policy.whitelist.slice() }
                    break
                  }
                  case 'removeWhitelist': {
                    const item = typeof body?.item === 'string' ? body.item : ''
                    policy.whitelist = policy.whitelist.filter((x) => x !== item)
                    savePolicy(policy)
                    updateScannerPolicy()
                    result = { ok: true, whitelist: policy.whitelist.slice() }
                    break
                  }
                  case 'addBlacklist': {
                    const item = typeof body?.item === 'string' ? body.item : ''
                    if (item && !policy.blacklist.includes(item)) {
                      policy.blacklist.push(item)
                      savePolicy(policy)
                      updateScannerPolicy()
                    }
                    result = { ok: true, blacklist: policy.blacklist.slice() }
                    break
                  }
                  case 'removeBlacklist': {
                    const item = typeof body?.item === 'string' ? body.item : ''
                    policy.blacklist = policy.blacklist.filter((x) => x !== item)
                    savePolicy(policy)
                    updateScannerPolicy()
                    result = { ok: true, blacklist: policy.blacklist.slice() }
                    break
                  }
                  case 'deletePlugin': {
                    const pluginName = typeof body?.pluginName === 'string' ? body.pluginName.trim() : ''
                    if (!pluginName || pluginName === 'dsh-security-guard') {
                      result = { ok: false, error: 'invalid plugin name' }
                      break
                    }
                    const marketResult = await deletePluginViaMarket(pluginName, webServerService, logger)
                    if (marketResult.ok) {
                      await cleanupProfileBundle(pluginName, logger)
                      result = marketResult
                    } else {
                      result = await deletePluginViaCli(pluginName, logger)
                    }
                    break
                  }
                  default:
                    result = { error: 'unknown method' }
                }
                sendJson(res, 200, result)
              } catch (err) {
                sendJson(res, 500, { error: err instanceof Error ? err.message : String(err) })
              }
            },
          }))
        }

        return () => {
          for (const dispose of webDisposers) {
            try { dispose?.() } catch { /* ignore */ }
          }
        }
      })
    })
  }

  // ----- startup scan (non-blocking) -----
  const startupTimer = cfg.scanOnStart ? setTimeout(() => {
    scanAllPlugins().catch((err) => {
      logger.warn(`[SecurityGuard] startup scan failed: ${err instanceof Error ? err.message : String(err)}`)
    })
  }, 1500) : null
  if (startupTimer?.unref) startupTimer.unref()

  if (typeof ctx.effect === 'function') {
    ctx.effect(() => () => {
      if (startupTimer) clearTimeout(startupTimer)
      scanner.clearCache()
    })
  }

  logger.info(`[SecurityGuard] dsh-security-guard ${pkg.version} started ✅ scanner ready, report at /plugins/dsh-security-guard/report`)
}