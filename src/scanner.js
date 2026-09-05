// ============================================================
// DSH Security Guard - static scanner
// Scans DSH plugin package source files and produces a risk
// report. Pure Node.js built-ins, no third-party runtime deps.
// ============================================================

import { createHash } from 'node:crypto'
import { promises as fs, existsSync, statSync, readFileSync } from 'node:fs'
import path from 'node:path'
import { DEFAULT_RULES, SEVERITY_WEIGHTS, CATEGORY_WEIGHTS } from './rules.js'

const DEFAULT_CONFIG = Object.freeze({
  maxFileSize: 1024 * 1024,
  includeNodeModules: false,
  whitelist: Object.freeze([]),
})

const SCAN_EXTENSIONS = new Set(['.js', '.cjs', '.mjs', '.ts', '.tsx', '.jsx', '.json', '.yml', '.yaml'])
const MAX_TOTAL_FILES = 10000
const RECOMMENDATIONS = {
  'token-theft': '移除硬编码凭据，改用环境变量或 DSH 凭据域；禁止将敏感数据外发',
  'data-exfil': '审查所有网络请求目标，确保数据仅发送至可信端点；启用请求审计日志',
  'credential-access': '限制插件对敏感文件和服务的访问，使用最小权限原则',
  'code-execution': '避免使用 eval/new Function，改用安全的沙箱执行环境',
  'obfuscation': '要求插件提供未混淆的源码，或仅从可信源安装',
  'network': '审查网络监听和代理行为，确保不会形成中间人攻击面',
  'filesystem': '限制文件写入范围在工作区内，禁止修改系统文件',
  'process': '审查子进程执行命令，确保不会执行未经验证的系统命令',
  'supply-chain': '锁定依赖版本，审查 install 脚本，使用私有镜像源',
  'persistence': '禁止修改系统启动项、计划任务和 Shell 配置文件',
  'privilege-escalation': '禁止插件请求提权或拦截 DSH 核心服务',
}

export class SecurityScanner {
  constructor(config = {}) {
    this.config = {
      maxFileSize: config.maxFileSize ?? DEFAULT_CONFIG.maxFileSize,
      includeNodeModules: config.includeNodeModules ?? DEFAULT_CONFIG.includeNodeModules,
      whitelist: Array.isArray(config.whitelist) ? config.whitelist : DEFAULT_CONFIG.whitelist,
      blacklist: Array.isArray(config.blacklist) ? config.blacklist : [],
      rules: Array.isArray(config.rules) && config.rules.length > 0 ? config.rules : DEFAULT_RULES,
    }
    this.cache = new Map()
    this.disabledRules = new Set()
    this.extraRules = []
    this.remoteSources = Array.isArray(config.remoteSources) ? config.remoteSources : []
    this.autoUpdateInterval = Number(config.autoUpdateInterval ?? 0) || 0
    this.updateTimer = null
  }

  activeRules() {
    const rules = [...this.config.rules, ...this.extraRules]
    const seen = new Set()
    const deduped = []
    for (const rule of rules) {
      if (seen.has(rule.id)) continue
      seen.add(rule.id)
      if (this.disabledRules.has(rule.id)) continue
      if (rule.enabled === false) continue
      deduped.push(rule)
    }
    return deduped
  }

  getRules() {
    const all = [...this.config.rules, ...this.extraRules]
    const seen = new Set()
    const out = []
    for (const r of all) {
      if (seen.has(r.id)) continue
      seen.add(r.id)
      const custom = this.extraRules.some((x) => x.id === r.id)
      out.push({
        id: r.id,
        name: r.name,
        severity: r.severity,
        category: r.category,
        description: r.description,
        enabled: !this.disabledRules.has(r.id) && r.enabled !== false,
        filePatterns: r.filePatterns ?? [],
        custom,
      })
    }
    return out
  }

  setRuleEnabled(ruleId, enabled) {
    const known = new Set([...this.config.rules, ...this.extraRules].map((r) => r.id))
    if (!known.has(ruleId)) return false
    if (enabled) {
      this.disabledRules.delete(ruleId)
    } else {
      this.disabledRules.add(ruleId)
    }
    this.cache.clear()
    return true
  }

  addRule(rule) {
    if (!rule || typeof rule.id !== 'string' || rule.id.length === 0) return false
    if (typeof rule.name !== 'string' || rule.name.length === 0) return false
    if (!Array.isArray(rule.patterns) || rule.patterns.length === 0) return false
    const severity = ['info', 'low', 'medium', 'high', 'critical'].includes(rule.severity)
      ? rule.severity
      : 'medium'
    const category = typeof rule.category === 'string' && rule.category.length > 0
      ? rule.category
      : 'custom'

    const compiledPatterns = rule.patterns
      .map((p) => {
        if (p instanceof RegExp) return p
        if (typeof p !== 'string' || p.length === 0) return null
        try {
          if (p.startsWith('/') && p.lastIndexOf('/') > 0) {
            const end = p.lastIndexOf('/')
            return new RegExp(p.slice(1, end), p.slice(end + 1))
          }
          return new RegExp(p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i')
        } catch {
          return null
        }
      })
      .filter(Boolean)

    if (compiledPatterns.length === 0) return false

    const entry = {
      id: rule.id,
      name: rule.name,
      severity,
      category,
      description: typeof rule.description === 'string' ? rule.description : '',
      patterns: compiledPatterns,
      filePatterns: Array.isArray(rule.filePatterns) ? rule.filePatterns : undefined,
    }
    this.extraRules = this.extraRules.filter((r) => r.id !== rule.id)
    this.extraRules.push(entry)
    this.disabledRules.delete(rule.id)
    this.cache.clear()
    return true
  }

  deleteRule(ruleId) {
    if (typeof ruleId !== 'string' || ruleId.length === 0) return false
    const idx = this.extraRules.findIndex((r) => r.id === ruleId)
    if (idx >= 0) {
      this.extraRules.splice(idx, 1)
      this.disabledRules.delete(ruleId)
      this.cache.clear()
      return true
    }
    if (this.config.rules.some((r) => r.id === ruleId)) {
      this.disabledRules.add(ruleId)
      this.cache.clear()
      return true
    }
    return false
  }
  getStats() {
    return {
      totalRules: this.activeRules().length,
      disabledRules: this.disabledRules.size,
      cacheSize: this.cache.size,
      remoteSources: this.remoteSources.length,
    }
  }

  async updateRules() {
    let updated = 0
    let failed = 0
    const fetched = []

    for (const source of this.remoteSources) {
      try {
        const res = await fetch(source)
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        const data = await res.json()
        const rules = Array.isArray(data) ? data : Array.isArray(data?.rules) ? data.rules : []
        if (rules.length === 0) throw new Error('empty rule set')
        for (const rule of rules) {
          if (rule && typeof rule.id === 'string' && Array.isArray(rule.patterns)) {
            fetched.push(rule)
            updated++
          }
        }
      } catch (err) {
        failed++
        console.warn(`[Scanner] update rule source failed: ${source}`, err)
      }
    }

    if (fetched.length > 0) {
      this.extraRules = fetched
      this.cache.clear()
    }
    return { updated, failed }
  }

  startAutoUpdate(callback) {
    if (this.autoUpdateInterval <= 0 || this.remoteSources.length === 0) return
    if (this.updateTimer) clearInterval(this.updateTimer)
    this.updateTimer = setInterval(async () => {
      await this.updateRules()
      callback?.()
    }, this.autoUpdateInterval * 60 * 1000)
    this.updateTimer.unref?.()
  }

  stopAutoUpdate() {
    if (this.updateTimer) {
      clearInterval(this.updateTimer)
      this.updateTimer = null
    }
  }


  async scanPlugin(pluginPath, pluginName) {
    const name = pluginName ?? path.basename(pluginPath)

    if (this.config.whitelist.some((w) => name.includes(w))) {
      return {
        pluginName: name,
        pluginPath,
        scannedAt: new Date().toISOString(),
        findings: [],
        fileResults: [],
        riskScore: 0,
        riskLevel: 'clean',
        durationMs: 0,
        skipped: true,
        reason: 'whitelisted',
      }
    }

    if (this.config.blacklist.some((b) => name.includes(b))) {
      return {
        pluginName: name,
        pluginPath,
        scannedAt: new Date().toISOString(),
        findings: [{
          ruleId: 'POL-001',
          ruleName: '黑名单插件',
          severity: 'critical',
          category: 'privilege-escalation',
          description: '插件命中安全卫士黑名单策略',
          filePath: '',
          line: 0,
          column: 0,
          match: name,
          lineContent: '',
          recommendation: '该插件已被加入黑名单。如需使用，请先从黑名单中移除并重新扫描。',
        }],
        fileResults: [],
        riskScore: 25,
        riskLevel: 'critical',
        durationMs: 0,
        skipped: false,
        reason: 'blacklisted',
      }
    }

    const cacheKey = this.cacheKey(pluginPath)
    if (this.cache.has(cacheKey)) return this.cache.get(cacheKey)

    const startedAt = Date.now()
    const findings = []
    const fileResults = []
    let skipped = false
    let reason = ''

    try {
      const stat = await fs.stat(pluginPath)
      if (!stat.isDirectory()) {
        // Single file scan
        const rel = path.basename(pluginPath)
        const result = await this.scanFile(pluginPath, path.dirname(pluginPath))
        fileResults.push(result)
        findings.push(...result.findings)
      } else {
        const files = await this.collectFiles(pluginPath)
        for (const filePath of files) {
          const result = await this.scanFile(filePath, pluginPath)
          fileResults.push(result)
          findings.push(...result.findings)
        }
      }
    } catch (err) {
      skipped = true
      reason = `read_error: ${err instanceof Error ? err.message : String(err)}`
    }

    const riskScore = this.calculateRiskScore(findings)
    const riskLevel = this.scoreToLevel(riskScore)
    const report = {
      pluginName: name,
      pluginPath,
      scannedAt: new Date().toISOString(),
      findings,
      fileResults,
      riskScore,
      riskLevel,
      durationMs: Date.now() - startedAt,
      skipped,
      reason: reason || undefined,
    }

    this.cache.set(cacheKey, report)
    return report
  }

  async scanInstalledPlugins(pluginRoots, { includeNodeModules = this.config.includeNodeModules } = {}) {
    const roots = Array.isArray(pluginRoots) ? pluginRoots : []
    const seen = new Map()
    const startedAt = Date.now()

    for (const root of roots) {
      const packages = await this.listPluginPackages(root)
      for (const pkg of packages) {
        if (pkg.name === 'dsh-security-guard') continue
        if (!seen.has(pkg.path)) seen.set(pkg.path, pkg)
      }
    }

    const pluginList = [...seen.values()]
    const pluginReports = []
    for (const pkg of pluginList) {
      const report = await this.scanPlugin(pkg.path, pkg.name)
      pluginReports.push(report)
    }

    const allFindings = pluginReports.flatMap((r) => r.findings.map((f) => ({ ...f, pluginName: r.pluginName })))
    allFindings.sort((a, b) => SEVERITY_WEIGHTS[b.severity] - SEVERITY_WEIGHTS[a.severity] || b.ruleId.localeCompare(a.ruleId))

    const riskScore = this.calculateRiskScore(allFindings)
    const riskLevel = this.scoreToLevel(riskScore)
    return {
      pluginCount: pluginReports.length,
      scannedAt: new Date().toISOString(),
      durationMs: Date.now() - startedAt,
      riskScore,
      riskLevel,
      findings: allFindings,
      plugins: pluginReports,
    }
  }

  async scanFile(filePath, basePath) {
    const relPath = path.relative(basePath, filePath) || path.basename(filePath)
    const findings = []

    try {
      const stat = await fs.stat(filePath)
      if (stat.size > this.config.maxFileSize) {
        return { filePath: relPath, findings, skipped: true, reason: 'too_large' }
      }

      const content = await fs.readFile(filePath, 'utf8')
      const lines = content.split('\n')

      for (const rule of this.activeRules()) {
        if (rule.filePatterns && !rule.filePatterns.some((p) => filePath.endsWith(p.replace('*', '')))) {
          continue
        }

        for (const pattern of rule.patterns) {
          const regex = new RegExp(pattern.source, pattern.flags.includes('g') ? pattern.flags : `${pattern.flags}g`)
          let match
          while ((match = regex.exec(content)) !== null) {
            const lineStart = content.lastIndexOf('\n', match.index) + 1
            const lineNum = content.slice(0, match.index).split('\n').length
            const colNum = match.index - lineStart + 1
            findings.push({
              ruleId: rule.id,
              ruleName: rule.name,
              severity: rule.severity,
              category: rule.category,
              description: rule.description,
              filePath: relPath,
              line: lineNum,
              column: colNum,
              match: match[0].slice(0, 120),
              lineContent: (lines[lineNum - 1] ?? '').trim(),
              recommendation: this.recommendation(rule.category),
            })
            if (findings.length >= 500) break
          }
          if (findings.length >= 500) break
        }
        if (findings.length >= 500) break
      }

      return { filePath: relPath, findings, skipped: false }
    } catch (err) {
      return { filePath: relPath, findings, skipped: true, reason: 'read_error', error: String(err) }
    }
  }

  async collectFiles(dir) {
    const files = []
    const stack = [dir]

    while (stack.length > 0 && files.length < MAX_TOTAL_FILES) {
      const current = stack.pop()
      let entries
      try {
        entries = await fs.readdir(current, { withFileTypes: true })
      } catch {
        continue
      }

      for (const entry of entries) {
        if (files.length >= MAX_TOTAL_FILES) break
        const fullPath = path.join(current, entry.name)

        // Follow symlinks: pnpm/generation packages often contain linked
        // directories; dirent.isDirectory() would skip them and create
        // scan blind spots.
        let stat
        try { stat = await fs.stat(fullPath) } catch { continue }
        if (stat.isDirectory()) {
          if (entry.name === 'node_modules' && !this.config.includeNodeModules) continue
          if (entry.name === '.git' || entry.name === '.cache') continue
          stack.push(fullPath)
        } else if (stat.isFile()) {
          const ext = path.extname(entry.name).toLowerCase()
          if (SCAN_EXTENSIONS.has(ext)) files.push(fullPath)
        }
      }
    }

    return files
  }

  async listPluginPackages(root) {
    const packages = []
    try {
      const entries = await fs.readdir(root, { withFileTypes: true })
      for (const entry of entries) {
        const fullPath = path.join(root, entry.name)

        // pnpm/generation installs plugins as symlinks into node_modules.
        // Use fs.stat (follows symlinks) instead of dirent.isDirectory() so
        // those packages are discovered too.
        let stat
        try { stat = await fs.stat(fullPath) } catch { continue }
        if (!stat.isDirectory()) continue

        if (entry.name.startsWith('@')) {
          try {
            const scoped = await fs.readdir(fullPath, { withFileTypes: true })
            for (const sub of scoped) {
              const subPath = path.join(fullPath, sub.name)
              let subStat
              try { subStat = await fs.stat(subPath) } catch { continue }
              if (!subStat.isDirectory()) continue
              if (this.looksLikePlugin(subPath)) packages.push({ name: `${entry.name}/${sub.name}`, path: subPath })
            }
          } catch { /* ignore */ }
        } else if (this.looksLikePlugin(fullPath)) {
          packages.push({ name: entry.name, path: fullPath })
        }
      }
    } catch { /* ignore */ }

    return packages
  }

  looksLikePlugin(dir) {
    if (!existsSync(path.join(dir, 'package.json'))) return false
    try {
      const pkg = JSON.parse(readFileSync(path.join(dir, 'package.json'), 'utf8'))
      if (pkg && typeof pkg === 'object') {
        const name = String(pkg.name ?? '')
        if (name.startsWith('@dsh') || name.includes('dsh-')) return true
        if (pkg.dsh || pkg.keywords?.some((k) => String(k).includes('dsh'))) return true
      }
    } catch { /* ignore */ }
    return false
  }

  calculateRiskScore(findings) {
    let score = 0
    const seenRules = new Set()
    for (const f of findings) {
      const weight = SEVERITY_WEIGHTS[f.severity] ?? 1
      if (seenRules.has(f.ruleId)) {
        score += weight * 0.3
      } else {
        score += weight
        seenRules.add(f.ruleId)
      }
    }
    return Math.round(score)
  }

  scoreToLevel(score) {
    if (score === 0) return 'clean'
    if (score < 5) return 'low'
    if (score < 15) return 'medium'
    if (score < 30) return 'high'
    return 'critical'
  }

  cacheKey(pluginPath) {
    try {
      const stat = statSync(pluginPath)
      const hash = createHash('sha256').update(`${pluginPath}:${stat.mtimeMs}`).digest('hex')
      return hash.slice(0, 16)
    } catch {
      return createHash('sha256').update(pluginPath).digest('hex').slice(0, 16)
    }
  }

  recommendation(category) {
    return RECOMMENDATIONS[category] ?? '请人工审查此插件的安全风险'
  }

  clearCache() {
    this.cache.clear()
  }
}