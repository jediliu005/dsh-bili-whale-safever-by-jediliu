// 出站机密闸（2026-11-17 主人要求）
//
// 背景：18:38 我把 `C:\...\notify-44.txt` 当正文发了出去——那是把本地临时文件路径
//   误当参数递给了 notify。主人提醒：万一是 token / 密钥，就把工作量送给贼了。
// 规则：任何「发给 B 站的字」（私信 / 通知）在发送前扫一遍，命中就拦下，不发。
//   只拦不改：宁可拒绝发送，也不替人删字（删了可能把本来对的内容改坏，还得重发）。
//
// 命中面（保守，宁可误拦）：
//   ① Windows / POSIX 绝对路径
//   ② 常见凭据前缀：sk-、ghp_、github_pat_、xoxb-、AKIA、AIza、Bearer <token>
//   ③ 「token/密钥/密码/secret」后面紧跟一串看起来像值的字符
//   ④ 32 位以上纯十六进制串（md5/sha 摘要、部分 token）
//   ⑤ 形如 user:pass@host 的带凭据 URL
// 允许：BV 号、rpid、普通中文、链接（http(s):// 无凭据）。
//
// 2026-11-17 追加（主人要求）：入场口令也能给发送授权。
//   正文按入场校验的同一套规则识别口令；命中即视为主人授权——抹掉口令后再发，
//   不因机密规则拦下；口令本身永不外发。具体写法不在注释、文档、回复里复述。

import { verifyToken, scrubToken, guardConfig } from '../../lib/inbound-guard.js'
import { config } from './config.mjs'

const RULES = [
  { id: 'path', re: /[A-Za-z]:\\[^\s"']+|\/(?:home|Users|root|etc|var|opt)\/[^\s"']+/, why: '本机绝对路径' },
  { id: 'token-prefix', re: /\b(?:sk-[A-Za-z0-9_-]{8,}|ghp_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{30,})/, why: '凭据前缀' },
  { id: 'bearer', re: /\bBearer\s+[A-Za-z0-9._-]{12,}/i, why: 'Bearer 令牌' },
  { id: 'named-secret', re: /(?:token|apikey|api[_-]?key|secret|password|passwd|密钥|令牌|授权码)\s*[:=：]\s*[A-Za-z0-9._~+/=-]{8,}/i, why: '字段名后跟疑似凭据值' },
  { id: 'hex32', re: /\b[0-9a-f]{32,}\b/i, why: '长十六进制串（摘要或 token）' },
  { id: 'cred-url', re: /[a-z][a-z0-9+.-]*:\/\/[^\s/@]+:[^\s/@]+@/i, why: '带用户名密码的链接' },
]

// 打码：留前 8 与后 4，中间省略，另附总长度。日志里永不出现完整凭据。
function maskHit(sample) {
  const s = String(sample ?? '')
  if (s.length <= 14) return `${s.slice(0, 3)}…（共 ${s.length} 字符）`
  return `${s.slice(0, 8)}…${s.slice(-4)}（共 ${s.length} 字符）`
}

export function scanOutbound(text) {
  const s = String(text ?? '')
  const hits = []
  for (const rule of RULES) {
    const m = s.match(rule.re)
    if (m) hits.push({ id: rule.id, why: rule.why, sample: String(m[0]), masked: maskHit(String(m[0])) })
  }
  return hits
}

// 返回 { ok:true } 或 { ok:false, hits }
export function checkOutbound(text) {
  const hits = scanOutbound(text)
  return hits.length ? { ok: false, hits } : { ok: true }
}

// 发送前调用：返回可发送的正文（口令已抹除）。
// 命中机密且无口令授权 → 打印三段式说明并 exit(3)。--allow-secretish 只能由人手动放行。
export function guardOutbound(text, { allow = false, label = '出站正文' } = {}) {
  const original = String(text ?? '')
  const hits0 = scanOutbound(original)
  if (allow) {
    const ids = hits0.map((h) => h.id).join(',') || 'none'
    console.log(`  ✓ 人工放行（--allow-secretish）· 命中规则：${ids} · ${new Date().toISOString()} · 仅本次 · 责任：加参数的人`)
    return original
  }
  const v = verifyToken(original, guardConfig(config()))
  const body = v.authorized ? scrubToken(original, v.token) : original
  if (v.authorized) {
    const rest = scanOutbound(body).map((h) => h.id)
    console.log(`  ✓ 口令授权 · 规则：${rest.join(',') || 'none'} · ${new Date().toISOString()} · 口令已抹除后放行 · 责任：口令授权人`)
    return body
  }
  const r = checkOutbound(body)
  if (r.ok) return body
  console.error(`✗ ${label}命中出站机密规则，已拦下未发送。`)
  console.error('  ① 命中类别：')
  for (const h of r.hits) console.error(`     · ${h.why}（规则 ${h.id}）`)
  console.error('  ② 命中片段（已打码）：')
  for (const h of r.hits) console.error(`     · ${h.masked}`)
  console.error('  ③ 下一步动作（三选一）：')
  console.error('     · 改内容：删掉这段，或改写成不含凭据/路径的说法，重跑一次')
  console.error('     · 走豁免：由主人授权，正文开头带口令 → 口令会被抹除后放行')
  console.error('     · 停手找人：人工加 --allow-secretish → 仅本次有效，日志会记时间与操作者')
  console.error('     可逆性：本闸只拦不发，不改任何文件；放行动作不做删除，撤回只需重新发送。')
  process.exit(3)
}
