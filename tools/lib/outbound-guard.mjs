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

export function scanOutbound(text) {
  const s = String(text ?? '')
  const hits = []
  for (const rule of RULES) {
    const m = s.match(rule.re)
    if (m) hits.push({ id: rule.id, why: rule.why, sample: String(m[0]).slice(0, 40) })
  }
  return hits
}

// 返回 { ok:true } 或 { ok:false, hits }
export function checkOutbound(text) {
  const hits = scanOutbound(text)
  return hits.length ? { ok: false, hits } : { ok: true }
}

// 发送前调用：返回可发送的正文（口令已抹除）。
// 命中机密且无口令授权 → 打印原因并 exit(3)。--allow-secretish 只能由人手动放行。
export function guardOutbound(text, { allow = false, label = '出站正文' } = {}) {
  const original = String(text ?? '')
  if (allow) return original
  const v = verifyToken(original, guardConfig(config()))
  const body = v.authorized ? scrubToken(original, v.token) : original
  if (v.authorized) {
    console.log('  ✓ 口令命中：视为主人授权，口令已抹除后放行（不再按机密规则拦）')
    return body
  }
  const r = checkOutbound(body)
  if (r.ok) return body
  console.error(`✗ ${label}里发现疑似机密，已拦下未发送：`)
  for (const h of r.hits) console.error(`   · ${h.why}：${h.sample}`)
  console.error('  说明：出站机密闸（lib/outbound-guard.mjs）。两条放行方式：正文开头带授权口令，或人工加 --allow-secretish。')
  process.exit(3)
}
