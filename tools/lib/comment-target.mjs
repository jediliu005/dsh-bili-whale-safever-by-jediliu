import {guardedFetch as fetch} from './traffic.mjs'
import {exactJson} from './json-exact.mjs'
export async function checkCommentTarget(type,oid,headers) {
  if(!/^\d+$/.test(String(oid)))throw Error('评论 oid 必须是完整的十进制 ID 字符串')
  const r=await fetch('https://api.bilibili.com/x/v2/reply/main?'+new URLSearchParams({type:String(type),oid:String(oid),ps:'1',pn:'1'}),{headers})
  const j=await exactJson(r)
  if(!r.ok||j.code!==0)throw Error('目标不存在或不可评论：type='+type+' oid='+oid+' code='+j.code)
}
