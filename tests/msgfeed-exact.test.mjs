import test from 'node:test'
import assert from 'node:assert/strict'
import {pullFeed,resolveLatestReply} from '../tools/lib/msgfeed.mjs'
import {checkCommentTarget} from '../tools/lib/comment-target.mjs'
process.env.BILI_TRAFFIC_TEST='1'
const original=globalThis.fetch
test.after(()=>{globalThis.fetch=original})
test('issue 39: raw large IDs survive inbox and thread reads; dynamic type 17 and root zero work',async()=>{
 const urls=[]
 globalThis.fetch=async url=>{
  const u=new URL(url);urls.push(u)
  if(u.pathname.includes('/msgfeed/'))return new Response('{"code":0,"data":{"items":[{"id":9007199254740993,"reply_time":1000,"user":{"mid":222},"item":{"subject_id":1262823889456594949,"business_id":17,"root_id":0,"source_id":9007199254740995}}]}}')
  return new Response('{"code":0,"data":{"root":{"rpid":9007199254740995,"mid":222,"ctime":1000,"content":{"message":"actual reply"}},"replies":[]}}')
 }
 const {items}=await pullFeed('reply',{headers:{}}),item=items[0]
 assert.equal(item.oid,'1262823889456594949');assert.equal(item.parent,'9007199254740995');assert.equal(item.id,'9007199254740993')
 const reply=await resolveLatestReply({...item,parentRpid:item.parent,headers:{}})
 assert.equal(reply.rpid,item.parent);assert.equal(reply.text,'actual reply');assert.equal(reply.exact,true)
 assert.equal(urls[1].searchParams.get('type'),'17');assert.equal(urls[1].searchParams.get('oid'),item.oid);assert.equal(urls[1].searchParams.get('root'),item.parent)
})
test('issue 39: rejected target stops preflight; exact ID and type preserved; no POST',async()=>{
 const requests=[];let code=-404
 globalThis.fetch=async(url,opts)=>{requests.push({url:new URL(url),method:opts.method??'GET'});return new Response(JSON.stringify({code}))}
 await assert.rejects(checkCommentTarget('17','1262823889456595000',{}),/目标不存在/)
 code=0;await checkCommentTarget('17','1262823889456594949',{})
 assert.equal(requests[1].url.searchParams.get('oid'),'1262823889456594949')
 assert.equal(requests[1].url.searchParams.get('type'),'17');assert.ok(requests.every(r=>r.method==='GET'))
})
