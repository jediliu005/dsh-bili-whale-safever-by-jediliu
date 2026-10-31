import net from 'node:net'
import crypto from 'node:crypto'
import path from 'node:path'
export async function acquireProcessLock(file) {
  const canonical=path.resolve(file)
  const hash=crypto.createHash('sha256').update(process.platform==='win32'?canonical.toLowerCase():canonical).digest('hex')
  const server=net.createServer(socket=>socket.destroy())
  const address=process.platform==='win32' ? {path:'\\\\.\\pipe\\bili-whale-'+hash} : {host:'127.0.0.1',port:49152+parseInt(hash.slice(0,8),16)%16384,exclusive:true}
  await new Promise((resolve,reject)=>{
    server.once('error',reject);server.listen(address,resolve)
  }).catch(e=>{throw Error('私信状态锁不可用（可能有另一个监听进程）：'+e.code)})
  return ()=>new Promise((resolve,reject)=>server.close(e=>e?reject(e):resolve()))
}
