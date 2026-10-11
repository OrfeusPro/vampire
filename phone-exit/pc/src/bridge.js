import { Buffer } from 'node:buffer';
export const WINDOW = 262144;
export const FRAME = 16384;

// Credit acknowledges TCP writes, rather than just arrival in the SCTP queue.
export function bridge(socket, channel, { onReady = () => {}, onError = () => {}, initiallyReady = false } = {}) {
  let credit = WINDOW, outstanding = 0, ready = initiallyReady, closed = false;
  let txEof = false, rxEof = false, incoming = 0, drainTimer;
  const queue = [];
  let queued = 0;
  socket.pause();
  channel.bufferedAmountLowThreshold = FRAME;
  const send = value => channel.send(JSON.stringify(value));
  function destroy() {
    if (closed) return;
    closed = true; clearTimeout(timer); clearInterval(drainTimer); socket.destroy(); channel.close();
  }
  function flush() {
    if (!ready || closed || channel.readyState !== 'open') return;
    while (queue.length && credit >= queue[0].length && channel.bufferedAmount < WINDOW) {
      const chunk = queue.shift(); queued -= chunk.length; credit -= chunk.length;
      outstanding += chunk.length; channel.send(chunk);
    }
    if (!queue.length && txEof) sendEof();
    if (!txEof && queued < FRAME && credit >= FRAME && channel.bufferedAmount < WINDOW) socket.resume();
    else socket.pause();
  }
  let eofSent = false;
  function sendEof() { if (!eofSent) { eofSent = true; send({type:'eof'}); } }
  const timer = setTimeout(() => { onError(4); destroy(); }, 15000);
  if (initiallyReady) { clearTimeout(timer); queueMicrotask(flush); }
  channel.bufferedAmountLow.subscribe(flush);
  channel.onMessage.subscribe(data => {
    if (closed) return;
    try {
      if (Buffer.isBuffer(data)) {
        if (!ready || rxEof || data.length === 0 || data.length > FRAME || incoming + data.length > WINDOW) throw Error('frame');
        incoming += data.length;
        socket.write(data, error => {
          incoming -= data.length;
          if (error) return destroy();
          if (!closed && channel.readyState === 'open') send({type:'credit',bytes:data.length});
        });
        return;
      }
      if (typeof data !== 'string' || Buffer.byteLength(data) > 1024) throw Error('control');
      const msg = JSON.parse(data);
      if (msg.type === 'ready' && !ready) { ready = true; clearTimeout(timer); onReady(); flush(); }
      else if (msg.type === 'error') { onError(Number.isInteger(msg.code) && msg.code >= 1 && msg.code <= 8 ? msg.code : 1); destroy(); }
      else if (msg.type === 'credit' && ready && Number.isInteger(msg.bytes) && msg.bytes > 0 && msg.bytes <= outstanding) {
        outstanding -= msg.bytes; credit += msg.bytes; flush();
      } else if (msg.type === 'eof' && ready && !rxEof) { rxEof = true; socket.end(); }
      else throw Error('unexpected message');
    } catch { onError(1); destroy(); }
  });
  socket.on('data', data => {
    for (let p = 0; p < data.length; p += FRAME) {
      const chunk = data.subarray(p, p + FRAME); queue.push(chunk); queued += chunk.length;
    }
    if (queued > WINDOW) return destroy();
    flush();
  });
  socket.on('end', () => { txEof = true; flush(); });
  socket.on('error', destroy);
  socket.on('close', () => {
    if (!txEof || !rxEof) return destroy();
    // TCP can close while SCTP still has the final response queued.
    let attempts = 0;
    drainTimer = setInterval(() => {
      if (closed) return;
      if ((outstanding === 0 && incoming === 0 && queued === 0 && channel.bufferedAmount === 0) || ++attempts > 1500) destroy();
    },20);
  });
  channel.stateChange.subscribe(state => { if (state === 'closed') { onError(1); destroy(); } });
  return { destroy };
}
