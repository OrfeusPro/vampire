export function downloadProbeResult(value,id,type='download-probe'){
  if(value?.type!==type||value.id!==id||!Number.isSafeInteger(value.bytes)||value.bytes<0||value.bytes>5000000
    ||!Number.isSafeInteger(value.elapsedMs)||value.elapsedMs<1||value.elapsedMs>65000||typeof value.success!=='boolean'
    ||(value.success&&value.bytes!==5000000))return null;
  return {bytes:value.bytes,seconds:value.elapsedMs/1000,bytesPerSecond:Math.round(value.bytes*1000/value.elapsedMs),success:value.success};
}
