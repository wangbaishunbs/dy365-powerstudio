/*!
 * DY365 BLE 协议库 v1.0 —— 独立可复用(浏览器 / Node 通用)
 * =========================================================================
 * 来源:e-Bull 电牛V2 v1.1.2 APK 逆向(差分测试 0 差异)+ ZT-DY365 真机验证
 *
 * 适用设备:众仪 ZOYI ZT-DY365(电源+万用表二合一)及 ZT-DY/ZOYI/POWER 系列
 * BLE:服务 0000FFF0;每条通知/每个 20 字节分包用 20 字节密钥独立 XOR
 * 帧式:A5 5A | LEN | ADDR | FUNC | CTL | DATA… | CRC16_HI | CRC16_LO | 0D 0A
 *       LEN = DATA.length + 3;CRC 覆盖 [LEN,ADDR,FUNC,CTL,DATA…],大端附加
 *
 * 浏览器用法:
 *   <script src="dy365-ble-protocol.js"></script>
 *   const ble = new DY365.Dy365BLE({
 *     keepalive: 'starvation',            // 'starvation'=静音(默认,仅断流补发)
 *                                         // 'interval'  =e-Bull 原版,每 2s 心跳(设备每 2s 滴一声)
 *     onFrame : fr => {},                 // 每个完整帧 {addr, f, st, data:Uint8Array}
 *     onStatus: (s, info) => {},          // 'connecting'|'connected'|'disconnected'|'stalled'|'error'
 *     onError : e  => {},                 // 错误对象(含 message)
 *   });
 *   await ble.connect();                  // 弹出系统蓝牙选择框(需用户手势)
 *   await ble.send(new Uint8Array([1]), 0xfc, 0x02);   // 例:打开输出
 *   ble.disconnect();
 *
 * Node 用法(仅协议层,无蓝牙):
 *   const DY365 = require('./dy365-ble-protocol.js');
 *   const f = DY365.buildFrame(0, 0xff, 0x00);
 * ========================================================================= */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.DY365 = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  /* ---------------- CRC16(查表,poly 0xA001 反射,初值/末异或 FFFF) ---------------- */
  const CRC16 = (() => {
    const T = new Uint16Array(256);
    for (let n = 0; n < 256; n++) {
      let c = (n << 8) & 0xffff;
      for (let i = 0; i < 8; i++) c = (c & 0x8000) ? ((c << 1) ^ 0xA001) & 0xffff : (c << 1) & 0xffff;
      T[n] = c;
    }
    return {
      table: T,
      compute(bytes, offset = 0, length = bytes.length) {
        let crc = 0xffff;
        for (let i = 0; i < length; i++)
          crc = (((crc << 8) & 0xffff) ^ T[((crc >> 8) ^ bytes[offset + i]) & 0xff]) & 0xffff;
        return (crc ^ 0xffff) & 0xffff;
      }
    };
  })();

  /* ---------------- 204B 状态结构(show_data,小端;BLE 路径补齐 208B 含 cycle) ---------------- */
  const META = [
    ['in_vol','f',2],['out_vol','f',2],['out_ele','f',3],['power','f',1],
    ['temperature','f',1],['temperature2','f',1],['temperature3','f',1],
    ['bat_vol','f',2],['power_sum_Wh','f',3],['power_sum_Ah','f',3],
    ['display_version','u16'],['power_version','u16'],['product_model','u16'],['output_time_num','u16'],
    ['output_status','u8'],['cc_cv_flag','u8'],['error_status','u8'],['bat_capacity','u8'],
    ['charge_status','u8'],['output_time','u8'],['tool_status','u8'],['fmt_status','u8'],
    ['mult_point','u8'],['mult_gears','u8'],['mult_unit','u8'],['reserve_a','u8'],
    ['mult_show','f',0],
    ['set_vol','f',2],['set_ele','f',3],['alarm_vol','f',2],['alarm_ele','f',2],
    ...Array.from({length:10},(_,i)=>[`m_set_vol${i+1}`,'f',2]),
    ...Array.from({length:10},(_,i)=>[`m_set_ele${i+1}`,'f',3]),
    ['over_vol_protection','f',2],['over_ele_protection','f',3],['over_power_protection','f',2],
    ['under_vol_protection','f',2],['over_temperature_protection','f',0],
    ['time_ouput','u32'],['device_addr','u16'],['m_save_index','u8'],
    ['set_language','i8'],['set_brightness','i8'],['set_volume','i8'],['set_measurement','i8'],['set_curve','i8'],
    ['read_index','u8'],['alarm_flag','u8'],['select_vol','u8'],['sleep_time','u8'],['mult_hold_flag','u8'],
    ['reserve_b','u8'],['reserve2','u8'],['reserve3','u8'],
    ['power_sum_time','u32'],
  ];
  const STATE_SIZE = META.reduce((s, [, t]) => s + ({ f: 4, u32: 4, u16: 2 }[t] || 1), 0); // 204

  function defaultState() {
    const st = {};
    for (const [k] of META) st[k] = 0;
    return st;
  }

  function encodeState(st) {
    const u8 = new Uint8Array(STATE_SIZE);
    const dv = new DataView(u8.buffer);
    let o = 0;
    for (const [k, t] of META) {
      const v = st[k] ?? 0;
      if (t === 'f') { dv.setFloat32(o, Number(v) || 0, true); o += 4; }
      else if (t === 'u32') { dv.setUint32(o, (+v >>> 0), true); o += 4; }
      else if (t === 'u16') { dv.setUint16(o, (+v) & 0xffff, true); o += 2; }
      else if (t === 'i8') { dv.setInt8(o, +v | 0); o += 1; }
      else { u8[o++] = (+v) & 0xff; }
    }
    return u8;
  }

  function decodeState(bytes) {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const st = {}; let o = 0;
    for (const [k, t] of META) {
      if (t === 'f') { st[k] = dv.getFloat32(o, true); o += 4; }
      else if (t === 'u32') { st[k] = dv.getUint32(o, true); o += 4; }
      else if (t === 'u16') { st[k] = dv.getUint16(o, true); o += 2; }
      else if (t === 'i8') { st[k] = dv.getInt8(o); o += 1; }
      else { st[k] = bytes[o++]; }
    }
    return st;
  }

  /* ---------------- 帧封装 / 解析 ---------------- */
  function buildFrame(addr, func, ctl, data = new Uint8Array(0)) {
    const len = data.length + 3;
    const f = new Uint8Array(data.length + 10);
    f[0] = 0xa5; f[1] = 0x5a; f[2] = len; f[3] = addr & 0xff; f[4] = func & 0xff; f[5] = ctl & 0xff;
    f.set(data, 6);
    const crc = CRC16.compute(f, 2, len + 1);
    f[6 + data.length] = crc >> 8; f[7 + data.length] = crc & 0xff;
    f[8 + data.length] = 0x0d; f[9 + data.length] = 0x0a;
    return f;
  }

  /** 从字节流提取完整帧 → {frames:[{addr,f,st,data}], rest} */
  function parseFrames(buf) {
    const frames = [];
    let i = 0;
    while (i + 7 <= buf.length) {
      if (buf[i] !== 0xa5 || buf[i + 1] !== 0x5a) { i++; continue; }
      const len = buf[i + 2];
      const total = len + 7;
      if (i + total > buf.length) break;                                    // 不完整
      if (buf[i + total - 2] !== 0x0d || buf[i + total - 1] !== 0x0a) { i++; continue; }
      const crc = (buf[i + len + 3] << 8) | buf[i + len + 4];
      if (CRC16.compute(buf, i + 2, len + 1) !== crc) { i++; continue; }    // CRC 失败
      frames.push({ addr: buf[i + 3], f: buf[i + 4], st: buf[i + 5], data: buf.slice(i + 6, i + 3 + len) });
      i += total;
    }
    return { frames, rest: buf.slice(i) };
  }

  /* ---------------- BLE 传输层 ---------------- */
  const BLE_SERVICE = '0000fff0-0000-1000-8000-00805f9b34fb';
  const DEVICE_FILTERS = [{ namePrefix: 'ZT-DY' }, { namePrefix: 'ZOYI' }, { namePrefix: 'POWER' }];
  /** 20 字节 XOR 密钥(e-Bull usartEncCode;每条通知/每个 20B 分包从 key[0] 独立开始) */
  const BLE_KEY = Uint8Array.from([65, 33, 115, 85, 162, 193, 50, 113, 102, 170,
                                   59, 208, 226, 168, 51, 20, 32, 26, 170, 187]);
  const xorCode = (u8) => { const o = new Uint8Array(u8.length); for (let i = 0; i < u8.length; i++) o[i] = u8[i] ^ BLE_KEY[i % 20]; return o; };
  const concatU8 = (a, b) => { const n = new Uint8Array(a.length + b.length); n.set(a); n.set(b, a.length); return n; };

  /** 应答帧 ctl 含义:f=0 时 — 1=system_data 2/3/4=ctl_data 6=pre_data 7=cycle_ok 其它=show_data */
  const CMD = {
    HANDSHAKE:   { func: 0xff, ctl: 0x00 },   // 握手/心跳,空 payload
    OUTPUT:      { func: 0xfc, ctl: 0x02 },   // payload [1]/[0]
    RECALL_GROUP:{ func: 0xfc, ctl: 0x03 },   // payload [组号 0..9]
    MULT_GEAR:   { func: 0xfc, ctl: 0x04 },   // payload [档位码]
    WRITE_ALL:   { func: 0xfd, ctl: 0x01 },   // payload: 状态体 208B
    SET_VI:      { func: 0xfd, ctl: 0x05 },   // payload: 状态体 208B
    REQ_PRESET:  { func: 0xfe, ctl: 0x06 },   // 请求 10 组预置(120B 应答),空 payload
  };

  /**
   * Dy365BLE —— Web Bluetooth 连接类(仅浏览器环境)
   * @param {object} opts
   *   keepalive   'starvation'(默认,静音:仅断流>stallMs 时补发心跳)
   *               | 'interval'(e-Bull 原版:握手后每 heartbeatMs 必发;设备对每条命令滴一声)
   *   stateSize   BLE 发送状态体的字节数,默认 208(与手机 App 一致,含 cycle=0 尾)
   *   silentMs    断流判失联阈值,默认 8000;0 = 不自动断开
   *   onFrame / onStatus / onError 回调
   */
  class Dy365BLE {
    constructor(opts = {}) {
      this.keepalive = opts.keepalive === 'interval' ? 'interval' : 'starvation';
      this.stateSize = opts.stateSize || 208;
      this.silentMs = opts.silentMs === undefined ? 8000 : opts.silentMs;
      this.handshakeMs = 500;
      this.heartbeatMs = 2000;
      this.stallMs = 3000;
      this.onFrame = opts.onFrame || (() => {});
      this.onStatus = opts.onStatus || (() => {});
      this.onError = opts.onError || (() => {});
      this.device = null; this.notify = null; this.write = null; this.writeResp = false;
      this.rxbuf = new Uint8Array(0);
      this.connected = false; this.connecting = false;
      this._hb = 0; this._wd = 0; this._lastRx = 0; this._lastHb = 0; this._gotRx = false;
    }

    /** 弹出系统蓝牙选择框并连接。resolve 于完全就绪;失败 reject(用户取消也 reject) */
    async connect() {
      if (this.connecting || this.connected) throw new Error('已在连接中/已连接');
      if (!('bluetooth' in navigator)) throw new Error('此浏览器不支持 Web Bluetooth,请使用 Edge/Chrome');
      this.connecting = true;
      this.onStatus('connecting');
      try {
        this.device = await navigator.bluetooth.requestDevice({
          filters: DEVICE_FILTERS, optionalServices: [BLE_SERVICE],
        });
        // Windows 上 Chrome 首次 gatt.connect() 常因广播时序失败,自动重试 3 次
        let server = null, lastErr = null;
        for (let a = 1; a <= 3 && !server; a++) {
          try { server = await this.device.gatt.connect(); }
          catch (e) { lastErr = e; if (a < 3) await new Promise(r => setTimeout(r, 800)); }
        }
        if (!server) throw lastErr || new Error('connect failed');
        const svc = await server.getPrimaryService(BLE_SERVICE);
        const chars = await svc.getCharacteristics();
        this.notify = chars.find(c => c.properties.notify);
        this.write = chars.find(c => c.properties.writeWithoutResponse || c.properties.write);
        if (!this.notify || !this.write) throw new Error('FFF0 服务特征不完整');
        this.writeResp = !this.write.properties.writeWithoutResponse;

        this.rxbuf = new Uint8Array(0); this._gotRx = false; this._lastRx = Date.now();
        await this.notify.startNotifications();
        this._onNotify = this._onNotify.bind(this);
        this.notify.addEventListener('characteristicvaluechanged', this._onNotify);
        this._onDrop = () => this._dropped();
        this.device.addEventListener('gattserverdisconnected', this._onDrop);

        this.connected = true;
        this.onStatus('connected', this.device.name);
        // 握手:每 500ms 直到收到首帧
        this._hb = setInterval(() => {
          if (!this._gotRx) this.send(new Uint8Array(0), CMD.HANDSHAKE.func, CMD.HANDSHAKE.ctl);
          else if (this.keepalive === 'interval') {
            if (Date.now() - this._lastHb >= this.heartbeatMs) { this._lastHb = Date.now(); this.send(new Uint8Array(0), CMD.HANDSHAKE.func, CMD.HANDSHAKE.ctl); }
          } else if (Date.now() - this._lastRx > this.stallMs && Date.now() - this._lastHb >= this.heartbeatMs) {
            this._lastHb = Date.now();                    // starvation 模式:断流才补发(静音)
            this.send(new Uint8Array(0), CMD.HANDSHAKE.func, CMD.HANDSHAKE.ctl);
          }
        }, this.handshakeMs);
        if (this.silentMs > 0) {
          this._wd = setInterval(() => {
            if (Date.now() - this._lastRx > this.silentMs) {
              this.onStatus('stalled');
              this.onError(new Error('断流超时,设备可能已离开/关机'));
              this.disconnect();
            }
          }, 1500);
        }
        return this.device.name;
      } finally {
        this.connecting = false;
      }
    }

    disconnect() {
      clearInterval(this._hb); clearInterval(this._wd); this._hb = this._wd = 0;
      try { this.notify?.stopNotifications(); this.notify?.removeEventListener('characteristicvaluechanged', this._onNotify); } catch {}
      try { this.device?.removeEventListener('gattserverdisconnected', this._onDrop); } catch {}
      try { this.device?.gatt.disconnect(); } catch {}
      this.device = this.notify = this.write = null;
      this.rxbuf = new Uint8Array(0);
      if (this.connected) { this.connected = false; this.onStatus('disconnected'); }
    }

    /** 发送命令。payload 为 Uint8Array;func/ctl 见 CMD */
    async send(payload, func, ctl) {
      if (!this.write) throw new Error('未连接');
      let data = payload || new Uint8Array(0);
      if (func === 0xfd && data.length === 204 && this.stateSize === 208)
        data = concatU8(data, new Uint8Array(this.stateSize - 204));   // 状态体补齐 cycle 尾
      const frame = buildFrame(0, func, ctl, data);                    // BLE 地址字节恒为 0
      const enc = xorCode(frame);
      for (let i = 0; i < enc.length; i += 20) {
        const chunk = enc.subarray(i, Math.min(i + 20, enc.length));
        if (!this.writeResp && this.write.writeValueWithoutResponse) await this.write.writeValueWithoutResponse(chunk);
        else await this.write.writeValue(chunk);
        if (enc.length > 20) await new Promise(r => setTimeout(r, 20));
      }
    }

    _onNotify(e) {
      const raw = e.target.value;
      const dec = xorCode(new Uint8Array(raw.buffer, raw.byteOffset, raw.byteLength));
      this.rxbuf = concatU8(this.rxbuf, dec);
      if (dec.length >= 2 && dec[dec.length - 2] === 0x0d && dec[dec.length - 1] === 0x0a) {
        this._gotRx = true; this._lastRx = Date.now();
        const { frames } = parseFrames(this.rxbuf);
        this.rxbuf = new Uint8Array(0);
        for (const fr of frames) this.onFrame(fr);
      }
      if (this.rxbuf.length > 4096) this.rxbuf = new Uint8Array(0);
    }

    _dropped() {
      const was = this.connected;
      this.disconnect();
      if (was) this.onError(new Error('蓝牙连接已断开'));
    }
  }

  return {
    CRC16, META, STATE_SIZE, defaultState, encodeState, decodeState,
    buildFrame, parseFrames, xorCode, concatU8, BLE_KEY, BLE_SERVICE, DEVICE_FILTERS, CMD, Dy365BLE,
  };
});
