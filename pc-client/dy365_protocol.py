# -*- coding: utf-8 -*-
"""
ZOYI/ZOTEK ZT-DY365 ("e-Bull 电牛" App) BLE 串口协议 —— 纯协议层,无 BLE 依赖。

协议来源:反编译 e-Bull 电牛V2 v1.1.2 (APK) 中 uni-app JS 层:
  assets/apps/__UNI__59084C7/www/app-service.js
    - 模块 0969 (utils/usart_power.js): XOR 编解码、帧打包、帧解析、字段表
    - 模块 f87f (utils/crc16.js): CRC16
    - 模块 3eb8 (utils/usart_mult.js): 万用表 5A A5 帧分发与命令打包
    - 模块 409a/437c/d3ca/62b4: 四种万用表子协议解析器
    - 模块 caf8 (pages/power_main/power_main.vue): ZT-DY365 页面交互时序

BLE 传输层(由 dy365_client.py 实现):
  - Service UUID 前缀 0000FFF0;notify 特征 + write 特征 (自动识别)
  - 发送:整帧 XOR 编码后按 20 字节分包写入 (writeNoResponse)
  - 接收:每条 notification 独立从密钥索引 0 开始 XOR 解码;
    电源协议(mode 0)按帧尾 \\r\\n 拼包后再解析;万用表协议(mode 1)逐包直接解析
"""
import math

XOR_KEY = bytes([65, 33, 115, 85, 162, 193, 50, 113, 102, 170,
                 59, 208, 226, 168, 51, 20, 32, 26, 170, 187])
XOR_KEY_LEN = 20


def xor_code(data: bytes) -> bytes:
    """usartEncCode: 与 20 字节密钥逐字节异或(自逆)。每个分包/每条通知从索引 0 开始。"""
    return bytes(b ^ XOR_KEY[i % XOR_KEY_LEN] for i, b in enumerate(data))


# ---------------------------------------------------------------- CRC16 ----
def _make_crc_table():
    table = []
    for e in range(256):
        t = (e << 8) & 0xFFFFFFFF
        for _ in range(8):
            t = ((t << 1) ^ 0xA001) if (t & 0x8000) else (t << 1)
            t &= 0xFFFF
        table.append(t)
    return table


_CRC_TABLE = _make_crc_table()


def crc16_calc(data: bytes, length: int) -> int:
    """crc16Calc: 与 utils/crc16.js 完全一致的查表实现。
    注意:索引用旧 CRC 的高字节,再整体左移异或 (a = (a<<8 ^ T[(a>>8)^b]) & 0xFFFF)。"""
    crc = 0xFFFF
    for i in range(min(length, len(data))):
        idx = ((crc >> 8) ^ (data[i] & 0xFF)) & 0xFF
        crc = ((crc << 8) ^ _CRC_TABLE[idx]) & 0xFFFF
    return 0xFFFF ^ crc


# ---------------------------------------------------------------- 帧封装 ----
def build_frame(payload: bytes, func: int, ctl: int) -> bytes:
    """usartPackaging: A5 5A [len] [0] [func] [ctl] [payload] [CRC_HI] [CRC_LO] 0D 0A
    len = len(payload) + 3 (覆盖 len/func/ctl/payload)
    CRC 覆盖 [len, 0, func, ctl, payload] 共 len+1 字节,大端放置。
    """
    s = len(payload)
    frame = bytearray(6 + s + 4)
    frame[0] = 0xA5
    frame[1] = 0x5A
    frame[2] = (s + 3) & 0xFF
    frame[3] = 0
    frame[4] = func & 0xFF
    frame[5] = ctl & 0xFF
    frame[6:6 + s] = payload
    c = crc16_calc(frame[2:6 + s], s + 4)
    frame[6 + s] = (c >> 8) & 0xFF
    frame[7 + s] = c & 0xFF
    frame[8 + s] = 0x0D
    frame[9 + s] = 0x0A
    return bytes(frame)


def split_package(data: bytes, size: int = 20):
    """splitPackage: 20 字节分包(BLE MTU 限制)。"""
    return [data[i:i + size] for i in range(0, len(data), size)]


def encode_tx(payload: bytes, func: int, ctl: int):
    """sendData 的完整发送流程:打包 → XOR 编码 → 20 字节分包。"""
    return [xor_code(chunk) for chunk in split_package(build_frame(payload, func, ctl), 20)]


# ---------------------------------------------------------------- 帧解析 ----
class Frame:
    __slots__ = ("func", "ctl", "payload")

    def __init__(self, func: int, ctl: int, payload: bytes):
        self.func = func
        self.ctl = ctl
        self.payload = payload

    def __repr__(self):
        return f"Frame(func=0x{self.func:02X}, ctl={self.ctl}, payload={self.payload.hex(' ').upper()})"


def resolve_frames(buf: bytes):
    """usartResolve: 扫描 A5 5A 头、校验 CRC、按 ctl 分发。
    返回 (frames, consumed)。func 固定为 0;ctl 含义:
      1          -> system_data (schema C)
      2 / 3 / 4  -> ctl_data    (schema C,设置命令的应答)
      6          -> pre_data    (schema S,10 组预置)
      7          -> cycle_ok    (无 payload)
      其他       -> show_data   (schema C,约 100ms 周期推送)
    """
    frames = []
    n = 0
    total = len(buf)
    while n < total:
        if n + 2 <= total and buf[n] == 0xA5 and buf[n + 1] == 0x5A:
            ln = buf[n + 2]
            crc_hi_off, crc_lo_off = n + 3 + ln, n + 4 + ln
            if crc_lo_off < total:
                crc_val = (buf[crc_hi_off] << 8) | buf[crc_lo_off]
                calc = crc16_calc(buf[n + 2:], ln + 1)
                if calc == crc_val:
                    func = buf[n + 4]
                    ctl = buf[n + 5]
                    payload = bytes(buf[n + 6: n + 3 + ln])
                    if func == 0:
                        frames.append(Frame(func, ctl, payload))
                    n += ln + 7
                    continue
        n += 1
    return frames, total


# ------------------------------------------------------------ 字段 schema ----
# (字段名, 类型, toFixed 小数位)。类型: f=float LE, u8, i8, u16, i16, u32
SCHEMA_C = [  # show_data / system_data / ctl_data 载荷 (205 字节)
    ("in_vol", "f", 2), ("out_vol", "f", 2), ("out_ele", "f", 3), ("power", "f", 1),
    ("temperature", "f", 1), ("temperature2", "f", 1), ("temperature3", "f", 1),
    ("bat_vol", "f", 2), ("power_sum_Wh", "f", 3), ("power_sum_Ah", "f", 3),
    ("display_version", "u16", 0), ("power_version", "u16", 0),
    ("product_model", "u16", 0), ("output_time_num", "u16", 0),
    ("output_status", "u8", 0), ("cc_cv_flag", "u8", 0), ("error_status", "u8", 0),
    ("bat_capacity", "u8", 0), ("charge_status", "u8", 0), ("output_time", "u8", 0),
    ("tool_status", "u8", 0), ("fmt_status", "u8", 0),
    ("mult_point", "u8", 0), ("mult_gears", "u8", 0), ("mult_unit", "u8", 0),
    ("reserve", "u8", 0),
    ("mult_show", "f", None),  # 小数位取已解析的 mult_point
    ("set_vol", "f", 2), ("set_ele", "f", 3),
    ("alarm_vol", "f", 2), ("alarm_ele", "f", 2),
    *[("m_set_vol%d" % i, "f", 2) for i in range(1, 11)],
    *[("m_set_ele%d" % i, "f", 3) for i in range(1, 11)],
    ("over_vol_protection", "f", 2), ("over_ele_protection", "f", 3),
    ("over_power_protection", "f", 2), ("under_vol_protection", "f", 2),
    ("over_temperature_protection", "f", 0),
    ("time_ouput", "u32", 0), ("device_addr", "u16", 0),
    ("m_save_index", "u8", 0), ("set_language", "i8", 0), ("set_brightness", "i8", 0),
    ("set_volume", "i8", 0), ("set_measurement", "i8", 0), ("set_curve", "i8", 0),
    ("read_index", "u8", 0), ("alarm_flag", "u8", 0), ("select_vol", "u8", 0),
    ("sleep_time", "u8", 0), ("mult_hold_flag", "u8", 0),
    ("reserve", "u8", 0), ("reserve2", "u8", 0), ("reserve3", "u8", 0),
    ("power_sum_time", "u32", 0), ("cycle", "u32", 0),
]

SCHEMA_S = [  # pre_data 载荷 (120 字节): 按"组"交错 (与 JS 表顺序一致)
    field
    for i in range(1, 11)
    for field in ((f"set_vol{i}", "f", 2), (f"set_ele{i}", "f", 3), (f"time_output{i}", "u32", 0))
]


def _fmt_float(value: float, digits) -> str:
    """JS Number.toFixed 等价:V8 对 .5 精确平局按"远离零"舍入
    (实测 (-78399.0625).toFixed(3) === "-78399.063")。"""
    if digits is None:
        digits = 0
    import decimal
    if math.isnan(value):
        return "NaN"
    if math.isinf(value):
        return "Infinity" if value > 0 else "-Infinity"
    with decimal.localcontext() as ctx:
        ctx.prec = max(60, digits + 50)  # toFixed 最大 100 位小数,精度须随位数扩展
        d = decimal.Decimal(float(value))
        q = decimal.Decimal(1).scaleb(-digits)
        r = d.quantize(q, rounding=decimal.ROUND_HALF_UP)  # 十进制 ROUND_HALF_UP = 远离零
    s = format(r, f".{digits}f")
    if value == 0.0 and math.copysign(1.0, value) < 0:
        s = format(abs(r), f".{digits}f")  # JS (-0).toFixed(2) === "0.00"
    return s


def decode_payload(payload: bytes, schema) -> dict:
    """u()/f() 解析器:按 schema 顺序读取,浮点保留 toFixed 字符串(与 App 显示一致)。
    任何解析错误 (如 mult_point>100 使 toFixed 抛 RangeError) → 返回 None,
    与 JS 端 try/catch 返回 undefined 的行为一致。"""
    try:
        out = {}
        off = 0
        import struct
        for name, typ, digits in schema:
            if typ == "f":
                if off + 4 > len(payload):
                    raise ValueError("short payload")
                (v,) = struct.unpack_from("<f", payload, off)
                off += 4
                if name == "mult_show":
                    digits = out.get("mult_point", 0)
                    if not isinstance(digits, int) or digits < 0 or digits > 100:
                        raise ValueError("toFixed digits out of range")
                out[name] = _fmt_float(v, digits)
                if name == "mult_show":
                    out["mult_show_raw"] = v
            elif typ == "u8":
                if off >= len(payload):
                    raise ValueError("short payload")
                out[name] = payload[off]
                off += 1
            elif typ == "i8":
                if off >= len(payload):
                    raise ValueError("short payload")
                v = payload[off]
                out[name] = v - 256 if v > 127 else v
                off += 1
            elif typ == "u16":
                if off + 2 > len(payload):
                    raise ValueError("short payload")
                out[name] = int.from_bytes(payload[off:off + 2], "little")
                off += 2
            elif typ == "i16":
                if off + 2 > len(payload):
                    raise ValueError("short payload")
                out[name] = int.from_bytes(payload[off:off + 2], "little", signed=True)
                off += 2
            elif typ == "u32":
                if off + 4 > len(payload):
                    raise ValueError("short payload")
                out[name] = int.from_bytes(payload[off:off + 4], "little")
                off += 4
            else:
                raise ValueError(typ)
        return out
    except Exception:
        return None


def _js_number(v):
    """JS Number() 语义: Number("12.34")=12.34, Number("OL")=NaN, Number("")=0, Number(null)=0"""
    if v is None:
        return 0.0
    if isinstance(v, bool):
        return 1.0 if v else 0.0
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v).strip()
    if s == "":
        return 0.0
    try:
        return float(s)
    except ValueError:
        return float("nan")


def encode_payload(data: dict, schema) -> bytes:
    """_encode/_encode2: 按字段表顺序写入(读-改-写回显)。
    注意:JS 端返回 r.slice(0, n+1) 会多带 1 个 allocUnsafe 未初始化字节,
    设备按 len 字段解析、忽略多余字节,这里返回干净的 schema 长度。"""
    import struct
    buf = bytearray(len(schema) * 8)
    off = 0
    for name, typ, _digits in schema:
        fv = _js_number(data.get(name, 0))
        if typ == "f":
            struct.pack_into("<f", buf, off, fv)
            off += 4
        elif typ == "u8":
            buf[off] = int(fv) & 0xFF
            off += 1
        elif typ == "i8":
            buf[off] = int(fv) & 0xFF
            off += 1
        elif typ == "u16":
            struct.pack_into("<H", buf, off, int(fv) & 0xFFFF)
            off += 2
        elif typ == "i16":
            struct.pack_into("<h", buf, off, int(fv) & 0xFFFF)
            off += 2
        elif typ == "u32":
            struct.pack_into("<I", buf, off, int(fv) & 0xFFFFFFFF)
            off += 4
    return bytes(buf[:off])


# 展示辅助(与 power_main 页面一致)
MULT_UNIT_TABLE = ["", "V", "mV", "A", "mA", "Hz", "KHz", "Ω", "KΩ", "MΩ", "nF", "uF", "mF", "F"]
MULT_GEARS_TABLE = ["AC", "DC", "R", "C", "BEEP", "DIODE"]
OUTPUT_ERROR_TABLE = ["", "OVP", "LVP", "OTP", "OPP", "OCP"]
INPUT_SELECT_TABLE = ["AUTO", "DC", "PD", "BAT"]


def _schema_size(schema) -> int:
    size = {"f": 4, "u8": 1, "i8": 1, "u16": 2, "i16": 2, "u32": 4}
    return sum(size[t] for _, t, _ in schema)


SCHEMA_C_SIZE = _schema_size(SCHEMA_C)   # 208
SCHEMA_S_SIZE = _schema_size(SCHEMA_S)   # 120


def classify_frame(frame: Frame):
    """按 ctl 将帧分类为 App 的数据类型。返回 (type_name, data)。
    payload 不足 schema 长度或解析出错时 data=None (对应 JS 解析器 catch 后返回 undefined)。"""
    ctl = frame.ctl
    if ctl == 1:
        return "system_data", decode_payload(frame.payload, SCHEMA_C)
    if ctl in (2, 3, 4):
        return "ctl_data", decode_payload(frame.payload, SCHEMA_C)
    if ctl == 6:
        return "pre_data", decode_payload(frame.payload, SCHEMA_S)
    if ctl == 7:
        return "cycle_ok", None
    return "show_data", decode_payload(frame.payload, SCHEMA_C)


# =====================================================================
# 万用表协议 (mode 1,设备名 "Bluetooth DMM",帧头 5A A5)
# =====================================================================
SEG_TABLE = [235, 10, 173, 143, 78, 199, 231, 138, 239, 207,
             238, 103, 225, 47, 229, 228, 97, 35, 101, 39, 4]

MULT_UNIT_TABLE_DMM = ["", "V", "mV", "A", "mA", "uA", "Hz", "KHz", "Ω", "KΩ", "MΩ",
                       "nF", "uF", "mF", "F", "", "MHz", "nV", "uV", "nA", "℃", "℉", "%"]


def _bit(v, mask):
    return 1 if (v & mask) == mask else 0


def _point_index(digs, n):
    for i in range(n):
        if _bit(digs[i], 16):
            return i + 1
    return 0


def _num_index(v):
    for t in range(10):
        if (v & 0xEF) == SEG_TABLE[t]:
            return t
    return 0 if v == 0 else -1


def _num_analyse(digs, point, count):
    # JS 中越界读取 undefined 等价于 0,这里补零对齐
    digs = list(digs) + [0] * 8
    val = 0
    for a in range(count):
        d = _num_index(digs[a])
        if d == -1:
            if (digs[a] & 0xEF) == SEG_TABLE[19]:
                if (digs[a + 1] & 0xEF) == SEG_TABLE[18] and \
                   (digs[a + 2] & 0xEF) == SEG_TABLE[17] and \
                   (digs[a + 3] & 0xEF) == SEG_TABLE[10]:
                    return -2  # AUTO
            elif (digs[a] & 0xEF) == SEG_TABLE[15] and (digs[a + 1] & 0xEF) == SEG_TABLE[14]:
                return -3  # EF (NCV)
            elif (digs[a] & 0xEF) == SEG_TABLE[20]:
                return -4 - a  # "----"
            return -1  # OL
        val += d * (10 ** a)
    return val / (10 ** point)


def _digits_from(payload):
    return [(payload[3] & 0xF0) | (payload[4] & 0x0F),
            (payload[2] & 0xF0) | (payload[3] & 0x0F),
            (payload[1] & 0xF0) | (payload[2] & 0x0F),
            (payload[0] & 0xF0) | (payload[1] & 0x0F)]


def _common_tail(d, ac, dc, beep, diode, R, F, V, A, m_v, u_v, n_v, m_a, u_a, n_a,
                 M, k, hz, temp_c, temp_f, percent):
    d["ncv"] = 0
    d["isAuto"] = 0
    d["acmv"] = d["acma"] = d["acv"] = d["aca"] = 0
    d["dcmv"] = d["dcma"] = d["dcv"] = d["dca"] = 0
    d["cap"] = d["diode_beep"] = d["res"] = 0
    if ac:
        d["gears"] = 0
        if m_v and V:
            d["acmv"] = 1
        elif m_v:
            d["acma"] = 1
        elif V:
            d["acv"] = 1
        else:
            d["aca"] = 1
    elif dc:
        d["gears"] = 1
        if m_v and V:
            d["dcmv"] = 1
        elif m_v:
            d["dcma"] = 1
        elif V:
            d["dcv"] = 1
        else:
            d["dca"] = 1
    elif beep and diode:
        d["gears"] = 6
        d["diode_beep"] = 1
    elif beep:
        d["gears"] = 4
    elif diode:
        d["gears"] = 5
    elif R:
        d["gears"] = 2
        d["res"] = 1
    elif F:
        d["gears"] = 3
        d["cap"] = 1
    else:
        d["gears"] = 7
    if d["gears"] != 7:
        d["ncv"] = 0
    if V:
        d["unit"] = 2 if m_v else (18 if u_v else (17 if n_v else 1))
    elif R:
        d["unit"] = 10 if M else (9 if k else 8)
    elif F:
        d["unit"] = 11 if n_v else (12 if u_v else (13 if m_a else 14))
    elif hz:
        d["unit"] = 16 if M else (7 if k else 6)
    elif A:
        d["unit"] = 19 if n_a else (5 if u_a else (4 if m_a else 3))
    elif temp_c:
        d["unit"] = 20
    elif temp_f:
        d["unit"] = 21
    elif percent:
        d["unit"] = 22
    else:
        d["unit"] = 0


def usart_qb5g_resolve(p):
    """子协议 1 (帧: 5A A5 01 + 7B payload)"""
    d = {}
    d["beep"] = _bit(p[0], 8)
    d["ble"] = _bit(p[0], 4)
    d["hold"] = _bit(p[0], 2)
    d["bat"] = _bit(p[0], 1)
    d["pol"] = _bit(p[0], 16)
    digs = _digits_from(p)
    point = _point_index(digs, 3)
    d["point"] = point
    big = _num_analyse(digs, point, 4)
    if big >= 0:
        if d["pol"]:
            big = -big
        d["data_big"] = f"{big:.{point}f}"
    elif big == -2:
        d["data_big"] = "AUTO"
        d["isAuto"] = 1
    elif big == -3:
        d["data_big"] = "EF"
        d["ncv"] = 1
    elif big == -1:
        d["data_big"] = "OL"
    elif big == -7:
        d["data_big"] = "-"
        d["ncv"] = 1
    elif big == -6:
        d["data_big"] = "--"
        d["ncv"] = 1
    elif big == -5:
        d["data_big"] = "---"
        d["ncv"] = 1
    elif big == -4:
        d["data_big"] = "----"
        d["ncv"] = 1
    ac, dc = _bit(p[4], 128), _bit(p[4], 64)
    V, n = _bit(p[4], 32), _bit(p[4], 16)
    u, A = _bit(p[5], 8), _bit(p[5], 4)
    diode, F = _bit(p[5], 2), _bit(p[5], 1)
    M, m = _bit(p[5], 128), _bit(p[5], 64)
    k, R = _bit(p[5], 32), _bit(p[5], 16)
    temp_c, temp_f = _bit(p[6], 8), _bit(p[6], 4)
    hz, rel = _bit(p[6], 2), _bit(p[6], 1)
    power, peak = _bit(p[6], 128), _bit(p[6], 64)
    percent, inrush = _bit(p[6], 32), _bit(p[6], 16)
    for key, val in [("ac", ac), ("dc", dc), ("V", V), ("n", n), ("u", u), ("A", A),
                     ("diode", diode), ("F", F), ("M", M), ("m", m), ("k", k), ("R", R),
                     ("temp_c", temp_c), ("temp_f", temp_f), ("hz", hz), ("rel", rel),
                     ("power", power), ("peak", peak), ("percent", percent), ("inrush", inrush)]:
        d[key] = val
    _common_tail(d, ac, dc, d["beep"], diode, R, F, V, A, m, u, n, m, u, n, M, k, hz, temp_c, temp_f, percent)
    return d


def usart_s5g_resolve(p):
    """子协议 2 (帧: 5A A5 02 + 7B payload)"""
    d = {}
    d["beep"] = _bit(p[0], 8)
    d["over_vol"] = _bit(p[0], 4)
    d["hold"] = _bit(p[0], 2)
    d["bat"] = _bit(p[0], 1)
    d["pol"] = _bit(p[0], 16)
    digs = _digits_from(p)
    point = _point_index(digs, 3)
    d["point"] = point
    big = _num_analyse(digs, point, 4)
    if big >= 0:
        if d["pol"]:
            big = -big
        d["data_big"] = f"{big:.{point}f}"
    elif big == -2:
        d["data_big"] = "AUTO"
        d["isAuto"] = 1
    elif big == -3:
        d["data_big"] = "EF"
        d["ncv"] = 1
    elif big == -1:
        d["data_big"] = "OL"
    elif big == -7:
        d["data_big"] = "-"
        d["ncv"] = 1
    elif big == -6:
        d["data_big"] = "--"
        d["ncv"] = 1
    elif big == -5:
        d["data_big"] = "---"
        d["ncv"] = 1
    elif big == -4:
        d["data_big"] = "----"
        d["ncv"] = 1
    d["ble"] = _bit(p[4], 128)
    d["power"] = _bit(p[4], 64)
    ac, dc = _bit(p[5], 8), _bit(p[5], 4)
    V, n = _bit(p[5], 2), _bit(p[5], 1)
    u, A = _bit(p[5], 128), _bit(p[5], 64)
    diode, F = _bit(p[5], 32), _bit(p[5], 16)
    M, m = _bit(p[6], 8), _bit(p[6], 4)
    k, R = _bit(p[6], 2), _bit(p[6], 1)
    temp_c, temp_f = _bit(p[6], 128), _bit(p[6], 64)
    hz, percent = _bit(p[6], 32), _bit(p[6], 16)
    for key, val in [("ac", ac), ("dc", dc), ("V", V), ("n", n), ("u", u), ("A", A),
                     ("diode", diode), ("F", F), ("M", M), ("m", m), ("k", k), ("R", R),
                     ("temp_c", temp_c), ("temp_f", temp_f), ("hz", hz), ("percent", percent)]:
        d[key] = val
    _common_tail(d, ac, dc, d["beep"], diode, R, F, V, A, m, u, n, m, u, n, M, k, hz, temp_c, temp_f, percent)
    return d


def usart_300ab_resolve(p):
    """子协议 3 (帧: 5A A5 03 + 8B payload) — ZT-300AB 系列"""
    d = {}
    d["beep"] = _bit(p[0], 8)
    d["ble"] = _bit(p[0], 4)
    d["trigon"] = _bit(p[0], 2)
    d["bat"] = _bit(p[0], 1)
    d["pol"] = _bit(p[0], 16)
    d["diode"] = _bit(p[4], 128)
    d["temp_c"] = _bit(p[4], 64)
    d["temp_f"] = _bit(p[4], 32)
    d["hold"] = _bit(p[4], 16)
    ac, percent = _bit(p[5], 8), _bit(p[5], 4)
    d["min"], d["max"] = _bit(p[5], 2), _bit(p[5], 1)
    n1, m1, u1 = _bit(p[5], 128), _bit(p[5], 64), _bit(p[5], 32)
    f = _bit(p[5], 16)
    M, k, R = _bit(p[6], 8), _bit(p[6], 4), _bit(p[6], 2)
    hz, A, dc = _bit(p[6], 1), _bit(p[6], 128), _bit(p[6], 64)
    m2, V = _bit(p[6], 32), _bit(p[6], 16)
    m3, u2 = _bit(p[7], 8), _bit(p[7], 4)
    d["manual"], d["auto"] = _bit(p[7], 2), _bit(p[7], 1)
    digs = _digits_from(p)
    point = _point_index(digs, 3)
    d["point"] = point
    big = _num_analyse(digs, point, 4)
    if big >= 0:
        if d["pol"]:
            big = -big
        d["data_big"] = f"{big:.{point}f}"
    elif big == -2:
        d["data_big"] = "AUTO"
        d["isAuto"] = 1
    elif big == -3:
        d["data_big"] = "EF"
        d["ncv"] = 1
    elif big == -1:
        d["data_big"] = "OL"
    elif big == -7:
        d["data_big"] = "-"
        d["ncv"] = 1
    elif big == -6:
        d["data_big"] = "--"
        d["ncv"] = 1
    elif big == -5:
        d["data_big"] = "---"
        d["ncv"] = 1
    elif big == -4:
        d["data_big"] = "----"
        d["ncv"] = 1
    for key, val in [("ac", ac), ("percent", percent), ("n1", n1), ("m1", m1), ("u1", u1),
                     ("f", f), ("M", M), ("k", k), ("R", R), ("hz", hz), ("A", A),
                     ("dc", dc), ("m2", m2), ("V", V), ("m3", m3), ("u2", u2)]:
        d[key] = val
    d["ncv"] = 0
    d["isAuto"] = 0
    d["acmv"] = d["acma"] = d["acv"] = d["aca"] = 0
    d["dcmv"] = d["dcma"] = d["dcv"] = d["dca"] = 0
    d["cap"] = d["diode_beep"] = d["res"] = 0
    if ac:
        d["gears"] = 0
        if (m2 or m3) and V:
            d["acmv"] = 1
        elif m2 or m3:
            d["acma"] = 1
        elif V:
            d["acv"] = 1
        else:
            d["aca"] = 1
    elif dc:
        d["gears"] = 1
        if (m2 or m3) and V:
            d["dcmv"] = 1
        elif m2 or m3:
            d["dcma"] = 1
        elif V:
            d["dcv"] = 1
        else:
            d["dca"] = 1
    elif d["beep"] and d["diode"]:
        d["gears"] = 6
        d["diode_beep"] = 1
    elif d["beep"]:
        d["gears"] = 4
    elif d["diode"]:
        d["gears"] = 5
    elif R:
        d["gears"] = 2
        d["res"] = 1
    elif f:
        d["gears"] = 3
        d["cap"] = 1
    else:
        d["gears"] = 7
    if d["gears"] != 7:
        d["ncv"] = 0
    if V:
        d["unit"] = 2 if m2 else 1
    elif R:
        d["unit"] = 10 if M else (9 if k else 8)
    elif f:
        d["unit"] = 11 if n1 else (12 if u1 else (13 if m1 else 14))
    elif hz:
        d["unit"] = 16 if M else (7 if k else 6)
    elif A:
        d["unit"] = 5 if u2 else (4 if m3 else 3)
    elif d["temp_c"]:
        d["unit"] = 20
    elif d["temp_f"]:
        d["unit"] = 21
    elif percent:
        d["unit"] = 22
    else:
        d["unit"] = 0
    return d


def _num_analyse_5566(digs, point, count, mode):
    """5566 模块自带的 c() —— 与其它子协议不同:无 AUTO/EF/dash 特殊码,
    未知段码直接 -1 (OL);mode=1 时若 digs[4] bit2&bit3 同时置位则万位 +10000。"""
    digs = list(digs) + [0] * 8
    val = 0
    for a in range(count):
        d = _num_index(digs[a])
        if d == -1:
            return -1
        val += d * (10 ** a)
    if mode and _bit(digs[4], 4) and _bit(digs[4], 8):
        val += 10000
    return val / (10 ** point)


def _tofixed(v, digits):
    """JS Number.toFixed 等价(数值场景),含 V8 远离零舍入。"""
    return _fmt_float(v, digits)


def usart_5566_resolve(p):
    """子协议 4 (帧: 5A A5 04 + 16B payload) — ZT-5566S 系列,小屏/大屏双显示。
    与其它子协议不同:数字段为原始字节 (bit4=小数点),非半字节拼装;
    解析用模块自带的简化 c()。"""
    d = {}
    d["manu"] = _bit(p[0], 2)
    d["auto"] = _bit(p[0], 4)
    d["l1_power"] = _bit(p[0], 8)
    d["rel"] = _bit(p[0], 16)
    d["beep"] = _bit(p[0], 32)
    d["diode"] = _bit(p[0], 64)
    d["vfc"] = _bit(p[0], 128)
    d["min"] = _bit(p[1], 1)
    d["max"] = _bit(p[1], 2)
    d["peak"] = _bit(p[1], 4)
    d["hold"] = _bit(p[1], 8)
    d["v"] = _bit(p[1], 16)
    d["k1_small"] = _bit(p[1], 32)
    d["hz1_small"] = _bit(p[1], 64)
    d["percent_small"] = _bit(p[1], 128)

    # --- 小屏 (slice p[2:], 4 位数字) ---
    ps = _point_index(p[2:], 3)
    d["pol2_small"] = _bit(p[5], 16)
    small = _num_analyse_5566(p[2:], ps, 4, 0)
    if d["pol2_small"]:
        small = -small
    d["data_small"] = _tofixed(small, ps)  # JS 无条件 toFixed

    # --- 大屏 (slice p[6:], 4 位 + 万位进位) ---
    pb = _point_index(p[6:], 4)
    d["point"] = pb
    d["pol1_big"] = _bit(p[10], 128)
    big = _num_analyse_5566(p[6:], pb, 4, 1)
    if big != -1:
        if d["pol1_big"]:
            big = -big
        d["data_big"] = _tofixed(big, pb)
    else:
        d["data_big"] = "OL"

    d["dc"] = _bit(p[10], 2)
    d["ac"] = _bit(p[10], 64)
    d["hz"] = _bit(p[13], 128)
    d["l4"] = _bit(p[13], 64)
    d["k2"] = _bit(p[13], 32)
    d["m1"] = _bit(p[13], 16)
    d["n"] = _bit(p[14], 8)
    d["m2"] = _bit(p[14], 4)
    d["u"] = _bit(p[14], 2)
    d["f"] = _bit(p[14], 1)
    d["a"] = _bit(p[15], 16)
    d["ncv"] = 0
    d["isAuto"] = 0
    d["acmv"] = d["acma"] = d["acv"] = d["aca"] = 0
    d["dcmv"] = d["dcma"] = d["dcv"] = d["dca"] = 0
    d["cap"] = d["diode_beep"] = d["res"] = 0
    ac, dc, V, f = d["ac"], d["dc"], d["v"], d["f"]
    m2, n, u, a = d["m2"], d["n"], d["u"], d["a"]
    if ac:
        d["gears"] = 0
        if m2 and V:
            d["acmv"] = 1
        elif m2:
            d["acma"] = 1
        elif V:
            d["acv"] = 1
        else:
            d["aca"] = 1
    elif dc:
        d["gears"] = 1
        if m2 and V:
            d["dcmv"] = 1
        elif m2:
            d["dcma"] = 1
        elif V:
            d["dcv"] = 1
        else:
            d["dca"] = 1
    elif d["beep"]:
        d["gears"] = 4
    elif d["diode"]:
        d["gears"] = 5
    elif d["l4"]:
        d["gears"] = 2
        d["res"] = 1
    elif f:
        d["gears"] = 3
        d["cap"] = 1
    else:
        d["gears"] = 7
    if V:
        d["unit"] = 17 if n else (18 if u else (2 if m2 else 1))
    elif d["l4"]:
        d["unit"] = 10 if d["m1"] else (9 if d["k2"] else 8)
    elif f:
        d["unit"] = 11 if n else (12 if u else (13 if m2 else 14))
    elif d["hz"]:
        d["unit"] = 16 if d["m1"] else (7 if d["k2"] else 6)
    elif a:
        d["unit"] = 19 if n else (5 if u else (4 if m2 else 3))
    else:
        d["unit"] = 0
    return d


def resolve_mult(data: bytes):
    """usartMultResolve: 5A A5 头 + 协议字节分发。返回 (protocol_name, parsed_dict) 或 None。"""
    if len(data) < 4 or data[0] != 0x5A or data[1] != 0xA5:
        return None
    pid = data[2]
    try:
        if pid == 4 and len(data) >= 19:
            return "5566", usart_5566_resolve(data[3:19])
        if pid == 3 and len(data) >= 11:
            return "300ab", usart_300ab_resolve(data[3:11])
        if pid == 1 and len(data) >= 10:
            return "qb5g", usart_qb5g_resolve(data[3:10])
        if pid == 2 and len(data) >= 10:
            return "s5g", usart_s5g_resolve(data[3:10])
    except IndexError:
        return None
    return None


def get_send_byte(cmd: int, code: int, extra: bytes = b"\x00\x00\x00\x00") -> bytes:
    """getSendByte: 万用表命令帧 AB CD [cmd] [code] [extra...] [SUM_HI] [SUM_LO]
    SUM 为前面所有字节按 16 位累加,大端放置。"""
    body = bytes([0xAB, 0xCD, cmd & 0xFF, code & 0xFF]) + extra
    total = sum(body) & 0xFFFF
    return body + bytes([(total >> 8) & 0xFF, total & 0xFF])
