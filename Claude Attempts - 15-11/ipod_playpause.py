"""
iPod Classic - Simple Remote play/pause over USB.

Simple Remote (lingo 0x02) is the button-press command set Apple leaves open to
unauthenticated accessories. The earlier test proved the iPod answers in this
lingo but rejected our button packet with status 0x04 (bad parameter), which is
a payload-shape problem, not an auth wall. This script cycles play/pause through
the payload widths different firmware expects, with and without an identify
step, and prints clearly which variant (if any) the iPod accepts.

Run:
  uv run --with pyusb --with libusb ipod_playpause.py

Success = the iPod returns a Simple Remote ACK with status 0x00 for a button
press, and (you'll see it) playback toggles on the device.
"""

import sys
import time

import usb.core
import usb.util

try:
    import libusb
    import usb.backend.libusb1 as libusb1
    BACKEND = libusb1.get_backend(find_library=lambda x: libusb.dll._name)
except Exception:
    BACKEND = None

APPLE_VID = 0x05AC
PLAYPAUSE_BIT = 0x01          # Simple Remote play/pause button
ACK_STATUS = {
    0x00: "SUCCESS", 0x01: "unknown db", 0x02: "command failed",
    0x03: "out of resources", 0x04: "bad parameter", 0x05: "unknown id",
    0x06: "pending", 0x07: "NOT AUTHENTICATED", 0x10: "unavailable in this mode",
}


def iap(lingo, cmd, params=b""):
    body = bytes([lingo, cmd]) + bytes(params)
    length = len(body)
    chk = (-(length + sum(body))) & 0xFF
    return b"\x55" + bytes([length]) + body + bytes([chk])


def connect():
    dev = usb.core.find(idVendor=APPLE_VID, backend=BACKEND)
    if dev is None:
        sys.exit("No Apple USB device found (did the Zadig driver swap stick?).")
    # find HID interface + its config
    cfg_val = iface = None
    for cfg in dev:
        for intf in cfg:
            if intf.bInterfaceClass == 0x03:
                cfg_val, iface = cfg.bConfigurationValue, intf.bInterfaceNumber
    if cfg_val is None:
        sys.exit("No HID/iAP interface found on this iPod.")
    dev.set_configuration(cfg_val)
    time.sleep(0.4)
    rdesc = dev.ctrl_transfer(0x81, 0x06, 0x2200, iface, 1024)
    outputs = _output_reports(rdesc)
    intf = dev.get_active_configuration()[(iface, 0)]
    ep_in = usb.util.find_descriptor(
        intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN)
    return dev, iface, outputs, ep_in


def _output_reports(desc):
    out, rid, size, count = {}, 0, 0, 0
    i = 0
    while i < len(desc):
        p = desc[i]
        n = [0, 1, 2, 4][p & 0x03]
        tag, data = p & 0xFC, int.from_bytes(bytes(desc[i + 1:i + 1 + n]), "little")
        if tag == 0x84: rid = data
        elif tag == 0x74: size = data
        elif tag == 0x94: count = data
        elif tag == 0x90: out[rid] = out.get(rid, 0) + size * count // 8
        i += 1 + n
    return out


def send(dev, iface, outputs, pkt):
    need = 1 + len(pkt)                       # link byte + packet
    size, rid = min((s, r) for r, s in outputs.items() if s >= need)
    report = bytes([rid, 0x00]) + pkt
    report += b"\x00" * (size + 1 - len(report))
    dev.ctrl_transfer(0x21, 0x09, 0x0200 | rid, iface, report)


def read_status(ep_in, timeout_s=1.0):
    """Return the status byte of a Simple Remote ACK (lingo 0x02, cmd 0x01), or None."""
    if ep_in is None:
        return None
    end = time.time() + timeout_s
    while time.time() < end:
        try:
            data = bytes(ep_in.read(ep_in.wMaxPacketSize, timeout=250))
        except usb.core.USBError:
            continue
        body = data[2:]
        if body[:1] == b"\x55":
            body = body[1:]
        if len(body) >= 5 and body[1] == 0x02 and body[2] == 0x01:
            return body[3]
    return None


def press(dev, iface, outputs, ep_in, width):
    """Send play/pause down+up with an N-byte button field. Return status byte or None."""
    down = PLAYPAUSE_BIT.to_bytes(width, "little")
    up = (0).to_bytes(width, "little")
    send(dev, iface, outputs, iap(0x02, 0x00, down))
    time.sleep(0.12)
    st = read_status(ep_in, 0.8)
    send(dev, iface, outputs, iap(0x02, 0x00, up))
    time.sleep(0.12)
    read_status(ep_in, 0.5)
    return st


def main():
    dev, iface, outputs, ep_in = connect()
    print(f"Connected. HID iface {iface}. Trying Simple Remote play/pause variants...\n")

    winner = None
    for identify in (False, True):
        if identify:
            # SimpleRemote identify: GeneralLingo RequestIdentify is iPod->acc, so
            # instead send the Simple-Remote-era ContextButtonStatus "null" to wake it
            send(dev, iface, outputs, iap(0x00, 0x01, b"\x02"))  # legacy Identify as remote
            time.sleep(0.2)
        for width in (1, 2, 4):
            st = press(dev, iface, outputs, ep_in, width)
            tag = f"identify={'yes' if identify else 'no':3}  button field={width} byte(s)"
            if st is None:
                print(f"  {tag}: no ACK")
            else:
                label = ACK_STATUS.get(st, f"0x{st:02x}")
                print(f"  {tag}: status 0x{st:02x} ({label})")
                if st == 0x00 and winner is None:
                    winner = (identify, width)
            time.sleep(0.3)

    print()
    if winner:
        print("=" * 56)
        print(f"  IT WORKED.  The iPod accepted play/pause.")
        print(f"  Winning variant: identify={winner[0]}, button field={winner[1]} byte(s).")
        print(f"  Playback should have toggled. That's your command path.")
        print("=" * 56)
    else:
        print("=" * 56)
        print("  No variant was accepted (no 0x00 success ACK).")
        print("  If every line said 0x04 bad parameter, the button")
        print("  encoding is still off. If you saw 0x07, this firmware")
        print("  still enforces auth on Simple Remote. Paste me the output.")
        print("=" * 56)


if __name__ == "__main__":
    main()
