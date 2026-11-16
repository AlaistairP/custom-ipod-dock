"""
iPod Classic 6G (RepriseOS) - LISTEN FIRST diagnostic.

Every previous script spoke first. But an iPod usually opens the conversation:
on USB attach it sends the accessory a RequestIdentify, and until the accessory
answers THAT, it rejects everything else as out-of-sequence - which matches the
blanket rejections we've seen. So this script does almost nothing but listen, and
only answers what the iPod actually asks:

  1. set the accessory config, then just read for a few seconds and log whatever
     the iPod sends on its own,
  2. if it sends RequestIdentify (0x00/0x00), answer with IdentifyDeviceLingoes,
  3. if it then drives authentication, answer with placeholders,
  4. log every byte both directions. No assumptions about IDPS or transactions.

Run:
  uv run --with pyusb --with libusb ipod_listen.py
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
ACC_LINGOES = [0x00, 0x02, 0x04]

NAMES = {
    0x00: "RequestIdentify", 0x02: "ACK", 0x13: "IdentifyDeviceLingoes",
    0x14: "GetDevAuthenticationInfo", 0x15: "RetDevAuthenticationInfo",
    0x16: "AckDevAuthenticationInfo", 0x17: "GetDevAuthenticationSignature",
    0x18: "RetDevAuthenticationSignature", 0x19: "AckDevAuthenticationStatus",
    0x27: "GetAccessoryInfo", 0x38: "StartIDPS", 0x3A: "RetFIDTokenValueACKs",
    0x3C: "IDPSStatus",
}


def ck(payload):
    return (-(len(payload) + sum(payload))) & 0xFF


def pack(lingo, cmd, params=b""):
    body = bytes([lingo, cmd]) + bytes(params)
    return b"\x55" + bytes([len(body)]) + body + bytes([ck(body)])


def identify_pkt():
    mask = 0
    for l in ACC_LINGOES:
        mask |= (1 << l)
    return pack(0x00, 0x13, mask.to_bytes(4, "big") + (0).to_bytes(4, "big") + (0).to_bytes(4, "big"))


class Link:
    def __init__(self):
        dev = usb.core.find(idVendor=APPLE_VID, backend=BACKEND)
        if dev is None:
            sys.exit("No Apple USB device found (Zadig driver swap in place?).")
        cfg_val = iface = None
        for cfg in dev:
            for intf in cfg:
                if intf.bInterfaceClass == 0x03:
                    cfg_val, iface = cfg.bConfigurationValue, intf.bInterfaceNumber
        if cfg_val is None:
            sys.exit("No HID/iAP interface on this iPod.")
        dev.set_configuration(cfg_val)
        time.sleep(0.4)
        rdesc = dev.ctrl_transfer(0x81, 0x06, 0x2200, iface, 1024)
        self.outputs = self._outputs(rdesc)
        intf = dev.get_active_configuration()[(iface, 0)]
        self.ep_in = usb.util.find_descriptor(
            intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN)
        self.dev, self.iface = dev, iface

    @staticmethod
    def _outputs(desc):
        out, rid, size, count, i = {}, 0, 0, 0, 0
        while i < len(desc):
            p = desc[i]; n = [0, 1, 2, 4][p & 0x03]
            tag = p & 0xFC; data = int.from_bytes(bytes(desc[i+1:i+1+n]), "little")
            if tag == 0x84: rid = data
            elif tag == 0x74: size = data
            elif tag == 0x94: count = data
            elif tag == 0x90: out[rid] = out.get(rid, 0) + size*count//8
            i += 1 + n
        return out

    def send(self, pkt, label=""):
        need = 1 + len(pkt)
        size, rid = min((s, r) for r, s in self.outputs.items() if s >= need)
        report = bytes([rid, 0x00]) + pkt
        report += b"\x00" * (size + 1 - len(report))
        self.dev.ctrl_transfer(0x21, 0x09, 0x0200 | rid, self.iface, report)
        print(f"  ->  {label:30} {pkt.hex(' ')}")

    def read_raw(self, timeout_ms=400):
        if self.ep_in is None:
            return None
        try:
            return bytes(self.ep_in.read(self.ep_in.wMaxPacketSize, timeout=timeout_ms))
        except usb.core.USBError:
            return None

    @staticmethod
    def parse(data):
        body = data[2:]
        if body[:1] == b"\x55":
            body = body[1:]
        if len(body) < 2:
            return None
        length = body[0]
        frame = bytes(body[1:1+length])
        if len(frame) < 2:
            return None
        return frame[0], frame[1], frame[2:], frame


def run():
    link = Link()
    print("Config set. Listening for the iPod to speak first...\n")

    identified = False
    end = time.time() + 12
    while time.time() < end:
        data = link.read_raw(500)
        if data is None:
            continue
        p = link.parse(data)
        if p is None:
            print(f"  <-  (raw) {data.hex(' ')}")
            continue
        lingo, cmd, params, frame = p
        name = NAMES.get(cmd, "?") if lingo == 0x00 else f"lingo{lingo}"
        print(f"  <-  lingo 0x{lingo:02x} cmd 0x{cmd:02x} {name:28} {frame.hex(' ')}")

        if lingo == 0x00 and cmd == 0x00:  # RequestIdentify
            link.send(identify_pkt(), "IdentifyDeviceLingoes")
            identified = True
        elif lingo == 0x00 and cmd == 0x14:  # GetDevAuthenticationInfo
            link.send(pack(0x00, 0x15, bytes([0x02, 0x00, 0x00, 0x00]) + b"\x00" * 16),
                      "RetDevAuthenticationInfo")
        elif lingo == 0x00 and cmd == 0x17:  # GetDevAuthenticationSignature
            link.send(pack(0x00, 0x18, b"\x00" * 20), "RetDevAuthenticationSignature")
        elif lingo == 0x00 and cmd == 0x19:  # AckDevAuthenticationStatus
            st = params[0] if params else 0xFF
            print(f"      AUTH STATUS 0x{st:02x}")

    if not identified:
        print("\nThe iPod sent no RequestIdentify on its own. Sending one IdentifyDeviceLingoes")
        print("to see how it answers when we open:")
        link.send(identify_pkt(), "IdentifyDeviceLingoes")
        t = time.time() + 3
        while time.time() < t:
            data = link.read_raw(500)
            if data is None:
                continue
            p = link.parse(data)
            if p:
                lingo, cmd, params, frame = p
                print(f"  <-  lingo 0x{lingo:02x} cmd 0x{cmd:02x}   {frame.hex(' ')}")

    print("\n--- done. Paste everything above. ---")


if __name__ == "__main__":
    run()
