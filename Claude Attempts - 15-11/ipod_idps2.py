"""
iPod Classic 6G (RepriseOS) - IDPS + auth + play/pause, WITH transaction IDs.

Last run showed StartIDPS itself returning bad-parameter. A command with no
parameters can't have a bad parameter - unless a required field is missing. On
the Classic's iAP, StartIDPS switches the link into transactional mode: from
StartIDPS onward every packet carries a 2-byte transaction ID placed right after
the command ID, before the payload, and the iPod echoes it. We weren't sending it.

This version:
  - sends a transaction ID on StartIDPS and everything after it (incrementing
    for each command we initiate),
  - echoes the iPod's transaction ID back on our auth replies,
  - strips the transaction ID when parsing inbound packets.

Command IDs, token framing and the transaction rule are from oandrew/ipod.

Run:
  uv run --with pyusb --with libusb ipod_idps2.py
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

G_ACK                           = 0x02
G_GetDevAuthenticationInfo      = 0x14
G_RetDevAuthenticationInfo      = 0x15
G_AckDevAuthenticationInfo      = 0x16
G_GetDevAuthenticationSignature = 0x17
G_RetDevAuthenticationSignature = 0x18
G_AckDevAuthenticationStatus    = 0x19
G_StartIDPS                     = 0x38
G_SetFIDTokenValues             = 0x39
G_RetFIDTokenValueACKs          = 0x3A
G_EndIDPS                       = 0x3B
G_IDPSStatus                    = 0x3C

ACK_STATUS = {0x00: "OK/SUCCESS", 0x02: "command failed", 0x04: "bad parameter",
              0x06: "pending", 0x07: "NOT AUTHENTICATED"}
ACC_LINGOES = [0x00, 0x02, 0x04]


def ck(payload):
    return (-(len(payload) + sum(payload))) & 0xFF


def pack(lingo, cmd, params=b"", trx=None):
    body = bytes([lingo, cmd])
    if trx is not None:
        body += trx.to_bytes(2, "big")
    body += bytes(params)
    return b"\x55" + bytes([len(body)]) + body + bytes([ck(body)])


def fid_token(ftype, fsubtype, body):
    tok = bytes([ftype, fsubtype]) + bytes(body)
    return bytes([len(tok)]) + tok


def set_fid_tokens():
    identify_body = (bytes([len(ACC_LINGOES)]) + bytes(ACC_LINGOES)
                     + (0).to_bytes(4, "big") + (0).to_bytes(4, "big"))
    acccaps_body = (0).to_bytes(8, "big")
    accname_body = bytes([0x01]) + b"Reprise\x00"
    tokens = (fid_token(0x00, 0x00, identify_body)
              + fid_token(0x00, 0x01, acccaps_body)
              + fid_token(0x00, 0x02, accname_body))
    return bytes([3]) + tokens


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
        self.trx_mode = False      # becomes True after we send StartIDPS

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
        print(f"  ->  {label:34} {pkt.hex(' ')}")

    def recv(self, timeout_s=1.5):
        """Return (lingo, cmd, trx, params). trx is None when not in transactional mode."""
        if self.ep_in is None:
            return None
        end = time.time() + timeout_s
        while time.time() < end:
            try:
                data = bytes(self.ep_in.read(self.ep_in.wMaxPacketSize, timeout=250))
            except usb.core.USBError:
                continue
            body = data[2:]
            if body[:1] == b"\x55":
                body = body[1:]
            if len(body) < 3:
                continue
            length = body[0]
            frame = body[1:1+length]
            if len(frame) < 2:
                continue
            lingo, cmd = frame[0], frame[1]
            rest = bytes(frame[2:])
            trx = None
            if self.trx_mode and lingo == 0x00:
                if len(rest) >= 2:
                    trx = int.from_bytes(rest[:2], "big")
                    rest = rest[2:]
            trxs = f" trx={trx:#06x}" if trx is not None else ""
            print(f"  <-  lingo 0x{lingo:02x} cmd 0x{cmd:02x}{trxs}            {bytes(frame).hex(' ')}")
            return lingo, cmd, trx, rest
        return None


def run():
    link = Link()
    print("Connected.\n--- IDPS identify (transactional) ---")
    our_trx = 0

    link.send(pack(0x00, G_StartIDPS, trx=our_trx), "StartIDPS")
    link.trx_mode = True
    link.recv(1.2)
    our_trx += 1

    link.send(pack(0x00, G_SetFIDTokenValues, set_fid_tokens(), trx=our_trx), "SetFIDTokenValues")
    link.recv(1.5)
    our_trx += 1

    link.send(pack(0x00, G_EndIDPS, bytes([0x00]), trx=our_trx), "EndIDPS(Continue)")
    our_trx += 1

    print("--- authentication (iPod-driven) ---")
    authed = False
    deadline = time.time() + 10
    while time.time() < deadline and not authed:
        msg = link.recv(1.5)
        if msg is None:
            continue
        lingo, cmd, trx, params = msg
        if lingo != 0x00:
            continue
        echo = trx if trx is not None else 0
        if cmd == G_IDPSStatus:
            st = params[0] if params else 0xFF
            print(f"      IDPS status 0x{st:02x} ({ACK_STATUS.get(st,'?')})")
        elif cmd == G_GetDevAuthenticationInfo:
            link.send(pack(0x00, G_RetDevAuthenticationInfo,
                           bytes([0x02, 0x00, 0x00, 0x00]) + b"\x00" * 16, trx=echo),
                      "RetDevAuthenticationInfo")
        elif cmd == G_AckDevAuthenticationInfo:
            st = params[0] if params else 0xFF
            print(f"      auth-info ack 0x{st:02x} ({ACK_STATUS.get(st,'?')})")
        elif cmd == G_GetDevAuthenticationSignature:
            link.send(pack(0x00, G_RetDevAuthenticationSignature, b"\x00" * 20, trx=echo),
                      "RetDevAuthenticationSignature")
        elif cmd == G_AckDevAuthenticationStatus:
            st = params[0] if params else 0xFF
            print(f"      AUTH STATUS 0x{st:02x} ({ACK_STATUS.get(st,'?')})")
            authed = (st == 0x00)
        elif cmd == G_ACK:
            st = params[0] if params else 0xFF
            acked = params[1] if len(params) > 1 else 0xFF
            print(f"      ack 0x{st:02x} for cmd 0x{acked:02x}")

    print("--- play/pause ---")
    # After IDPS the link is transactional; send Simple Remote with a transaction,
    # and if that's rejected, retry once without (Simple Remote is sometimes exempt).
    for use_trx in (our_trx, None):
        tag = "with trx" if use_trx is not None else "no trx"
        link.send(pack(0x02, 0x00, (0x01).to_bytes(4, "little"), trx=use_trx), f"play/pause DOWN ({tag})")
        link.recv(0.9)
        link.send(pack(0x02, 0x00, (0x00).to_bytes(4, "little"), trx=use_trx), f"release ({tag})")
        link.recv(0.7)
        if use_trx is not None:
            our_trx += 1

    print()
    print("=" * 60)
    if authed:
        print("  AUTHENTICATED. If the music toggled, USB control is live.")
    else:
        print("  Not authenticated - see transcript for the last answered step.")
    print("=" * 60)


if __name__ == "__main__":
    run()
