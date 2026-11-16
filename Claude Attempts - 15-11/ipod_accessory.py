"""
iPod Classic 6G (RepriseOS) - USB accessory that authenticates, then plays/pauses.

Why this version is different from the earlier ones:
RepriseOS stubs the firmware's signature verifier (IAP_VerifyDeviceSignatureV1/V2)
to return success, so any accessory authenticates WITHOUT a Made-for-iPod chip.
But the iPod only starts the auth handshake after an accessory identifies and says
it will authenticate - and it is the iPod that drives the handshake. So this script
identifies, then reacts to each General-Lingo request the iPod sends, answering the
auth challenge with placeholder bytes (which RepriseOS accepts). Then it sends a
Simple Remote play/pause.

It prints every packet both ways and ends with a clear verdict. If it stops partway,
the transcript shows exactly which step the firmware is waiting on.

Run:
  uv run --with pyusb --with libusb ipod_accessory.py
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

# ---- General Lingo (0x00) command IDs ----
G_RequestIdentify              = 0x00
G_ACK                          = 0x02
G_IdentifyDeviceLingoes        = 0x13
G_GetDevAuthenticationInfo     = 0x14
G_RetDevAuthenticationInfo     = 0x15
G_AckDevAuthenticationInfo     = 0x16
G_GetDevAuthenticationSignature= 0x17
G_RetDevAuthenticationSignature= 0x18
G_AckDevAuthenticationStatus   = 0x19
G_StartIDPS                    = 0x38
G_SetFIDTokenValues            = 0x39
G_RetFIDTokenValueACKs         = 0x3A
G_EndIDPS                      = 0x3B
G_IDPSStatus                   = 0x3C

ACK_STATUS = {
    0x00: "SUCCESS", 0x02: "command failed", 0x04: "bad parameter",
    0x06: "pending", 0x07: "NOT AUTHENTICATED",
}

# Lingoes we claim: General(0) + SimpleRemote(2) + Extended(4) = 0x15
LINGO_MASK = (1 << 0) | (1 << 2) | (1 << 4)


def checksum(payload):
    return (-(len(payload) + sum(payload))) & 0xFF


def pack(lingo, cmd, params=b""):
    body = bytes([lingo, cmd]) + bytes(params)
    return b"\x55" + bytes([len(body)]) + body + bytes([checksum(body)])


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
        print(f"  ->  {label:38} {pkt.hex(' ')}")

    def recv(self, timeout_s=1.2):
        """Return (lingo, cmd, params) of one inbound iAP packet, or None."""
        if self.ep_in is None:
            return None
        end = time.time() + timeout_s
        while time.time() < end:
            try:
                data = bytes(self.ep_in.read(self.ep_in.wMaxPacketSize, timeout=250))
            except usb.core.USBError:
                continue
            body = data[2:]                      # strip report id + link byte
            if body[:1] == b"\x55":
                body = body[1:]
            if len(body) < 3:
                continue
            length = body[0]
            frame = body[1:1+length]
            if len(frame) < 2:
                continue
            lingo, cmd, params = frame[0], frame[1], frame[2:]
            print(f"  <-  lingo 0x{lingo:02x} cmd 0x{cmd:02x}                   {bytes(frame).hex(' ')}")
            return lingo, cmd, bytes(params)
        return None


def run():
    link = Link()
    print("Connected to iPod USB accessory interface.\n--- handshake ---")

    authed = False
    info_sent = False

    # Kick off: declare our lingoes. Try the classic IdentifyDeviceLingoes first;
    # params = lingo bitmask (BE) + options (BE, bit1 = will authenticate) + device id.
    options = 0x00000002  # bit1: accessory will authenticate
    link.send(pack(0x00, G_IdentifyDeviceLingoes,
                   LINGO_MASK.to_bytes(4, "big") + options.to_bytes(4, "big") + (0).to_bytes(4, "big")),
              "IdentifyDeviceLingoes(0,2,4;auth)")

    deadline = time.time() + 8
    while time.time() < deadline and not authed:
        msg = link.recv(1.2)
        if msg is None:
            # Nothing pending. If we identified but the iPod hasn't asked for auth
            # info yet, offer it once unsolicited (some flows expect that).
            if not info_sent:
                link.send(pack(0x00, G_RetDevAuthenticationInfo,
                               bytes([0x02, 0x00, 0x00, 0x00]) + b"\x00" * 16),
                          "RetDevAuthenticationInfo(2.0)*")
                info_sent = True
                continue
            break

        lingo, cmd, params = msg
        if lingo != 0x00:
            continue  # ignore non-general chatter during handshake

        if cmd == G_RequestIdentify:
            link.send(pack(0x00, G_IdentifyDeviceLingoes,
                           LINGO_MASK.to_bytes(4, "big") + options.to_bytes(4, "big") + (0).to_bytes(4, "big")),
                      "IdentifyDeviceLingoes (re-id)")
        elif cmd == G_GetDevAuthenticationInfo:
            # iPod wants our auth version + certificate. Placeholder cert; RepriseOS
            # ignores the signature later, but answer with a plausible 2.0 single section.
            link.send(pack(0x00, G_RetDevAuthenticationInfo,
                           bytes([0x02, 0x00, 0x00, 0x00]) + b"\x00" * 16),
                      "RetDevAuthenticationInfo(2.0)")
            info_sent = True
        elif cmd == G_AckDevAuthenticationInfo:
            st = params[0] if params else 0xFF
            print(f"      info ack status 0x{st:02x} ({ACK_STATUS.get(st,'?')})")
        elif cmd == G_GetDevAuthenticationSignature:
            # iPod sent a challenge; sign it. Content is irrelevant on RepriseOS.
            link.send(pack(0x00, G_RetDevAuthenticationSignature, b"\x00" * 20),
                      "RetDevAuthenticationSignature")
        elif cmd == G_AckDevAuthenticationStatus:
            st = params[0] if params else 0xFF
            print(f"      AUTH STATUS 0x{st:02x} ({ACK_STATUS.get(st,'?')})")
            authed = (st == 0x00)
        elif cmd == G_ACK:
            st = params[0] if params else 0xFF
            acked = params[1] if len(params) > 1 else 0xFF
            print(f"      ack status 0x{st:02x} for cmd 0x{acked:02x}")
            if st == 0x00 and acked == G_IdentifyDeviceLingoes:
                pass  # identify accepted; wait for auth requests

    print("--- result ---")
    if not authed:
        print("Authentication did not complete. Transcript above shows the last step")
        print("the iPod answered; that's what to adjust. Paste it back.")
        # still try a button in case this firmware gates nothing
    else:
        print("Authenticated. Sending play/pause...")

    # Simple Remote play/pause (bit 0), 4-byte state, press + release.
    link.send(pack(0x02, 0x00, (0x01).to_bytes(4, "little")), "SimpleRemote play/pause DOWN")
    st = link.recv(1.0)
    link.send(pack(0x02, 0x00, (0x00).to_bytes(4, "little")), "SimpleRemote release")
    link.recv(0.8)

    print()
    print("=" * 60)
    if authed:
        print("  Handshake OK. If the music toggled, USB control works and")
        print("  we can add next/prev/track-info next.")
    else:
        print("  Not authenticated yet - see transcript. The play/pause above")
        print("  was a long shot without auth; the handshake is the real fix.")
    print("=" * 60)


if __name__ == "__main__":
    run()
