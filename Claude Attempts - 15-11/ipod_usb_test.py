"""
iPod Classic USB iAP test (Windows, via libusb).

Switches the iPod to its "iPod USB Interface" configuration, finds the HID
interface, sends an iAP identify, then a Simple Remote play/pause press and
release, and prints whatever the iPod sends back.

Needs: pip install pyusb libusb
and the iPod's driver swapped to libusb-win32 or libusbK with Zadig first.

Usage:
  python ipod_usb_test.py               # identify + play/pause
  python ipod_usb_test.py --cmd next    # next track
  python ipod_usb_test.py --no-sync     # leave out the 0x55 byte inside the HID report
  python ipod_usb_test.py --descriptor  # just dump configs and the HID report descriptor
"""

import argparse
import sys
import time

import usb.core
import usb.util

try:
    import libusb  # bundles libusb-1.0.dll on Windows
    import usb.backend.libusb1 as libusb1
    BACKEND = libusb1.get_backend(find_library=lambda x: libusb.dll._name)
except Exception:
    BACKEND = None  # let pyusb find whatever is installed

APPLE_VID = 0x05AC

# Simple Remote (lingo 0x02) button bitmask for ContextButtonStatus (cmd 0x00)
BUTTONS = {
    "playpause": 0x01,
    "volup": 0x02,
    "voldown": 0x04,
    "next": 0x08,
    "prev": 0x10,
    "nextalbum": 0x20,
    "prevalbum": 0x40,
    "stop": 0x80,
}

ACK_STATUS = {
    0x00: "Success",
    0x01: "Unknown database category",
    0x02: "Command failed",
    0x03: "Out of resources",
    0x04: "Bad parameter",
    0x05: "Unknown ID",
    0x06: "Command pending",
    0x07: "NOT AUTHENTICATED  <-- auth wall is up",
    0x08: "Bad authentication version",
    0x0A: "Certificate invalid",
    0x0B: "Certificate permissions invalid",
    0x11: "Invalid accessory resistor value",
}


def iap_packet(lingo, cmd, params=b"", sync=True):
    body = bytes([lingo, cmd]) + bytes(params)
    length = len(body)
    if length > 0xFF:
        raise ValueError("large packets not supported in this test")
    checksum = (-(length + sum(body))) & 0xFF
    pkt = bytes([length]) + body + bytes([checksum])
    return (b"\x55" + pkt) if sync else pkt


def parse_report_descriptor(desc):
    """Minimal HID descriptor walk: returns {report_id: byte_len} for outputs and inputs."""
    outputs, inputs = {}, {}
    report_id, report_size, report_count = 0, 0, 0
    i = 0
    while i < len(desc):
        prefix = desc[i]
        if prefix == 0xFE:  # long item
            i += 3 + desc[i + 1]
            continue
        size = [0, 1, 2, 4][prefix & 0x03]
        tag = prefix & 0xFC
        data = int.from_bytes(bytes(desc[i + 1:i + 1 + size]), "little")
        if tag == 0x84:
            report_id = data
        elif tag == 0x74:
            report_size = data
        elif tag == 0x94:
            report_count = data
        elif tag == 0x90:  # Output
            outputs[report_id] = outputs.get(report_id, 0) + report_size * report_count // 8
        elif tag == 0x80:  # Input
            inputs[report_id] = inputs.get(report_id, 0) + report_size * report_count // 8
        i += 1 + size
    return outputs, inputs


def find_ipod():
    dev = usb.core.find(idVendor=APPLE_VID, backend=BACKEND)
    if dev is None:
        sys.exit("No Apple USB device found. Is the driver swapped with Zadig? (see notes)")
    print(f"Found {dev.idVendor:04x}:{dev.idProduct:04x}")
    return dev


def find_hid_config(dev):
    for cfg in dev:
        for intf in cfg:
            if intf.bInterfaceClass == 0x03:
                return cfg.bConfigurationValue, intf.bInterfaceNumber
    return None, None


def dump(dev):
    for cfg in dev:
        name = ""
        try:
            name = usb.util.get_string(dev, cfg.iConfiguration) if cfg.iConfiguration else ""
        except Exception:
            pass
        print(f"Config {cfg.bConfigurationValue}: {name}")
        for intf in cfg:
            print(f"  iface {intf.bInterfaceNumber} alt {intf.bAlternateSetting} class 0x{intf.bInterfaceClass:02x}")
            for ep in intf:
                print(f"    ep 0x{ep.bEndpointAddress:02x} attr {ep.bmAttributes} maxpkt {ep.wMaxPacketSize}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--cmd", default="playpause", choices=BUTTONS.keys())
    ap.add_argument("--no-sync", action="store_true", help="omit 0x55 inside HID reports")
    ap.add_argument("--descriptor", action="store_true", help="only dump descriptors")
    args = ap.parse_args()
    sync = not args.no_sync

    dev = find_ipod()
    dump(dev)

    cfg_val, iface = find_hid_config(dev)
    if cfg_val is None:
        sys.exit("No HID interface in any configuration; this iPod/firmware doesn't expose iAP over USB.")
    print(f"\nHID iAP interface: config {cfg_val}, interface {iface}")

    try:
        dev.set_configuration(cfg_val)
    except usb.core.USBError as e:
        sys.exit(f"set_configuration({cfg_val}) failed: {e}\n"
                 "If you used WinUSB in Zadig, reinstall with libusb-win32 or libusbK instead.")
    time.sleep(0.5)

    # HID report descriptor
    rdesc = dev.ctrl_transfer(0x81, 0x06, 0x2200, iface, 1024)
    outputs, inputs = parse_report_descriptor(rdesc)
    print(f"Output reports (id: bytes): {outputs}")
    print(f"Input reports  (id: bytes): {inputs}")
    if args.descriptor:
        print("Raw report descriptor:", bytes(rdesc).hex(" "))
        return

    try:
        usb.util.claim_interface(dev, iface)
    except usb.core.USBError as e:
        print(f"claim_interface warning: {e}")

    intf = dev.get_active_configuration()[(iface, 0)]
    ep_in = usb.util.find_descriptor(intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_IN)
    ep_out = usb.util.find_descriptor(intf, custom_match=lambda e: usb.util.endpoint_direction(e.bEndpointAddress) == usb.util.ENDPOINT_OUT)

    def send(pkt, label):
        need = 1 + len(pkt)  # link-control byte + packet
        fits = sorted((size, rid) for rid, size in outputs.items() if size >= need)
        if not fits:
            sys.exit(f"No output report big enough for {need} bytes")
        size, rid = fits[0]
        report = bytes([rid, 0x00]) + pkt
        report += b"\x00" * (size + 1 - len(report))
        print(f"-> {label}: report {rid} [{report.hex(' ')}]")
        if ep_out is not None:
            ep_out.write(report)
        else:
            # SET_REPORT, output type
            dev.ctrl_transfer(0x21, 0x09, 0x0200 | rid, iface, report)

    def read_all(timeout_s=1.5):
        if ep_in is None:
            print("   (no IN endpoint to read from)")
            return
        end = time.time() + timeout_s
        while time.time() < end:
            try:
                data = bytes(ep_in.read(ep_in.wMaxPacketSize, timeout=300))
            except usb.core.USBTimeoutError:
                continue
            except usb.core.USBError as e:
                print(f"   read error: {e}")
                return
            print(f"<- [{data.hex(' ')}]")
            decode(data)

    def decode(data):
        # skip report id + link byte, find the iAP packet
        body = data[2:]
        if body[:1] == b"\x55":
            body = body[1:]
        if len(body) < 3:
            return
        lingo, cmd = body[1], body[2]
        if lingo == 0x00 and cmd == 0x02 and len(body) >= 5:
            status = body[3]
            print(f"   ACK for cmd 0x{body[4]:02x}: 0x{status:02x} {ACK_STATUS.get(status, '?')}")
        elif lingo == 0x00 and cmd == 0x00:
            print("   iPod sent RequestIdentify")
        else:
            print(f"   lingo 0x{lingo:02x} cmd 0x{cmd:02x}")

    # 1. Identify as a Simple Remote accessory (legacy Identify, lingo 0 cmd 0x01)
    send(iap_packet(0x00, 0x01, b"\x02", sync), "Identify (Simple Remote)")
    read_all()

    # 2. IdentifyDeviceLingoes: lingoes 0 + 2, no auth options, device id 0
    params = (0x00000005).to_bytes(4, "big") + (0).to_bytes(4, "big") + (0).to_bytes(4, "big")
    send(iap_packet(0x00, 0x13, params, sync), "IdentifyDeviceLingoes (0,2; no auth)")
    read_all()

    # 3. Button press + release
    mask = BUTTONS[args.cmd]
    send(iap_packet(0x02, 0x00, bytes([mask]), sync), f"Button down: {args.cmd}")
    time.sleep(0.15)
    send(iap_packet(0x02, 0x00, b"\x00", sync), "Button up")
    read_all(2.0)

    usb.util.release_interface(dev, iface)
    print("\nDone. If the track toggled, you're in. If you saw status 0x07, auth is still enforced.")


if __name__ == "__main__":
    main()
