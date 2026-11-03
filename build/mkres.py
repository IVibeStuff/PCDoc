"""Build a Win32 .res file: application manifest (admin prompt), icon group and version info.
Used because the Mono C# compiler takes these via -win32res."""
import struct, sys

VERSION = tuple(int(x) for x in sys.argv[1].split('.')) if len(sys.argv) > 1 else (0, 2, 0, 0)
VERSION = (VERSION + (0, 0, 0, 0))[:4]
VSTR = '.'.join(str(v) for v in VERSION[:3])


def pad4(b):
    return b + b'\0' * ((4 - len(b) % 4) % 4)


def res_entry(rtype, rid, data, lang=0x0409, flags=0x1030):
    hdr = struct.pack('<HH', 0xFFFF, rtype) + struct.pack('<HH', 0xFFFF, rid)
    hdr = pad4(hdr)
    hdr += struct.pack('<IHHII', 0, flags, lang, 0, 0)
    header = struct.pack('<II', len(data), 8 + len(hdr)) + hdr
    return header + pad4(data)


MANIFEST = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <assemblyIdentity version="{'.'.join(str(v) for v in VERSION)}" name="PCAudit.App" type="win32"/>
  <description>PC Audit - read-only PC health and driver scan</description>
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
    <security><requestedPrivileges xmlns="urn:schemas-microsoft-com:asm.v3">
      <requestedExecutionLevel level="requireAdministrator" uiAccess="false"/>
    </requestedPrivileges></security>
  </trustInfo>
  <compatibility xmlns="urn:schemas-microsoft-com:compatibility.v1">
    <application><supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}"/></application>
  </compatibility>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <dpiAware xmlns="http://schemas.microsoft.com/SMI/2005/WindowsSettings">true</dpiAware>
    </windowsSettings>
  </application>
  <dependency><dependentAssembly>
    <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
  </dependentAssembly></dependency>
</assembly>
'''.encode('utf-8')


def icon_resources(path):
    d = open(path, 'rb').read()
    _, typ, count = struct.unpack_from('<HHH', d, 0)
    assert typ == 1
    icons, grp = [], struct.pack('<HHH', 0, 1, count)
    for i in range(count):
        w, h, colors, res, planes, bpp, size, off = struct.unpack_from('<BBBBHHII', d, 6 + 16 * i)
        icons.append(res_entry(3, i + 1, d[off:off + size]))
        grp += struct.pack('<BBBBHHIH', w, h, colors, res, planes, bpp, size, i + 1)
    return b''.join(icons) + res_entry(14, 1, grp)


def vblock(key, value=b'', vlen=0, vtype=0, children=b''):
    k = (key + '\0').encode('utf-16-le')
    body = struct.pack('<HHH', 0, vlen, vtype) + k
    body = pad4(body) + value
    if children:
        body = pad4(body) + children
    return struct.pack('<H', len(body)) + body[2:]


def vstring(key, val):
    v = (val + '\0').encode('utf-16-le')
    return pad4(vblock(key, v, len(val) + 1, 1))


def version_info():
    ms = (VERSION[0] << 16) | VERSION[1]
    ls = (VERSION[2] << 16) | VERSION[3]
    fixed = struct.pack('<13I', 0xFEEF04BD, 0x00010000, ms, ls, ms, ls, 0x3F, 0, 0x40004, 1, 0, 0, 0)
    strings = b''.join(vstring(k, v) for k, v in [
        ('CompanyName', 'PC Audit'), ('FileDescription', 'PC Audit - PC health, driver and update scan'),
        ('FileVersion', VSTR), ('InternalName', 'PCAudit'), ('LegalCopyright', 'Free to use'),
        ('OriginalFilename', 'PCAudit.exe'), ('ProductName', 'PC Audit'), ('ProductVersion', VSTR)])
    table = pad4(vblock('040904B0', b'', 0, 1, strings))
    sfi = pad4(vblock('StringFileInfo', b'', 0, 1, table))
    var = pad4(vblock('Translation', struct.pack('<HH', 0x0409, 0x04B0), 4, 0))
    vfi = pad4(vblock('VarFileInfo', b'', 0, 1, var))
    return vblock('VS_VERSION_INFO', fixed, len(fixed), 0, sfi + vfi)


out = b'\0\0\0\0\x20\0\0\0\xff\xff\0\0\xff\xff\0\0' + b'\0' * 16  # empty leading entry
out += res_entry(24, 1, MANIFEST)
out += icon_resources(sys.argv[2] if len(sys.argv) > 2 else 'app.ico')
out += res_entry(16, 1, version_info())
open(sys.argv[3] if len(sys.argv) > 3 else 'app.res', 'wb').write(out)
print('res written', len(out))
