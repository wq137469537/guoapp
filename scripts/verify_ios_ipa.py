import argparse
import hashlib
import json
import plistlib
import re
import struct
import zipfile
from pathlib import Path

from app_build import BuildVariant, add_variant_argument


def verify_device_executable(data):
    if len(data) < 32:
        raise ValueError('Truncated Mach-O executable')
    magic, cpu, _, file_type, count, command_bytes, _, _ = struct.unpack_from('<8I', data)
    if (magic, cpu, file_type) != (0xFEEDFACF, 0x0100000C, 2):
        raise ValueError('Runner must be a thin ARM64 Mach-O device executable')
    end = 32 + command_bytes
    if end > len(data):
        raise ValueError('Truncated Mach-O load commands')
    position = 32
    minimum = None
    for _ in range(count):
        if position + 8 > end:
            raise ValueError('Invalid Mach-O load command')
        command, size = struct.unpack_from('<2I', data, position)
        if size < 8 or position + size > end:
            raise ValueError('Invalid Mach-O load command size')
        if command == 0x32:
            if size < 24:
                raise ValueError('Truncated LC_BUILD_VERSION')
            platform, version = struct.unpack_from('<2I', data, position + 8)
            if platform != 2:
                raise ValueError('Runner was not built for iOS devices')
            minimum = f'{version >> 16}.{(version >> 8) & 255}.{version & 255}'
        if command == 0x2C:
            if size < 24 or struct.unpack_from('<I', data, position + 16)[0] != 0:
                raise ValueError('Runner is encrypted or has invalid encryption metadata')
        position += size
    if minimum is None or position != end:
        raise ValueError('Missing or invalid device build metadata')
    return minimum


def verify_ipa(path, variant, version):
    application = 'Payload/Runner.app/'
    with zipfile.ZipFile(path) as package:
        bad = package.testzip()
        if bad:
            raise ValueError('IPA CRC mismatch: ' + bad)
        names = package.namelist()
        if len(names) != len(set(names)):
            raise ValueError('IPA contains duplicate entries')
        if application + 'Info.plist' not in names:
            raise ValueError('IPA must contain Payload/Runner.app/Info.plist')
        info = plistlib.loads(package.read(application + 'Info.plist'))
        expected_version, expected_build = version.split('+')
        expected = {
            'CFBundleDisplayName': variant.name,
            'CFBundleName': variant.slug,
            'CFBundleExecutable': 'Runner',
            'CFBundlePackageType': 'APPL',
            'CFBundleShortVersionString': expected_version,
            'CFBundleVersion': expected_build,
            'CFBundleSupportedPlatforms': ['iPhoneOS'],
        }
        for key, value in expected.items():
            if info.get(key) != value:
                raise ValueError(f'{key}: expected {value!r}, got {info.get(key)!r}')
        if not info.get('CFBundleIdentifier') or not info.get('MinimumOSVersion'):
            raise ValueError('Missing bundle identity or minimum iOS version')
        if any(name.startswith(application + '_CodeSignature/') or
               name == application + 'embedded.mobileprovision' for name in names):
            raise ValueError('Expected an unsigned application without a provisioning profile')
        minimum = verify_device_executable(package.read(application + 'Runner'))
        if tuple(map(int, minimum.split('.'))) != tuple(
                int(part) for part in (info['MinimumOSVersion'].split('.') + ['0', '0'])[:3]):
            raise ValueError('Executable and Info.plist minimum iOS versions differ')
        for framework in ['App', 'Flutter']:
            if application + f'Frameworks/{framework}.framework/{framework}' not in names:
                raise ValueError('Missing required Flutter framework: ' + framework)
    with path.open('rb') as stream:
        digest = hashlib.file_digest(stream, 'sha256').hexdigest()
    return {
        'file': path.name,
        'bytes': path.stat().st_size,
        'sha256': digest,
        'app_name': info['CFBundleDisplayName'],
        'bundle_identifier': info['CFBundleIdentifier'],
        'version': version,
        'minimum_ios': info['MinimumOSVersion'],
        'architecture': 'arm64',
        'platform': 'iPhoneOS',
        'signed': False,
        'all_sources': variant.all_sources,
    }


def main():
    parser = argparse.ArgumentParser(description='Verify an unsigned device IPA without Apple tools')
    parser.add_argument('ipa', type=Path)
    parser.add_argument('--output', type=Path)
    add_variant_argument(parser)
    options = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    version = re.search(r'^version:\s*(\S+)', (root / 'pubspec.yaml').read_text(encoding='utf-8'),
                        re.MULTILINE).group(1)
    metadata = verify_ipa(options.ipa, BuildVariant(options.all_sources), version)
    text = json.dumps(metadata, ensure_ascii=False, indent=2) + '\n'
    if options.output:
        options.output.write_text(text, encoding='utf-8')
    print(text)


if __name__ == '__main__':
    main()
