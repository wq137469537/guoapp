import plistlib
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from app_build import BuildVariant
from verify_ios_ipa import verify_device_executable, verify_ipa


def executable(platform=2, cpu=0x0100000C):
    return struct.pack('<8I', 0xFEEDFACF, cpu, 0, 2, 1, 24, 0, 0) + struct.pack(
        '<6I', 0x32, 24, platform, 0x0F0100, 0x1A0000, 0)


class IosIpaTests(unittest.TestCase):
    def test_device_executable(self):
        self.assertEqual(verify_device_executable(executable()), '15.1.0')

    def test_simulator_or_wrong_architecture_is_rejected(self):
        for data in [executable(platform=7), executable(cpu=0x01000007), b'not an app',
                     executable()[:-1]]:
            with self.subTest(data=data), self.assertRaises(ValueError):
                verify_device_executable(data)

    def test_payload_branding_version_and_unsigned_status(self):
        for enabled in [False, True]:
            variant = BuildVariant(enabled)
            for prefix, signed, expected_name, success in [
                ('Payload/Runner.app/', False, variant.name, True),
                ('Runner.app/', False, variant.name, False),
                ('Payload/Runner.app/', True, variant.name, False),
                ('Payload/Runner.app/', False, 'wrong edition', False),
            ]:
                with self.subTest(enabled=enabled, prefix=prefix, signed=signed,
                                  name=expected_name), tempfile.TemporaryDirectory() as directory:
                    path = Path(directory) / 'synthetic.ipa'
                    with zipfile.ZipFile(path, 'w') as package:
                        package.writestr(prefix + 'Info.plist', plistlib.dumps({
                            'CFBundleDisplayName': expected_name,
                            'CFBundleName': variant.slug,
                            'CFBundleExecutable': 'Runner',
                            'CFBundleIdentifier': 'example.app',
                            'CFBundlePackageType': 'APPL',
                            'CFBundleShortVersionString': '0.2.65',
                            'CFBundleVersion': '72',
                            'CFBundleSupportedPlatforms': ['iPhoneOS'],
                            'MinimumOSVersion': '15.1',
                        }))
                        package.writestr(prefix + 'Runner', executable())
                        for name in ['App', 'Flutter']:
                            package.writestr(prefix + f'Frameworks/{name}.framework/{name}', b'fixture')
                        if signed:
                            package.writestr(prefix + '_CodeSignature/CodeResources', b'fixture')
                    if success:
                        metadata = verify_ipa(path, variant, '0.2.65+72')
                        self.assertEqual(metadata['architecture'], 'arm64')
                        self.assertEqual(metadata['all_sources'], enabled)
                        self.assertEqual(len(metadata['sha256']), 64)
                    else:
                        with self.assertRaises(ValueError):
                            verify_ipa(path, variant, '0.2.65+72')

    def test_ditto_preserves_payload_parent(self):
        script = (Path(__file__).parent / 'build_ios.py').read_text(encoding='utf-8')
        self.assertIn("'--keepParent', str(payload), str(ipa)", script)


if __name__ == '__main__':
    unittest.main()
