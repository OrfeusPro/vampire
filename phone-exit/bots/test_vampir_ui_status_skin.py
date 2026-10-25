"""Bounded source frame extraction, float color conversion and alpha preservation."""
import struct
import sys
import unittest
import zlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / 'resource-tools/vampir'))
import ui_status_skin as skin

FRAME = bytes.fromhex('00020502090206030102020901010000c4420000904100090000003f0000003f0000003f0000003fb6ffffff1a000000000400000000')


def texture(pixel):
    dims = struct.pack('<iii', 1, 1, 1)
    return dims + bytes(4) + b'PF_FloatRGBA\0' + bytes(3) + struct.pack('<4e', *pixel) + dims


class SkinTests(unittest.TestCase):
    def test_deferred_portrait_path_is_distinct_from_brush_fallback(self):
        raw = bytes.fromhex('0002020205020903020000000000000009000000000000000000000004040103010000804300008043edffffff030000000100000000')
        names = ['None'] * 10
        names[2] = '/Game/RED/UI/Resource/Texture/Image/PortraitContents/IMG_PortraitFrame_Noble_01'
        names[9] = 'IMG_PortraitFrame_Noble_01'
        result = skin.decode_portrait_deferred(raw, names)
        self.assertEqual(result['asset_path'], names[2])
        self.assertTrue(result['unread_payload_hex'].endswith('00000000'))
        self.assertFalse(result['runtime_loader_verified'])

    def test_deferred_unknown_names_and_subpaths_are_not_guessed(self):
        raw = bytes.fromhex('0002020205020903020000000000000009000000000000000000000004040103010000804300008043edffffff030000000100000000')
        with self.assertRaises(ValueError):
            skin.decode_portrait_deferred(raw, ['None'])
        names = ['None'] * 10
        names[2], names[9] = '/Game/Example/Asset', 'Different'
        with self.assertRaises(ValueError):
            skin.decode_portrait_deferred(raw, names)

    def test_direct_brush_reference_and_unread_inherited_tail_are_separate(self):
        result = skin.decode_frame_brush(FRAME)
        self.assertEqual(result['resource_object'], -74)
        self.assertEqual(result['image_size'], [98, 18])
        self.assertEqual(result['margin'], [.5] * 4)
        self.assertFalse(result['inherited_properties_decoded'])
        self.assertTrue(result['inherited_payload_hex'])
        self.assertEqual(skin.decode_frame_brush(FRAME + b'new')['inherited_payload_hex'], result['inherited_payload_hex'] + b'new'.hex())

    def test_unreviewed_brush_layout_and_truncated_fields_rejected(self):
        for raw in [b'', FRAME[:20], b'\0\1' + FRAME[2:], FRAME[:12] + b'\3' + FRAME[13:]]:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                skin.decode_frame_brush(raw)

    def test_float_texture_color_and_alpha(self):
        png, info = skin.float_rgba_png(texture((0, .25, 1, .25)))
        self.assertEqual((info['width'], info['height']), (1, 1))
        self.assertFalse(info['hdr_clamped'])
        position, decoded = 8, None
        while position < len(png):
            size = struct.unpack_from('>I', png, position)[0]
            kind = png[position + 4:position + 8]
            if kind == b'IDAT': decoded = zlib.decompress(png[position + 8:position + 8 + size])
            position += size + 12
        self.assertEqual(decoded, bytes([0, 0, 137, 255, 64]))

    def test_hdr_nonfinite_and_missing_payload_rejected(self):
        for raw in [texture((2, 0, 0, 1)), texture((float('nan'), 0, 0, 1)), texture((0, 0, 0, 2)), texture((0, 0, 0, 1))[:-5]]:
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                skin.float_rgba_png(raw)


if __name__ == '__main__':
    unittest.main()
