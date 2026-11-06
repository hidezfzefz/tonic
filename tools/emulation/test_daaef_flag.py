#!/usr/bin/env python3
"""Regression checks for the 0xdaaef fallback flag.

The captured normal state is in tools/emulation/flag_gate.log:
    rax=0x1092, r12=0, r14=1, [rsp+0x250]=1

The assembly at 0xdaaef is modelled here:

    rcx = key ^ r14
    rdx = r14 ^ r12
    cl = ((rdx | rcx) == 0)
    bl = signed(rax) < signed(r12)
    bl |= cl

`key` is the fixed 0x7afc4394e610c6e4 value, so the key-equality term cannot
set the flag when r12 is zero.  A normal gettid is positive, so the signed
less-than term is also false.
"""

import unittest

MASK64 = (1 << 64) - 1
DEFAULT_PID_MAX = 4_194_304

KEY = 0x7AFC4394E610C6E4
NORMAL_R12 = 0
NORMAL_R14 = 1
NORMAL_RAX = 0x1092  # gettid in the capture


def signed64(value):
    value &= MASK64
    if value & (1 << 63):
        return value - (1 << 64)
    return value


def fallback_flag(key, r12, r14, rax):
    """Return bl after the 0xdaaef comparisons."""
    cl = int(((key ^ r14) | (r14 ^ r12)) == 0)
    bl = int(signed64(rax) < signed64(r12))
    return bl | cl


class DaaefFlagTests(unittest.TestCase):
    def test_captured_normal_state(self):
        self.assertEqual(NORMAL_RAX, 0x1092)
        self.assertEqual(NORMAL_R12, 0)
        self.assertEqual(NORMAL_R14, 1)
        self.assertEqual(fallback_flag(KEY, NORMAL_R12, NORMAL_R14, NORMAL_RAX), 0)

    def test_normal_pid_range_stays_zero(self):
        for tid in range(1, DEFAULT_PID_MAX + 1):
            self.assertEqual(
                fallback_flag(KEY, NORMAL_R12, NORMAL_R14, tid), 0,
                f"flag became nonzero for gettid={tid}",
            )

    def test_key_term_is_structurally_zero(self):
        # r12 == 0 and key != 0 make rdx|rcx nonzero for every r14:
        # - r14 == 0 -> rcx == key
        # - r14 != 0 -> rdx == r14
        for r14 in (
            0,
            1,
            2,
            0xFF,
            KEY,
            KEY ^ 1,
            1 << 63,
            MASK64,
        ):
            self.assertEqual(
                fallback_flag(KEY, 0, r14, NORMAL_RAX), 0,
                f"key term unexpectedly set the flag for r14={r14:#x}",
            )

    def test_forced_states_are_needed_to_set_flag(self):
        # Both values equal the key: sete can fire, but this is not the
        # captured normal state.
        self.assertEqual(fallback_flag(KEY, KEY, KEY, 1), 1)

        # A negative rax can trigger setl with r12 == 0, but gettid is
        # positive in the normal range.
        self.assertEqual(fallback_flag(KEY, 0, 1, MASK64), 1)


if __name__ == "__main__":
    unittest.main()
