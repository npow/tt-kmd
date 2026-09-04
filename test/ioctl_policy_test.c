// SPDX-FileCopyrightText: © 2026 Tenstorrent Inc.
// SPDX-License-Identifier: GPL-2.0-only

#include <stdbool.h>
#include <stdio.h>

#include "../ioctl_policy.h"

#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))

static bool expected_arc_allowed(unsigned int opcode, unsigned int arg0,
				 unsigned int arg1)
{
	switch (opcode) {
	case 0x13: /* GET_VOLTAGE */
	case 0x16: /* REPORT_SCRATCH_ONLY */
	case 0x22: /* SET_TDP_LIMIT */
	case 0x23: /* SET_ASIC_HOST_FMAX */
	case 0x34: /* GET_AICLK */
	case 0x54: /* AICLK_GO_LONG_IDLE */
	case 0x90: /* TEST */
	case 0xc4: /* CONFIRM_FLASHED_SPI: challenge echo only. */
		return true;
	case 0x24: /* SET_BOARD_POWER_LIMIT */
		return arg0 != 0 || (arg1 & 1) != 0;
	case 0xc1: /* SET_WDT_TIMEOUT: userspace may only disable it. */
		return arg0 == 0;
	default:
		return false;
	}
}

static int test_arc_policy(void)
{
	static const unsigned int args[][2] = {
		{ 0, 0 }, { 0, 1 }, { 1, 0 }, { ~0U, ~0U }
	};
	unsigned int opcode;
	unsigned int i;

	for (opcode = 0; opcode <= 0xff; opcode++) {
		for (i = 0; i < ARRAY_SIZE(args); i++) {
			bool expected = expected_arc_allowed(opcode, args[i][0], args[i][1]);
			bool actual = bh_user_arc_msg_allowed(opcode, args[i][0], args[i][1]);

			if (actual != expected) {
				fprintf(stderr,
					"ARC opcode 0x%02x args 0x%x/0x%x: expected %s, got %s\n",
					opcode, args[i][0], args[i][1],
					expected ? "allowed" : "denied",
					actual ? "allowed" : "denied");
				return 1;
			}
		}
	}

	return 0;
}

static int test_reset_policy(void)
{
	unsigned int flag;

	for (flag = 0; flag <= 0xff; flag++) {
		bool expected = flag <= 6;
		bool actual = tenstorrent_reset_ioctl_flag_valid(flag);

		if (actual != expected) {
			fprintf(stderr, "reset flag 0x%x: expected %s, got %s\n",
				flag, expected ? "valid" : "invalid",
				actual ? "valid" : "invalid");
			return 1;
		}
	}

	if (tenstorrent_reset_ioctl_flag_valid(~0U)) {
		fputs("reset flag UINT_MAX should be invalid\n", stderr);
		return 1;
	}

	return 0;
}

int main(void)
{
	if (test_arc_policy() || test_reset_policy())
		return 1;

	puts("ioctl_policy_test: PASSED (1281/1281)");
	return 0;
}
