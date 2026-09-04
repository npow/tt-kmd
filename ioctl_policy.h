// SPDX-FileCopyrightText: © 2026 Tenstorrent Inc.
// SPDX-License-Identifier: GPL-2.0-only

#ifndef TTDRIVER_IOCTL_POLICY_H_INCLUDED
#define TTDRIVER_IOCTL_POLICY_H_INCLUDED

/*
 * Blackhole ARC commands that are safe for ordinary runtime clients. Keep
 * this list intentionally small: raw ARC messages bypass the typed KMD ioctl
 * validation used for operations such as power-domain control.
 */
static inline int bh_user_arc_msg_allowed(unsigned int opcode, unsigned int arg0, unsigned int arg1)
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
		return 1;
	case 0x24: /* SET_BOARD_POWER_LIMIT */
		/* Zero without restore would disable the runtime board limit. */
		return arg0 != 0 || (arg1 & 1) != 0;
	case 0xc1: /* SET_WDT_TIMEOUT: userspace may only disable it. */
		return arg0 == 0;
	default:
		return 0;
	}
}

static inline int tenstorrent_reset_ioctl_flag_valid(unsigned int flag)
{
	/* RESTORE_STATE through POST_RESET are the complete public ABI. */
	return flag <= 6;
}

#endif
