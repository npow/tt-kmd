// SPDX-FileCopyrightText: © 2026 Tenstorrent Inc.
// SPDX-License-Identifier: GPL-2.0-only
//
// Combined stress, benchmark, and adversarial test for the
// TENSTORRENT_IOCTL_SMC_MSG interface.  Merges arc_msg_break.c (adversarial
// attacks) and arc_msg_stress.c (benchmarks and abandon stress) into a single
// binary that loops over every device in /dev/tenstorrent.
//
// The ioctl is poll-based and each fd may have at most one message
// outstanding: POST submits a message, POLL is non-blocking and returns
// -EAGAIN until the response is ready, and ABANDON cancels an outstanding
// message.  Exactly one of POST, POLL, or ABANDON is legal per call.
//
// Only two firmware message types are ever sent:
//   * TT_SMC_MSG_TEST (0x90)
//       Echo.  Response is { 0, test_value + 1, last_serial + 1, ... }.
//   * TT_SMC_MSG_POWER_SETTING (0x21) with validity = 0
//       No fields are applied, so the firmware just acks.  Safe to issue
//       concurrently with the kernel's own power-state aggregation traffic.
//
// Anomalies (unexpected errnos, echo mismatches, health-check failures,
// etc.) are counted and reported at exit; exit status is nonzero if any
// were seen.
//
// Usage:
//   ./arc_msg_test [-i iterations] [-t threads] [-m duration_ms] [device...]
//
// With no device arguments, all devices in /dev/tenstorrent are tested.
// Devices whose firmware lacks the message queue are skipped.

#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

// --- Driver definitions (self-contained) ---

#define TENSTORRENT_IOCTL_MAGIC           0xFA
#define TENSTORRENT_IOCTL_SET_POWER_STATE _IO(TENSTORRENT_IOCTL_MAGIC, 15)
#define TENSTORRENT_IOCTL_SMC_MSG         _IO(TENSTORRENT_IOCTL_MAGIC, 17)

#define TENSTORRENT_SMC_MSG_POST    (1U << 0)
#define TENSTORRENT_SMC_MSG_POLL    (1U << 1)
#define TENSTORRENT_SMC_MSG_ABANDON (1U << 2)

struct tenstorrent_smc_msg {
	uint32_t argsz;
	uint32_t flags;
	uint32_t queue_index;
	uint32_t reserved0;
	uint32_t message[8];
};

struct tenstorrent_power_state {
	uint32_t argsz;
	uint32_t flags;
	uint8_t  reserved0;
	uint8_t  validity;
	uint16_t power_flags;
	uint16_t power_settings[14];
};

// Innocuous firmware messages — see file header.
#define MSG_TYPE_TEST          0x90
#define MSG_TYPE_POWER_SETTING 0x21

// Deadline for a single round-trip before we give up and abandon.
#define ROUND_TRIP_TIMEOUT_SEC 2.0

#define DEVICE_DIR "/dev/tenstorrent"

// --- Configuration and globals ---

// Base iteration count; per-phase counts are scaled from this.
static int g_iterations = 1000;
// Worker thread count for the multithreaded phases.
static int g_threads = 8;
// Base duration for the timed phases.
static int g_duration_ms = 500;

// Path of the device currently under test.
static const char *g_path;
static atomic_int g_anomalies;

#define BUMP_ANOMALY(fmt, ...) do {                                           \
	atomic_fetch_add(&g_anomalies, 1);                                    \
	fprintf(stderr, "  ANOMALY: " fmt "\n", ##__VA_ARGS__);               \
} while (0)

// --- Low-level helpers ---

static double now_sec(void)
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec * 1e-9;
}

static int open_dev(void)
{
	int fd = open(g_path, O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "open(%s): %s\n", g_path, strerror(errno));
		exit(1);
	}
	return fd;
}

static int arc_raw(int fd, void *arg)
{
	return ioctl(fd, TENSTORRENT_IOCTL_SMC_MSG, arg);
}

static int smc_msg(int fd, uint32_t flags, uint32_t *msg8)
{
	struct tenstorrent_smc_msg m = {0};
	m.argsz = sizeof(m);
	m.flags = flags;
	if (msg8)
		memcpy(m.message, msg8, sizeof(m.message));
	int ret = ioctl(fd, TENSTORRENT_IOCTL_SMC_MSG, &m);
	if (msg8)
		memcpy(msg8, m.message, sizeof(m.message));
	return ret;
}

static int post(int fd, uint32_t *m)     { return smc_msg(fd, TENSTORRENT_SMC_MSG_POST, m); }
static int poll_msg(int fd, uint32_t *m) { return smc_msg(fd, TENSTORRENT_SMC_MSG_POLL, m); }
static int abandon(int fd)               { return smc_msg(fd, TENSTORRENT_SMC_MSG_ABANDON, NULL); }

// POST then POLL until the response arrives.  POLL is non-blocking (the queue
// pump advances on every POLL), so we spin.  Returns 0 with the response in
// *m (a firmware error is reported via the response header, not errno), or -1
// with errno set (EBUSY/EOPNOTSUPP from POST, ETIMEDOUT on our own deadline).
// If first_poll_hit is non-NULL it is set to 1 when the very first POLL
// already had the response.
static int round_trip(int fd, uint32_t *m, int *first_poll_hit)
{
	double deadline;
	int polls = 0;

	if (post(fd, m) != 0)
		return -1;

	deadline = now_sec() + ROUND_TRIP_TIMEOUT_SEC;
	for (;;) {
		int ret = poll_msg(fd, m);
		polls++;
		if (ret == 0) {
			if (first_poll_hit)
				*first_poll_hit = (polls == 1);
			return 0;
		}
		if (errno != EAGAIN)
			return -1;
		if (now_sec() > deadline) {
			abandon(fd);
			errno = ETIMEDOUT;
			return -1;
		}
	}
}

static void mk_test(uint32_t *m, uint32_t value)
{
	memset(m, 0, 8 * sizeof(uint32_t));
	m[0] = MSG_TYPE_TEST;
	m[1] = value;
}

// Power message with validity = 0 → firmware applies nothing.
static void mk_power_noop(uint32_t *m)
{
	// Header layout matches struct power_setting_rqst:
	//   byte 0: command code
	//   byte 1: bits 0-3 power_flags_valid, bits 4-7 power_settings_valid
	//   bytes 2-3: power_flags
	memset(m, 0, 8 * sizeof(uint32_t));
	m[0] = MSG_TYPE_POWER_SETTING;
}

// --- Health check ---

static void verify_healthy(int fd)
{
	uint32_t m[8];

	mk_test(m, 0xCAFE);
	if (round_trip(fd, m, NULL) != 0) {
		BUMP_ANOMALY("health round_trip failed: %s", strerror(errno));
		// Try to recover so subsequent phases aren't all broken.
		abandon(fd);
		return;
	}
	if (m[0] != 0)
		BUMP_ANOMALY("health: response header nonzero (%u)", m[0]);
	if (m[1] != 0xCAFF)
		BUMP_ANOMALY("health: echo mismatch, sent 0xCAFE got 0x%x", m[1]);
}

// --- Attack: argsz fuzzing ---

static void attack_argsz(int fd)
{
	// argsz must equal sizeof(struct tenstorrent_smc_msg) exactly; the
	// kernel rejects any other value with -EINVAL before it even looks at
	// the flags.  The one well-formed size, with POLL on an IDLE fd, is the
	// terminal operation and returns -ESRCH.
	const uint32_t good = sizeof(struct tenstorrent_smc_msg);
	int einval = 0, esrch = 0, ok = 0, unexpected = 0;
	uint32_t sz;

	for (sz = 0; sz <= 256; sz++) {
		struct tenstorrent_smc_msg m = {0};
		m.argsz = sz;
		m.flags = TENSTORRENT_SMC_MSG_POLL;
		if (arc_raw(fd, &m) == 0) {
			ok++;
			abandon(fd);
			continue;
		}
		if (sz == good) {
			if (errno == ESRCH) {
				esrch++;
			} else {
				unexpected++;
				fprintf(stderr, "  argsz=%u -> %s\n", sz, strerror(errno));
			}
		} else if (errno == EINVAL) {
			einval++;
		} else {
			unexpected++;
			fprintf(stderr, "  argsz=%u -> %s\n", sz, strerror(errno));
		}
	}

	// 257 iterations [0,256]: exactly one (argsz == good) yields ESRCH, the
	// other 256 yield EINVAL, and nothing should succeed.
	if (ok != 0)
		BUMP_ANOMALY("argsz: %d calls unexpectedly succeeded", ok);
	if (esrch != 1)
		BUMP_ANOMALY("argsz: expected 1 ESRCH at argsz=%u, got %d", good, esrch);
	if (einval != 256)
		BUMP_ANOMALY("argsz: expected 256 EINVAL, got %d", einval);
	if (unexpected != 0)
		BUMP_ANOMALY("argsz: %d unexpected results", unexpected);

	printf("  argsz sweep [0,256]: einval=%d esrch=%d ok=%d unexpected=%d\n",
	       einval, esrch, ok, unexpected);
}

// --- Attack: flags fuzzing ---

static void attack_flags(int fd)
{
	// Exactly one of POST, POLL, ABANDON is a legal flags value.  Every
	// other value — zero, unknown bits, or any combination (POST|POLL
	// included) — must be rejected with -EINVAL.  ABANDON after each
	// iteration returns the fd to IDLE.
	int ok = 0, einval = 0, esrch = 0, other = 0;
	int post_ok = 0, abandon_ok = 0;

	for (uint32_t f = 0; f < 256; f++) {
		struct tenstorrent_smc_msg m = {0};
		m.argsz = sizeof(m);
		m.flags = f;
		m.message[0] = MSG_TYPE_TEST;
		m.message[1] = f;

		int ret = arc_raw(fd, &m);
		if (ret == 0) {
			ok++;
			if (f == TENSTORRENT_SMC_MSG_POST)
				post_ok++;
			if (f == TENSTORRENT_SMC_MSG_ABANDON)
				abandon_ok++;
		} else switch (errno) {
		case EINVAL: einval++; break;
		case ESRCH:  esrch++;  break;
		default:     other++; fprintf(stderr, "  flags=0x%x -> %s\n", f, strerror(errno));
		}

		// Leave the fd IDLE for next iteration (no-op if already IDLE).
		if (abandon(fd) != 0)
			BUMP_ANOMALY("flags fuzz: abandon failed at f=0x%x: %s", f, strerror(errno));
	}

	// Expected over f in [0,255]:
	//   f=POST(1)    -> 0 (then abandoned back to IDLE)
	//   f=POLL(2)    -> ESRCH (IDLE, nothing outstanding)
	//   f=ABANDON(4) -> 0
	//   everything else (253 values) -> EINVAL
	if (post_ok != 1)
		BUMP_ANOMALY("flags fuzz: POST ok count = %d (expected 1)", post_ok);
	if (abandon_ok != 1)
		BUMP_ANOMALY("flags fuzz: ABANDON ok count = %d (expected 1)", abandon_ok);
	if (esrch != 1)
		BUMP_ANOMALY("flags fuzz: POLL-on-IDLE ESRCH count = %d (expected 1)", esrch);
	if (einval != 253)
		BUMP_ANOMALY("flags fuzz: EINVAL count = %d (expected 253)", einval);
	if (other > 0)
		BUMP_ANOMALY("flags fuzz: %d unexpected errnos", other);

	printf("  flags 0..255: ok=%d einval=%d esrch=%d other=%d\n",
	       ok, einval, esrch, other);
}

// --- Attack: reserved-field fuzzing ---

static void attack_reserved(int fd)
{
	struct tenstorrent_smc_msg m;
	int errs = 0;

	// queue_index != 0 -> EINVAL.
	memset(&m, 0, sizeof(m));
	m.argsz = sizeof(m);
	m.flags = TENSTORRENT_SMC_MSG_POST;
	m.queue_index = 1;
	m.message[0] = MSG_TYPE_TEST;
	int ret = arc_raw(fd, &m);
	if (ret == 0 || errno != EINVAL) {
		BUMP_ANOMALY("queue_index=1: ret=%d errno=%s", ret, strerror(errno));
		errs++;
		abandon(fd);
	}

	// reserved0 != 0 -> EINVAL.
	memset(&m, 0, sizeof(m));
	m.argsz = sizeof(m);
	m.flags = TENSTORRENT_SMC_MSG_POST;
	m.reserved0 = 0xDEADBEEFu;
	m.message[0] = MSG_TYPE_TEST;
	ret = arc_raw(fd, &m);
	if (ret == 0 || errno != EINVAL) {
		BUMP_ANOMALY("reserved0=DEADBEEF: ret=%d errno=%s", ret, strerror(errno));
		errs++;
		abandon(fd);
	}

	printf("  reserved fields: %d anomalies\n", errs);
}

// --- Attack: bad user-space pointers ---

static void attack_bad_pointers(int fd)
{
	int efault_seen = 0, other = 0;

	// NULL pointer.
	if (ioctl(fd, TENSTORRENT_IOCTL_SMC_MSG, (void *)NULL) == 0)
		BUMP_ANOMALY("bad_ptr NULL: succeeded");
	else if (errno == EFAULT)
		efault_seen++;
	else
		other++;

	// Kernel-space address — should also EFAULT (access_ok rejects).
	if (ioctl(fd, TENSTORRENT_IOCTL_SMC_MSG, (void *)(uintptr_t)0xfffffffffffff000ULL) == 0)
		BUMP_ANOMALY("bad_ptr kernel: succeeded");
	else if (errno == EFAULT)
		efault_seen++;
	else
		other++;

	// Struct straddling a page boundary, where the 2nd page is
	// unmapped.  The kernel's copy_from_user must EFAULT.
	long pg = sysconf(_SC_PAGESIZE);
	char *region = mmap(NULL, pg * 2, PROT_READ | PROT_WRITE,
			    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region != MAP_FAILED) {
		// Drop the upper page so reads past `region+pg-4` fault.
		munmap(region + pg, pg);
		struct tenstorrent_smc_msg *m =
			(struct tenstorrent_smc_msg *)(region + pg -
						       sizeof(uint32_t));
		// argsz is in the mapped page; the rest is in the unmapped one.
		m->argsz = sizeof(struct tenstorrent_smc_msg);
		if (ioctl(fd, TENSTORRENT_IOCTL_SMC_MSG, m) == 0)
			BUMP_ANOMALY("bad_ptr straddle: succeeded");
		else if (errno == EFAULT)
			efault_seen++;
		else
			other++;
		munmap(region, pg);
	}

	if (other != 0)
		BUMP_ANOMALY("bad_ptr: %d non-EFAULT errnos", other);

	printf("  bad pointers: efault=%d other=%d\n", efault_seen, other);
}

// --- Attack: multi-thread shared fd ---
//
// Many threads hammer the same fd with POST + POLL.  Because a single fd may
// have only one message outstanding, losers see -EBUSY on POST; the kernel
// mutex serialises us and each successful round-trip must still echo correctly.
struct mt_shared_ctx {
	int fd;
	atomic_int running;
	atomic_long posts;
	atomic_long echo_ok;
	atomic_long echo_bad;
	atomic_long ebusy;
	atomic_long other;
};

static void *mt_shared_worker(void *arg)
{
	struct mt_shared_ctx *ctx = arg;
	uint32_t seed = (uint32_t)((uintptr_t)pthread_self() & 0xFFFFFFFFu);

	while (atomic_load(&ctx->running)) {
		uint32_t v = seed + (uint32_t)atomic_fetch_add(&ctx->posts, 1);
		uint32_t m[8];
		mk_test(m, v);
		int ret = round_trip(ctx->fd, m, NULL);
		if (ret == 0) {
			if (m[1] == v + 1)
				atomic_fetch_add(&ctx->echo_ok, 1);
			else
				atomic_fetch_add(&ctx->echo_bad, 1);
		} else if (errno == EBUSY || errno == EAGAIN || errno == ETIMEDOUT) {
			atomic_fetch_add(&ctx->ebusy, 1);
		} else {
			atomic_fetch_add(&ctx->other, 1);
		}
	}
	return NULL;
}

static void attack_multithread_shared(int fd, int n_threads, int duration_ms)
{
	pthread_t tids[n_threads];
	struct mt_shared_ctx ctx = { .fd = fd, .running = 1 };

	for (int i = 0; i < n_threads; i++)
		pthread_create(&tids[i], NULL, mt_shared_worker, &ctx);

	usleep(duration_ms * 1000);
	atomic_store(&ctx.running, 0);

	for (int i = 0; i < n_threads; i++)
		pthread_join(tids[i], NULL);

	abandon(fd);  // Just in case.

	if (atomic_load(&ctx.echo_bad) != 0)
		BUMP_ANOMALY("mt shared: %ld echo mismatches", atomic_load(&ctx.echo_bad));
	if (atomic_load(&ctx.other) != 0)
		BUMP_ANOMALY("mt shared: %ld unexpected errnos", atomic_load(&ctx.other));

	printf("  mt shared (%d threads, %d ms): posts=%ld echo_ok=%ld echo_bad=%ld ebusy=%ld other=%ld\n",
	       n_threads, duration_ms, atomic_load(&ctx.posts),
	       atomic_load(&ctx.echo_ok), atomic_load(&ctx.echo_bad),
	       atomic_load(&ctx.ebusy), atomic_load(&ctx.other));
}

// --- Attack: random workers with own fds ---
//
// Each worker thread owns its own fd and runs a random mix of TEST and
// POWER (no-op) ops.  No correctness assertions on the message content here —
// we're stressing the queue state machine and the lock paths.
struct mt_random_ctx {
	atomic_int running;
	atomic_long post_poll_test;
	atomic_long post_poll_power;
	atomic_long post_then_poll;
	atomic_long abandon_calls;
	atomic_long unexpected_errno;
};

static void *mt_random_worker(void *arg)
{
	struct mt_random_ctx *ctx = arg;
	int fd = open_dev();
	uint32_t seed = (uint32_t)((uintptr_t)pthread_self() ^ (uintptr_t)&fd);

	while (atomic_load(&ctx->running)) {
		uint32_t r = (seed = seed * 1103515245u + 12345u);
		uint32_t pick = (r >> 16) % 100;
		uint32_t m[8];

		if (pick < 50) {
			mk_test(m, r);
			int ret = round_trip(fd, m, NULL);
			atomic_fetch_add(&ctx->post_poll_test, 1);
			if (ret != 0 && errno != EAGAIN && errno != EBUSY && errno != ETIMEDOUT)
				atomic_fetch_add(&ctx->unexpected_errno, 1);
		} else if (pick < 65) {
			mk_power_noop(m);
			int ret = round_trip(fd, m, NULL);
			atomic_fetch_add(&ctx->post_poll_power, 1);
			if (ret != 0 && errno != EAGAIN && errno != EBUSY && errno != ETIMEDOUT)
				atomic_fetch_add(&ctx->unexpected_errno, 1);
		} else if (pick < 85) {
			mk_test(m, r);
			int ret = post(fd, m);
			if (ret == 0) {
				// Spin-poll briefly then abandon if not ready.
				for (int i = 0; i < 100; i++) {
					if (poll_msg(fd, m) == 0)
						break;
					if (errno != EAGAIN)
						break;
				}
				atomic_fetch_add(&ctx->post_then_poll, 1);
			}
			abandon(fd);
		} else {
			abandon(fd);
			atomic_fetch_add(&ctx->abandon_calls, 1);
		}
	}

	abandon(fd);
	close(fd);
	return NULL;
}

static void attack_random_workers(int n_threads, int duration_ms)
{
	pthread_t tids[n_threads];
	struct mt_random_ctx ctx = { .running = 1 };

	for (int i = 0; i < n_threads; i++)
		pthread_create(&tids[i], NULL, mt_random_worker, &ctx);

	usleep(duration_ms * 1000);
	atomic_store(&ctx.running, 0);

	for (int i = 0; i < n_threads; i++)
		pthread_join(tids[i], NULL);

	if (atomic_load(&ctx.unexpected_errno) != 0)
		BUMP_ANOMALY("random workers: %ld unexpected errnos",
			     atomic_load(&ctx.unexpected_errno));

	printf("  random workers (%d threads, %d ms): pp_test=%ld pp_power=%ld post_poll2=%ld abandon=%ld\n",
	       n_threads, duration_ms,
	       atomic_load(&ctx.post_poll_test), atomic_load(&ctx.post_poll_power),
	       atomic_load(&ctx.post_then_poll), atomic_load(&ctx.abandon_calls));
}

// --- Attack: fork storm ---
//
// Many children open a fd, POST without polling, and _exit().  The
// kernel close path must abandon the inflight message cleanly.
static void attack_fork_storm(int n_children)
{
	int wait_failures = 0, nonzero_exits = 0;

	for (int i = 0; i < n_children; i++) {
		pid_t pid = fork();
		if (pid < 0) {
			BUMP_ANOMALY("fork: %s", strerror(errno));
			break;
		}
		if (pid == 0) {
			int cfd = open_dev();
			uint32_t m[8];
			mk_test(m, (uint32_t)i);
			(void)post(cfd, m);
			_exit(0);
		}
	}

	for (int i = 0; i < n_children; i++) {
		int status;
		pid_t r = wait(&status);
		if (r < 0) {
			wait_failures++;
			break;
		}
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
			nonzero_exits++;
	}

	if (wait_failures)
		BUMP_ANOMALY("fork storm: %d wait failures", wait_failures);
	if (nonzero_exits)
		BUMP_ANOMALY("fork storm: %d nonzero exits", nonzero_exits);

	printf("  fork storm: %d children spawned\n", n_children);
}

// --- Attack: open/close churn ---
//
// Each open triggers tenstorrent_set_aggregated_power_state on a legacy
// fd, which sends a kernel-internal POWER_SETTING via arc_msg_send_sync.
// Same on close.  Lots of churn = lots of nested locking.
static void attack_open_close_churn(int iterations)
{
	int open_failures = 0;
	int post_failures = 0;

	for (int i = 0; i < iterations; i++) {
		int fd = open(g_path, O_RDWR | O_CLOEXEC);
		if (fd < 0) {
			open_failures++;
			continue;
		}
		if ((i & 3) == 0) {
			uint32_t m[8];
			mk_test(m, (uint32_t)i);
			if (post(fd, m) != 0)
				post_failures++;
		}
		close(fd);
	}

	if (open_failures)
		BUMP_ANOMALY("open/close churn: %d open failures", open_failures);

	printf("  open/close churn (%d iter): open_failures=%d post_failures=%d\n",
	       iterations, open_failures, post_failures);
}

// --- Kernel power-state hammer thread (shared by the mixed-path phases) ---
//
// The driver's SET_POWER_STATE ioctl ultimately calls arc_msg_send_sync
// while holding chardev_mutex.  User SMC_MSG ioctls acquire only
// arc_msg_mutex.  Hammering this path races the kernel's internal ARC
// traffic against user messages.
struct power_hammer_ctx {
	atomic_int running;
	atomic_long ops;
	atomic_long errors;
	int sleep_us;
};

static void *power_hammer_thread(void *arg)
{
	struct power_hammer_ctx *ctx = arg;
	int fd = open(g_path, O_RDWR | O_APPEND | O_CLOEXEC);
	if (fd < 0) {
		atomic_fetch_add(&ctx->errors, 1);
		return NULL;
	}

	while (atomic_load(&ctx->running)) {
		struct tenstorrent_power_state ps = {0};
		ps.argsz = sizeof(ps);
		ps.validity = 0x0F; // 15 flags valid, 0 settings — legacy default.
		if (ioctl(fd, TENSTORRENT_IOCTL_SET_POWER_STATE, &ps) != 0)
			atomic_fetch_add(&ctx->errors, 1);
		atomic_fetch_add(&ctx->ops, 1);
		usleep(ctx->sleep_us);
	}

	close(fd);
	return NULL;
}

// --- Attack: concurrent user SMC_MSG vs kernel SET_POWER_STATE ---

struct mixed_ctx {
	int user_fd;
	atomic_int running;
	atomic_long user_ops;
	atomic_long user_errors;
};

static void *user_msg_thread(void *arg)
{
	struct mixed_ctx *ctx = arg;
	uint32_t i = 0;

	while (atomic_load(&ctx->running)) {
		uint32_t m[8];
		// Alternate between TEST echo and POWER no-op so the user
		// path races with the kernel's POWER traffic.
		if (i & 1)
			mk_power_noop(m);
		else
			mk_test(m, i);

		int ret = round_trip(ctx->user_fd, m, NULL);
		atomic_fetch_add(&ctx->user_ops, 1);
		if (ret != 0 && errno != EAGAIN && errno != EBUSY && errno != ETIMEDOUT)
			atomic_fetch_add(&ctx->user_errors, 1);
		// Verify TEST echo correctness when it succeeded.
		if (ret == 0 && (i & 1) == 0 && m[1] != i + 1)
			atomic_fetch_add(&ctx->user_errors, 1);
		i++;
	}
	return NULL;
}

static void attack_mixed_paths(int fd, int duration_ms)
{
	pthread_t user_tid, power_tid;
	struct mixed_ctx ctx = { .user_fd = fd, .running = 1 };
	struct power_hammer_ctx power = { .running = 1, .sleep_us = 200 };

	pthread_create(&user_tid, NULL, user_msg_thread, &ctx);
	pthread_create(&power_tid, NULL, power_hammer_thread, &power);

	usleep(duration_ms * 1000);
	atomic_store(&ctx.running, 0);
	atomic_store(&power.running, 0);

	pthread_join(user_tid, NULL);
	pthread_join(power_tid, NULL);

	if (atomic_load(&ctx.user_errors))
		BUMP_ANOMALY("mixed: %ld user errors", atomic_load(&ctx.user_errors));
	if (atomic_load(&power.errors))
		BUMP_ANOMALY("mixed: %ld power-state ioctl errors", atomic_load(&power.errors));

	printf("  mixed (%d ms): user_ops=%ld power_ops=%ld user_errs=%ld power_errs=%ld\n",
	       duration_ms, atomic_load(&ctx.user_ops), atomic_load(&power.ops),
	       atomic_load(&ctx.user_errors), atomic_load(&power.errors));
}

// --- Benchmarks ---

static void bench_round_trip(int fd, int count)
{
	double start = now_sec();
	int errors = 0;
	int first_hits = 0;

	for (int i = 0; i < count; i++) {
		uint32_t message[8] = {0};
		int first_hit = 0;
		message[0] = MSG_TYPE_TEST;
		message[1] = i;

		if (round_trip(fd, message, &first_hit) != 0) {
			fprintf(stderr, "  round-trip failed at %d: %s\n", i, strerror(errno));
			errors++;
			continue;
		}
		if (first_hit)
			first_hits++;
		if (message[1] != (uint32_t)(i + 1)) {
			fprintf(stderr, "  echo mismatch: sent %d, got %u\n", i, message[1]);
			errors++;
		}
	}

	double elapsed = now_sec() - start;
	printf("  %d messages in %.3f s (%.0f msg/s, %.1f us/msg)\n",
	       count, elapsed, count / elapsed, elapsed / count * 1e6);
	printf("  %d/%d completed on first poll\n", first_hits, count);
	if (errors)
		BUMP_ANOMALY("round-trip bench: %d errors", errors);
}

static void bench_latency(int fd, int count)
{
	double min_us = 1e9, max_us = 0, sum_us = 0;
	int errors = 0;

	for (int i = 0; i < count; i++) {
		uint32_t message[8] = {0};
		message[0] = MSG_TYPE_TEST;
		message[1] = i;

		double t0 = now_sec();
		if (round_trip(fd, message, NULL) != 0) {
			errors++;
			continue;
		}
		double us = (now_sec() - t0) * 1e6;

		if (us < min_us) min_us = us;
		if (us > max_us) max_us = us;
		sum_us += us;
	}

	int good = count - errors;
	if (good > 0)
		printf("  min=%.1f us  avg=%.1f us  max=%.1f us\n",
		       min_us, sum_us / good, max_us);
	if (errors)
		BUMP_ANOMALY("latency bench: %d errors", errors);
}

// --- Abandon stress tests ---

// Abandon before FW submit: a second fd occupies the in-flight FW slot so our
// message stays QUEUED in software, then we ABANDON it before the pump can push
// it to firmware.
static void stress_abandon_before_submit(int fd, int count)
{
	int errors = 0;

	// We need a second fd to occupy the inflight slot so our message
	// stays QUEUED.
	int fd2 = open(g_path, O_RDWR | O_CLOEXEC);
	if (fd2 < 0) {
		printf("  SKIP: couldn't open second fd: %s\n", strerror(errno));
		return;
	}

	for (int i = 0; i < count; i++) {
		// fd2 posts a message to occupy the inflight slot.
		uint32_t msg2[8] = {0};
		msg2[0] = MSG_TYPE_TEST;
		if (post(fd2, msg2) != 0) {
			fprintf(stderr, "  fd2 POST failed: %s\n", strerror(errno));
			errors++;
			break;
		}

		// fd posts a message — should stay QUEUED behind fd2's.
		uint32_t msg1[8] = {0};
		msg1[0] = MSG_TYPE_TEST;
		if (post(fd, msg1) != 0) {
			fprintf(stderr, "  fd POST failed: %s\n", strerror(errno));
			// Clean up fd2's message.
			round_trip(fd2, msg2, NULL);
			errors++;
			continue;
		}

		// Abandon fd's message while it's still in the SW queue.
		if (abandon(fd) != 0) {
			fprintf(stderr, "  ABANDON failed: %s\n", strerror(errno));
			errors++;
		}

		// Drain fd2's message.  It is already posted, so poll it out.
		double deadline = now_sec() + ROUND_TRIP_TIMEOUT_SEC;
		for (;;) {
			if (poll_msg(fd2, msg2) == 0)
				break;
			if (errno != EAGAIN || now_sec() > deadline) {
				fprintf(stderr, "  fd2 POLL failed: %s\n", strerror(errno));
				abandon(fd2);
				errors++;
				break;
			}
		}
	}

	close(fd2);
	if (errors)
		BUMP_ANOMALY("abandon before submit: %d errors", errors);
	printf("  %d iterations, %d errors\n", count, errors);
}

// Abandon after FW submit: POST (the pump submits it to FW), sleep briefly to
// let it reach firmware, then ABANDON while it is SUBMITTED.  Then confirm the
// fd is usable with a fresh round-trip.
static void stress_abandon_after_submit(int fd, int count)
{
	int errors = 0;

	for (int i = 0; i < count; i++) {
		uint32_t message[8] = {0};
		message[0] = MSG_TYPE_TEST;
		message[1] = i;

		// POST without POLL — the pump submits to FW.
		if (post(fd, message) != 0) {
			fprintf(stderr, "  POST failed: %s\n", strerror(errno));
			errors++;
			continue;
		}

		// Brief sleep to let the message reach firmware.
		usleep(500);

		// Abandon while (likely) SUBMITTED.
		if (abandon(fd) != 0) {
			fprintf(stderr, "  ABANDON failed: %s\n", strerror(errno));
			errors++;
			continue;
		}

		// Verify the fd is usable: round-trip a new message.
		memset(message, 0, sizeof(message));
		message[0] = MSG_TYPE_TEST;
		message[1] = 1000 + i;

		if (round_trip(fd, message, NULL) != 0) {
			fprintf(stderr, "  round-trip after abandon failed: %s\n", strerror(errno));
			errors++;
			continue;
		}

		if (message[1] != (uint32_t)(1001 + i)) {
			fprintf(stderr, "  echo mismatch after abandon: expected %d, got %u\n",
				1001 + i, message[1]);
			errors++;
		}
	}

	if (errors)
		BUMP_ANOMALY("abandon after submit: %d errors", errors);
	printf("  %d iterations, %d errors\n", count, errors);
}

// Rapid POST/ABANDON cycles on a single fd.
static void stress_rapid_post_abandon(int fd, int count)
{
	int errors = 0;

	for (int i = 0; i < count; i++) {
		uint32_t message[8] = {0};
		message[0] = MSG_TYPE_TEST;
		message[1] = i;

		if (post(fd, message) != 0) {
			fprintf(stderr, "  POST failed at %d: %s\n", i, strerror(errno));
			errors++;
			break;
		}

		if (abandon(fd) != 0) {
			fprintf(stderr, "  ABANDON failed at %d: %s\n", i, strerror(errno));
			errors++;
			break;
		}
	}

	// Verify fd is still healthy after the storm.
	uint32_t message[8] = {0};
	message[0] = MSG_TYPE_TEST;
	message[1] = 0xDEAD;

	if (round_trip(fd, message, NULL) != 0) {
		fprintf(stderr, "  round-trip after storm failed: %s\n", strerror(errno));
		errors++;
	} else if (message[1] != 0xDEAE) {
		fprintf(stderr, "  echo mismatch after storm: expected 0xDEAE, got 0x%x\n", message[1]);
		errors++;
	}

	if (errors)
		BUMP_ANOMALY("rapid post/abandon: %d errors", errors);
	printf("  %d iterations, %d errors\n", count, errors);
}

// --- Stress: sequential user messages vs kernel SET_POWER_STATE ---
//
// Unlike the mixed-paths attack (timed, alternating message types), this
// drives a fixed count of TEST round-trips with full echo verification while
// the kernel path runs at a gentler cadence.
static void stress_concurrent_kernel_user(int fd, int count)
{
	struct power_hammer_ctx power = { .running = 1, .sleep_us = 1000 };
	pthread_t tid;

	if (pthread_create(&tid, NULL, power_hammer_thread, &power) != 0) {
		printf("  SKIP: couldn't create thread\n");
		return;
	}

	int user_errors = 0;
	for (int i = 0; i < count; i++) {
		uint32_t message[8] = {0};
		message[0] = MSG_TYPE_TEST;
		message[1] = i;

		if (round_trip(fd, message, NULL) != 0) {
			user_errors++;
			continue;
		}
		if (message[1] != (uint32_t)(i + 1)) {
			fprintf(stderr, "  echo mismatch: sent %d, got %u\n",
				i, message[1]);
			user_errors++;
		}
	}

	atomic_store(&power.running, 0);
	pthread_join(tid, NULL);

	if (user_errors)
		BUMP_ANOMALY("concurrent kernel+user: %d user errors", user_errors);
	if (atomic_load(&power.errors))
		BUMP_ANOMALY("concurrent kernel+user: %ld power-state ioctl errors",
			     atomic_load(&power.errors));

	printf("  user: %d msgs, %d errors\n", count, user_errors);
	printf("  power: %ld calls, %ld errors\n",
	       atomic_load(&power.ops), atomic_load(&power.errors));
}

// --- Per-device driver ---

// Runs every phase against the device in g_path.  Returns 0 if the device
// was tested, 1 if it was skipped (no message queue support).
static int test_device(void)
{
	int fd = open_dev();
	int phase = 0;

	// Probe: confirm the queue is available before running anything.
	uint32_t probe[8];
	mk_test(probe, 0);
	if (round_trip(fd, probe, NULL) != 0) {
		if (errno == EOPNOTSUPP) {
			printf("SKIP %s: SMC message queue not available\n", g_path);
			close(fd);
			return 1;
		}
		BUMP_ANOMALY("SMC_MSG probe failed on %s: %s", g_path, strerror(errno));
		close(fd);
		return 1;
	}
	printf("Probe OK on %s\n", g_path);

	const int n_phases = 15;
#define PHASE(name) printf("[%d/%d] %s\n", ++phase, n_phases, name)

	PHASE("argsz fuzz");
	attack_argsz(fd);
	verify_healthy(fd);

	PHASE("flags fuzz");
	attack_flags(fd);
	verify_healthy(fd);

	PHASE("reserved-field fuzz");
	attack_reserved(fd);
	verify_healthy(fd);

	PHASE("bad-pointer fuzz");
	attack_bad_pointers(fd);
	verify_healthy(fd);

	PHASE("multithread shared fd");
	attack_multithread_shared(fd, g_threads, g_duration_ms);
	verify_healthy(fd);

	PHASE("random workers");
	attack_random_workers(g_threads, 3 * g_duration_ms);
	verify_healthy(fd);

	PHASE("fork storm");
	attack_fork_storm(g_iterations / 16 > 0 ? g_iterations / 16 : 1);
	verify_healthy(fd);

	PHASE("open/close churn");
	attack_open_close_churn(g_iterations / 2 > 0 ? g_iterations / 2 : 1);
	verify_healthy(fd);

	PHASE("mixed user+power-state paths");
	attack_mixed_paths(fd, 3 * g_duration_ms);
	verify_healthy(fd);

	PHASE("round-trip benchmark");
	bench_round_trip(fd, 10 * g_iterations);
	verify_healthy(fd);

	PHASE("latency distribution");
	bench_latency(fd, g_iterations);
	verify_healthy(fd);

	PHASE("abandon after FW submit");
	stress_abandon_after_submit(fd, g_iterations);
	verify_healthy(fd);

	PHASE("abandon before FW submit");
	stress_abandon_before_submit(fd, g_iterations);
	verify_healthy(fd);

	PHASE("rapid POST/ABANDON");
	stress_rapid_post_abandon(fd, 10 * g_iterations);
	verify_healthy(fd);

	PHASE("concurrent kernel+user messages");
	stress_concurrent_kernel_user(fd, 10 * g_iterations);
	verify_healthy(fd);

#undef PHASE

	close(fd);
	return 0;
}

// --- Device enumeration ---

static int devdir_filter(const struct dirent *e)
{
	return e->d_name[0] != '.';
}

// Returns a malloc'd array of malloc'd device paths, sorted numerically.
static char **enumerate_devices(int *count_out)
{
	struct dirent **entries;
	char **paths = NULL;
	int count = 0;

	int n = scandir(DEVICE_DIR, &entries, devdir_filter, versionsort);
	if (n < 0) {
		fprintf(stderr, "scandir(%s): %s\n", DEVICE_DIR, strerror(errno));
		*count_out = 0;
		return NULL;
	}

	paths = malloc(n * sizeof(*paths));
	for (int i = 0; i < n; i++) {
		char path[PATH_MAX];
		struct stat st;

		snprintf(path, sizeof(path), "%s/%s", DEVICE_DIR, entries[i]->d_name);
		free(entries[i]);
		if (stat(path, &st) != 0 || !S_ISCHR(st.st_mode))
			continue;
		paths[count++] = strdup(path);
	}
	free(entries);

	*count_out = count;
	return paths;
}

// --- Main ---

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [options] [device...]\n"
		"\n"
		"Stress, benchmark, and adversarial test for the SMC_MSG ioctl.\n"
		"With no device arguments, all devices in %s are tested.\n"
		"\n"
		"Options:\n"
		"  -i N   base iteration count (default 1000); benchmark and rapid\n"
		"         phases run 10*N, fork storm N/16, open/close churn N/2\n"
		"  -t N   worker thread count for multithreaded phases (default 8)\n"
		"  -m MS  base duration of timed phases in ms (default 500)\n"
		"  -h     show this help\n",
		prog, DEVICE_DIR);
}

int main(int argc, char *argv[])
{
	int opt;

	while ((opt = getopt(argc, argv, "i:t:m:h")) != -1) {
		switch (opt) {
		case 'i': g_iterations = atoi(optarg); break;
		case 't': g_threads = atoi(optarg); break;
		case 'm': g_duration_ms = atoi(optarg); break;
		case 'h': usage(argv[0]); return 0;
		default:  usage(argv[0]); return 1;
		}
	}

	if (g_iterations <= 0 || g_threads <= 0 || g_duration_ms <= 0) {
		fprintf(stderr, "Iterations, threads, and duration must be positive.\n");
		return 1;
	}

	char **devices;
	int n_devices;

	if (optind < argc) {
		devices = &argv[optind];
		n_devices = argc - optind;
	} else {
		devices = enumerate_devices(&n_devices);
		if (n_devices == 0) {
			fprintf(stderr, "No devices found in %s.\n", DEVICE_DIR);
			return 1;
		}
	}

	int tested = 0;
	for (int i = 0; i < n_devices; i++) {
		g_path = devices[i];
		if (i > 0)
			printf("\n");
		if (test_device() == 0)
			tested++;
	}

	int n = atomic_load(&g_anomalies);
	printf("\nDone. %d device(s) tested, %d skipped, %d anomalies.\n",
	       tested, n_devices - tested, n);
	if (tested == 0) {
		fprintf(stderr, "No devices were tested.\n");
		return 1;
	}
	return n == 0 ? 0 : 2;
}
