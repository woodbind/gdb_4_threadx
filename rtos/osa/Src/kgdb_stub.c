#include <string.h>
#include "trid_debug.h"
#include "tx_api.h"
#include "kgdb_mips.h"
#include "mips_inst.h"
#include "ptrace.h"
#include "eic.h"
#include "../../threadx/Src/tx_thread.h"

#define EPERM            1      /* Operation not permitted */
#define ENOENT           2      /* No such file or directory */
#define ESRCH            3      /* No such process */
#define EINTR            4      /* Interrupted system call */
#define EIO              5      /* I/O error */
#define ENXIO            6      /* No such device or address */
#define E2BIG            7      /* Argument list too long */
#define ENOEXEC          8      /* Exec format error */
#define EBADF            9      /* Bad file number */
#define ECHILD          10      /* No child processes */
#define EAGAIN          11      /* Try again */
#define ENOMEM          12      /* Out of memory */
#define EACCES          13      /* Permission denied */
#define EFAULT          14      /* Bad address */
#define ENOTBLK         15      /* Block device required */
#define EBUSY           16      /* Device or resource busy */
#define EEXIST          17      /* File exists */
#define EXDEV           18      /* Cross-device link */
#define ENODEV          19      /* No such device */
#define ENOTDIR         20      /* Not a directory */
#define EISDIR          21      /* Is a directory */
#define EINVAL          22      /* Invalid argument */
#define ENFILE          23      /* File table overflow */
#define EMFILE          24      /* Too many open files */
#define ENOTTY          25      /* Not a typewriter */
#define ETXTBSY         26      /* Text file busy */
#define EFBIG           27      /* File too large */
#define ENOSPC          28      /* No space left on device */
#define ESPIPE          29      /* Illegal seek */
#define EROFS           30      /* Read-only file system */
#define EMLINK          31      /* Too many links */
#define EPIPE           32      /* Broken pipe */
#define EDOM            33      /* Math argument out of domain of func */
#define ERANGE          34      /* Math result not representable */

struct die_args {
	struct pt_regs *regs;
	const char *str;
	long err;
};

enum die_val {
	DIE_OOPS = 1,
	DIE_FP,
	DIE_TRAP,
	DIE_RI,
	DIE_PAGE_FAULT,
	DIE_BREAK,
	DIE_SSTEPBP,
	DIE_MSAFP,
	DIE_UPROBE,
	DIE_UPROBE_XOL,
};

#define KGDB_HW_BREAKPOINT      1
#define BREAK_INSTR_SIZE        4
enum kgdb_bptype {
	BP_BREAKPOINT = 0,
	BP_HARDWARE_BREAKPOINT,
	BP_WRITE_WATCHPOINT,
	BP_READ_WATCHPOINT,
	BP_ACCESS_WATCHPOINT,
	BP_POKE_BREAKPOINT,
};

enum kgdb_bpstate {
	BP_UNDEFINED = 0,
	BP_REMOVED,
	BP_SET,
	BP_ACTIVE
};

struct kgdb_bkpt {
	unsigned long           bpt_addr;
	unsigned char           saved_instr[BREAK_INSTR_SIZE];
	enum kgdb_bptype        type;
	enum kgdb_bpstate       state;
};

struct dbg_reg_def_t {
	char *name;
	int size;
	int offset;
};

#define NOTIFY_DONE             0x0000          /* Don't care */
#define NOTIFY_OK               0x0001          /* Suits me */
#define NOTIFY_STOP_MASK        0x8000          /* Don't call further */
#define NOTIFY_BAD              (NOTIFY_STOP_MASK|0x0002)
/* Bad/Veto action */
#define NOTIFY_STOP             (NOTIFY_STOP_MASK|NOTIFY_OK)

/* Switch from one cpu to another */
#define DBG_SWITCH_CPU_EVENT -123456

#define DBG_MAX_REG_NUM 72
#define NUMREGBYTES             (DBG_MAX_REG_NUM * 4)
#define KGDB_GDB_REG_SIZE       32
#define GDB_SIZEOF_REG          sizeof(unsigned int)
/**
 * struct kgdb_arch - Describe architecture specific values.
 * @gdb_bpt_instr: The instruction to trigger a breakpoint.
 * @flags: Flags for the breakpoint, currently just %KGDB_HW_BREAKPOINT.
 * @set_breakpoint: Allow an architecture to specify how to set a software
 * breakpoint.
 * @remove_breakpoint: Allow an architecture to specify how to remove a
 * software breakpoint.
 * @set_hw_breakpoint: Allow an architecture to specify how to set a hardware
 * breakpoint.
 * @remove_hw_breakpoint: Allow an architecture to specify how to remove a
 * hardware breakpoint.
 * @disable_hw_break: Allow an architecture to specify how to disable
 * hardware breakpoints for a single cpu.
 * @remove_all_hw_break: Allow an architecture to specify how to remove all
 * hardware breakpoints.
 * @correct_hw_break: Allow an architecture to specify how to correct the
 * hardware debug registers.
 * @enable_nmi: Manage NMI-triggered entry to KGDB
 */
struct kgdb_arch {
	unsigned char           gdb_bpt_instr[BREAK_INSTR_SIZE];
	unsigned long           flags;

	int     (*set_breakpoint)(unsigned long, char *);
	int     (*remove_breakpoint)(unsigned long, char *);
	int     (*set_hw_breakpoint)(unsigned long, int, enum kgdb_bptype);
	int     (*remove_hw_breakpoint)(unsigned long, int, enum kgdb_bptype);
	void    (*disable_hw_break)(struct pt_regs *regs);
	void    (*remove_all_hw_break)(void);
	void    (*correct_hw_break)(void);

	void    (*enable_nmi)(int on);
};

/**
 * struct kgdb_io - Describe the interface for an I/O driver to talk with KGDB.
 * @name: Name of the I/O driver.
 * @read_char: Pointer to a function that will return one char.
 * @write_char: Pointer to a function that will write one char.
 * @flush: Pointer to a function that will flush any pending writes.
 * @init: Pointer to a function that will initialize the device.
 * @pre_exception: Pointer to a function that will do any prep work for
 * the I/O driver.
 * @post_exception: Pointer to a function that will do any cleanup work
 * for the I/O driver.
 * @is_console: 1 if the end device is a console 0 if the I/O device is
 * not a console
 */
struct kgdb_io {
	const char              *name;
	char                    (*read_char) (void);
	void                    (*write_char) (char);
	void                    (*flush) (void);
	int                     (*init) (void);
	void                    (*pre_exception) (void);
	void                    (*post_exception) (void);
	int                     is_console;
};

typedef struct {
	int counter;
} atomic_t;


/* kernel debug core data structures */
struct kgdb_state {
	int                     ex_vector;
	//int                     signo;
	int                     err_code;
	int                     cpu;
	int                     pass_exception;
	unsigned long           thr_query;
	unsigned long           threadid;
	long                    kgdb_usethreadid;
	struct pt_regs          *linux_regs;
	atomic_t                *send_ready;
};

/* Exception state values */
#define DCPU_WANT_MASTER 0x1 /* Waiting to become a master kgdb cpu */
#define DCPU_NEXT_MASTER 0x2 /* Transition from one master cpu to another */
#define DCPU_IS_SLAVE    0x4 /* Slave cpu enter exception */
#define DCPU_SSTEP       0x8 /* CPU is single stepping */

struct debuggerinfo_struct {
	void                    *debuggerinfo;
	TX_THREAD               *task;
	int                     exception_state;
	int                     ret_state;
	//int                     irq_depth;
	int                     enter_kgdb;
};

struct debuggerinfo_struct kgdb_info[1];


#define __sync()                            \
	__asm__ __volatile__(                   \
			".set   push\n\t"               \
			".set   noreorder\n\t"          \
			".set   mips2\n\t"              \
			"sync\n\t"                      \
			".set   pop"                    \
			: /* no output */               \
			: /* no input */                \
			: "memory")

#define wmb()     __sync()
#define rmb()     __sync()

/*
 * atomic_read - read atomic variable
 * @v: pointer of type atomic_t
 *
 * Atomically reads the value of @v.  Note that the guaranteed
 * useful range of an atomic_t is only 24 bits.
 */
#define atomic_read(v)	((v)->counter)

/*
 * atomic_set - set atomic variable
 * @v: pointer of type atomic_t
 * @i: required value
 *
 * Atomically sets the value of @v to @i.  Note that the guaranteed
 * useful range of an atomic_t is only 24 bits.
 */
#define atomic_set(v,i)	((v)->counter = (i))

/*
 * atomic_add - add integer to atomic variable
 * @i: integer value to add
 * @v: pointer of type atomic_t
 *
 * Atomically adds @i to @v.  Note that the guaranteed useful range
 * of an atomic_t is only 24 bits.
 */
__inline__ void atomic_add(int i, atomic_t * v)
{
	unsigned long temp;

	__asm__ __volatile__(
			"1:   ll      %0, %1      # atomic_add\n"
			"     addu    %0, %2                  \n"
			"     sc      %0, %1                  \n"
			"     beqz    %0, 1b                  \n"
			: "=&r" (temp), "=m" (v->counter)
			: "Ir" (i), "m" (v->counter));
}

/*
 * atomic_sub - subtract the atomic variable
 * @i: integer value to subtract
 * @v: pointer of type atomic_t
 *
 * Atomically subtracts @i from @v.  Note that the guaranteed
 * useful range of an atomic_t is only 24 bits.
 */
__inline__ void atomic_sub(int i, atomic_t * v)
{
	unsigned long temp;

	__asm__ __volatile__(
			"1:   ll      %0, %1      # atomic_sub\n"
			"     subu    %0, %2                  \n"
			"     sc      %0, %1                  \n"
			"     beqz    %0, 1b                  \n"
			: "=&r" (temp), "=m" (v->counter)
			: "Ir" (i), "m" (v->counter));
}

#define atomic_dec(v) atomic_sub(1,(v))
#define atomic_inc(v) atomic_add(1,(v))

static inline void local_irq_disable(void)
{
	__asm__ __volatile__(
			"       .set    push                                            \n"
			"       .set    noat                                            \n"
			"       di                                                      \n"
			"       ssnop                                                   \n"
			"       ssnop                                                   \n"
			"       sync                                                    \n"
			"       ehb                                                     \n"
			"       .set    pop                                             \n"
			: /* no outputs */
			: /* no inputs */
			: "memory");
}

static inline unsigned long local_irq_save(void)
{
	unsigned long flags;

	asm __volatile__(
			"       .set    push                                            \n"
			"       .set    reorder                                         \n"
			"       .set    noat                                            \n"
			"       di      %[flags]                                        \n"
			"       andi    %[flags], 1                                     \n"
			"       ssnop                                                   \n"
			"       ssnop                                                   \n"
			"       sync                                                    \n"
			"       ehb                                                     \n"
			"       .set    pop                                             \n"
			: [flags] "=r" (flags)
			: /* no inputs */
			: "memory");

	return flags;
}

static inline void local_irq_restore(unsigned long flags)
{
	unsigned long __tmp1;

	__asm__ __volatile__(
			"       .set    push                                            \n"
			"       .set    noreorder                                       \n"
			"       .set    noat                                            \n"
			/*
			 * Slow, but doesn't suffer from a relatively unlikely race
			 * condition we're having since days 1.
			 */
			"       beqz    %[flags], 1f                                    \n"
			"       di                                                      \n"
			"       ei                                                      \n"
			"1:                                                             \n"
			"       ssnop                                                   \n"
			"       ssnop                                                   \n"
			"       sync                                                    \n"
			"       ehb                                                     \n"
			"       .set    pop                                             \n"
			: /* no outputs */
			: [flags] "r" (flags)
			: "memory");
}

static inline void local_irq_enable(void)
{
	__asm__ __volatile__(
			"       .set    push                                            \n"
			"       .set    reorder                                         \n"
			"       .set    noat                                            \n"
			"       ei                                                      \n"
			"       ssnop                                                   \n"
			"       ssnop                                                   \n"
			"       sync                                                    \n"
			"       ehb                                                     \n"
			"       .set    pop                                             \n"
			: /* no outputs */
			: /* no inputs */
			: "memory");
}

void __attribute__((noinline)) arch_kgdb_breakpoint(void)
{
	__asm__ __volatile__(
			".globl breakinst\n\t"
			".set\tnoreorder\n\t"
			"nop\n"
			"breakinst:\tbreak\n\t"
			"nop\n\t"
			".set\treorder");
}

/*
 * Macros to access the system control coprocessor
 */

#define __read_32bit_c0_register(source, sel)                           \
	({ unsigned int __res;                                                  \
	 if (sel == 0)                                                   \
	 __asm__ __volatile__(                                   \
		 "mfc0\t%0, " #source "\n\t"                     \
		 : "=r" (__res));                                \
	 else                                                            \
	 __asm__ __volatile__(                                   \
		 ".set\tmips32\n\t"                              \
		 "mfc0\t%0, " #source ", " #sel "\n\t"           \
		 ".set\tmips0\n\t"                               \
		 : "=r" (__res));                                \
	 __res;                                                          \
	 })

#define __write_32bit_c0_register(register, sel, value)                 \
	do {                                                                    \
		if (sel == 0)                                                   \
		__asm__ __volatile__(                                   \
				"mtc0\t%z0, " #register "\n\t"                  \
				: : "Jr" ((unsigned int)(value)));              \
		else                                                            \
		__asm__ __volatile__(                                   \
				".set\tmips32\n\t"                              \
				"mtc0\t%z0, " #register ", " #sel "\n\t"        \
				".set\tmips0"                                   \
				: : "Jr" ((unsigned int)(value)));              \
	} while (0)

/*
 * The WatchLo register.  There may be up to 8 of them.
 */
#define read_c0_watchlo0()      __read_32bit_c0_register($18, 0)
#define read_c0_watchlo1()      __read_32bit_c0_register($18, 1)
#define read_c0_watchlo2()      __read_32bit_c0_register($18, 2)
#define read_c0_watchlo3()      __read_32bit_c0_register($18, 3)
#define write_c0_watchlo0(val)  __write_32bit_c0_register($18, 0, val)
#define write_c0_watchlo1(val)  __write_32bit_c0_register($18, 1, val)
#define write_c0_watchlo2(val)  __write_32bit_c0_register($18, 2, val)
#define write_c0_watchlo3(val)  __write_32bit_c0_register($18, 3, val)

/*
 * The WatchHi register.  There may be up to 8 of them.
 */
#define read_c0_watchhi0()      __read_32bit_c0_register($19, 0)
#define read_c0_watchhi1()      __read_32bit_c0_register($19, 1)
#define read_c0_watchhi2()      __read_32bit_c0_register($19, 2)
#define read_c0_watchhi3()      __read_32bit_c0_register($19, 3)

#define write_c0_watchhi0(val)  __write_32bit_c0_register($19, 0, val)
#define write_c0_watchhi1(val)  __write_32bit_c0_register($19, 1, val)
#define write_c0_watchhi2(val)  __write_32bit_c0_register($19, 2, val)
#define write_c0_watchhi3(val)  __write_32bit_c0_register($19, 3, val)

/* For hw watchpoint break */
#define HBP_NUM 4
static struct hw_breakpoint {
	unsigned                enabled;
	unsigned long           addr;
	int                     len;
	int                     type;
} breakinfo[HBP_NUM];

#define NUM_WATCH_REGS 4
struct mips3264_watch_reg_state {
	/* The width of watchlo is 32 in a 32 bit kernel and 64 in a
	   64 bit kernel.  We use unsigned long as it has the same
	   property. */
	unsigned long  watchlo[NUM_WATCH_REGS];
	/* Only the mask and IRW bits from watchhi. */
	unsigned short watchhi[NUM_WATCH_REGS];
} watch_mips3264;

#define _ULCAST_ (unsigned long)
/* WatchLo* register definitions */
#define MIPS_WATCHLO_IRW        (_ULCAST_(0x7) << 0)

/* WatchHi* register definitions */
#define MIPS_WATCHHI_M          (_ULCAST_(1) << 31)
#define MIPS_WATCHHI_G          (_ULCAST_(1) << 30)
#define MIPS_WATCHHI_WM         (_ULCAST_(0x3) << 28)
#define MIPS_WATCHHI_WM_R_RVA   (_ULCAST_(0) << 28)
#define MIPS_WATCHHI_WM_R_GPA   (_ULCAST_(1) << 28)
#define MIPS_WATCHHI_WM_G_GVA   (_ULCAST_(2) << 28)
#define MIPS_WATCHHI_EAS        (_ULCAST_(0x3) << 24)
#define MIPS_WATCHHI_ASID       (_ULCAST_(0xff) << 16)
#define MIPS_WATCHHI_MASK       (_ULCAST_(0x1ff) << 3)
#define MIPS_WATCHHI_I          (_ULCAST_(1) << 2)
#define MIPS_WATCHHI_R          (_ULCAST_(1) << 1)
#define MIPS_WATCHHI_W          (_ULCAST_(1) << 0)
#define MIPS_WATCHHI_IRW        (_ULCAST_(0x7) << 0)

/*
 * Install the watch registers for the current thread.  A maximum of
 * four registers are installed although the machine may have more.
 */
void mips_install_watch_registers()
{
	struct mips3264_watch_reg_state *watches = &watch_mips3264;
#if 1
	if (watches->watchlo[3] != 0) {
		write_c0_watchlo3(watches->watchlo[3]);
		/* Write 1 to the I, R, and W bits to clear them, and
		   1 to G so all ASIDs are trapped. */
		write_c0_watchhi3(MIPS_WATCHHI_G | MIPS_WATCHHI_IRW | watches->watchhi[3]);
	}
	if (watches->watchlo[2] != 0) {
		write_c0_watchlo2(watches->watchlo[2]);
		write_c0_watchhi2(MIPS_WATCHHI_G | MIPS_WATCHHI_IRW | watches->watchhi[2]);
	}
	if (watches->watchlo[1] != 0) {
		write_c0_watchlo1(watches->watchlo[1]);
		write_c0_watchhi1(MIPS_WATCHHI_G | MIPS_WATCHHI_IRW | watches->watchhi[1]);
	}
	if (watches->watchlo[0] != 0) {
		write_c0_watchlo0(watches->watchlo[0]);
		write_c0_watchhi0(MIPS_WATCHHI_G | MIPS_WATCHHI_IRW | watches->watchhi[0]);
	}
#endif
	//write_c0_watchlo2(watches->watchlo[0]|MIPS_WATCHLO_IRW);
	//write_c0_watchhi2(MIPS_WATCHHI_G | MIPS_WATCHHI_IRW | watches->watchhi[0]);
	Trid_Print("watchlo0=0x%x,watchhi0=0x%x\n",read_c0_watchlo0(), read_c0_watchhi0());
	Trid_Print("watchlo1=0x%x,watchhi1=0x%x\n",read_c0_watchlo1(), read_c0_watchhi1());
	Trid_Print("watchlo2=0x%x,watchhi2=0x%x\n",read_c0_watchlo2(), read_c0_watchhi2());
	Trid_Print("watchlo3=0x%x,watchhi3=0x%x\n",read_c0_watchlo3(), read_c0_watchhi3());
}

/*
 * Read back the watchhi registers so the user space debugger has
 * access to the I, R, and W bits.  A maximum of four registers are
 * read although the machine may have more.
 */
void mips_read_watch_registers(void)
{
	struct mips3264_watch_reg_state *watches = &watch_mips3264;
	watches->watchhi[3] = (read_c0_watchhi3() &
			(MIPS_WATCHHI_MASK | MIPS_WATCHHI_IRW));
	watches->watchhi[2] = (read_c0_watchhi2() &
			(MIPS_WATCHHI_MASK | MIPS_WATCHHI_IRW));
	watches->watchhi[1] = (read_c0_watchhi1() &
			(MIPS_WATCHHI_MASK | MIPS_WATCHHI_IRW));
	watches->watchhi[0] = (read_c0_watchhi0() &
			(MIPS_WATCHHI_MASK | MIPS_WATCHHI_IRW));
}

/*
 * Disable all watch registers.  Although only four registers are
 * installed, all are cleared to eliminate the possibility of endless
 * looping in the watch handler.
 */
void mips_clear_watch_registers(int slot)
{
	switch (slot) {
		case 3:
			write_c0_watchlo3(0);
			break;
		case 2:
			write_c0_watchlo2(0);
			break;
		case 1:
			write_c0_watchlo1(0);
			break;
		case 0:
			write_c0_watchlo0(0);
			break;
	}
}

int arch_install_hw_breakpoint(int slot)
{
	int i;
	struct mips3264_watch_reg_state *watches = &watch_mips3264;
	/* only watch[2]&[3] is for data access */
#if 1
	for (i = 0; i < NUM_WATCH_REGS; i++) {
		if (slot ==	i) {
			watches->watchlo[i] = breakinfo[slot].addr|(breakinfo[slot].type-1);
			break;
		}
	}
	//Trid_Print("install breakpoint slot%d\n", slot);
	if (i == HBP_NUM) {
		Trid_Print("Can't find any breakpoint slot");
		return -EBUSY;
	}
#endif
	//watches->watchlo[0] = breakinfo[slot].addr;
	mips_install_watch_registers();

	return 0;
}

void arch_uninstall_hw_breakpoint(int slot)
{
	int i;
	struct mips3264_watch_reg_state *watches = &watch_mips3264;

	for (i = 0; i < NUM_WATCH_REGS; i++) {
		if (slot == i) {
			watches->watchlo[i] = 0;
			break;
		}
	}

	if (i == HBP_NUM) {
		Trid_Print("Can't find any breakpoint slot");
	}

	mips_clear_watch_registers(slot);
	//mips_clear_watch_registers(2);
}

static int kgdb_remove_hw_break(unsigned long addr, int len, enum kgdb_bptype bptype)
{
	int i;

	for (i = 0; i < HBP_NUM; i++)
		if (breakinfo[i].addr == addr && breakinfo[i].enabled)
			break;
	if (i == HBP_NUM)
		return -1;

	//arch_uninstall_hw_breakpoint(i);
	breakinfo[i].enabled = 0;

	return 0;
}

static void kgdb_remove_all_hw_break(void)
{
	int i;

	for (i = 0; i < HBP_NUM; i++) {
		if (!breakinfo[i].enabled)
			continue;
		arch_uninstall_hw_breakpoint(i);
		breakinfo[i].enabled = 0;
	}
}

static int kgdb_set_hw_break(unsigned long addr, int len, enum kgdb_bptype bptype)
{
	int i;

	for (i = 2; i < HBP_NUM; i++) /* only 2&3 is usable for data access on mips24k */
		if (!breakinfo[i].enabled)
			break;
	if (i == HBP_NUM)
		return -1;

	switch (bptype) {
		case BP_HARDWARE_BREAKPOINT: /* not supported */
			breakinfo[i].type = BP_HARDWARE_BREAKPOINT;
			break;
		case BP_WRITE_WATCHPOINT: /* no use */
			breakinfo[i].type = BP_WRITE_WATCHPOINT;
			break;
		case BP_READ_WATCHPOINT:  /* for rwatch */
			breakinfo[i].type = BP_READ_WATCHPOINT;
			break;
		case BP_ACCESS_WATCHPOINT: /*for watch & awatch */
			breakinfo[i].type = BP_ACCESS_WATCHPOINT;
			break;
		default:
			return -1;
	}
	switch (len) {
		case 1:
			breakinfo[i].len = 1;
			break;
		case 2:
			breakinfo[i].len = 2;
			break;
		case 4:
			breakinfo[i].len = 4;
			break;
		default:
			return -1;
	}
	breakinfo[i].addr = addr;
	breakinfo[i].enabled = 1;

	return 0;
}

static void kgdb_disable_hw_debug(struct pt_regs *regs)
{
	int i;

	/* Disable hardware debugging while we are in kgdb: */
	for (i = 0; i < HBP_NUM; i++) {
		if (!breakinfo[i].enabled)
			continue;
		arch_uninstall_hw_breakpoint(i);
	}
}

static void kgdb_correct_hw_break(void)
{
	int breakno;

	for (breakno = 0; breakno < HBP_NUM; breakno++) {
		int val;
		if (!breakinfo[breakno].enabled)
			continue;
		val = arch_install_hw_breakpoint(breakno);
		//if (!val)
		//	bp->attr.disabled = 0;
	}
}

/* kgdb entry */
extern unsigned char except_vec3_generic;
extern unsigned char __ram_excpt_base;
extern void breakinst(void);
int vec3_installed = 0;
atomic_t  kgdb_setting_breakpoint;

static TX_THREAD                *kgdb_sstep_pid;

TX_THREAD              *kgdb_usethread;
TX_THREAD              *kgdb_contthread;

atomic_t                        kgdb_active = {-1};
atomic_t                        kgdb_cpu_doing_single_step = {-1};
static atomic_t                 masters_in_kgdb;
static atomic_t                 slaves_in_kgdb;

int                             kgdb_single_step;
struct kgdb_io          		*dbg_io_ops;
int                             kgdb_connected;
/* Guard for recursive entry */
static int                      exception_level;
struct kgdb_arch arch_kgdb_ops;

extern TX_THREAD* _tx_thread_identify_safe(void);

extern char Trid_GetChar(void);
extern void Trid_PutChar(char);
static struct kgdb_io kgdboc_io_ops = {
	.name                   = "kgdboc",
	.read_char              = Trid_GetChar,
	.write_char             = Trid_PutChar,
	.pre_exception          = 0,//kgdboc_pre_exp_handler,
	.post_exception         = 0,//kgdboc_post_exp_handler,
};

/* Our I/O buffers. */
#define BUFMAX                  2048
static char                     remcom_in_buffer[BUFMAX];
static char                     remcom_out_buffer[BUFMAX];

/* Storage for the registers, in GDB format. */
static unsigned long            gdb_regs[(NUMREGBYTES +
		sizeof(unsigned long) - 1) /
sizeof(unsigned long)];

struct dbg_reg_def_t dbg_reg_def[DBG_MAX_REG_NUM] =
{
	{ "zero", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[0]) },
	{ "at", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[1]) },
	{ "v0", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[2]) },
	{ "v1", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[3]) },
	{ "a0", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[4]) },
	{ "a1", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[5]) },
	{ "a2", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[6]) },
	{ "a3", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[7]) },
	{ "t0", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[8]) },
	{ "t1", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[9]) },
	{ "t2", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[10]) },
	{ "t3", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[11]) },
	{ "t4", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[12]) },
	{ "t5", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[13]) },
	{ "t6", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[14]) },
	{ "t7", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[15]) },
	{ "s0", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[16]) },
	{ "s1", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[17]) },
	{ "s2", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[18]) },
	{ "s3", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[19]) },
	{ "s4", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[20]) },
	{ "s5", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[21]) },
	{ "s6", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[22]) },
	{ "s7", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[23]) },
	{ "t8", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[24]) },
	{ "t9", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[25]) },
	{ "k0", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[26]) },
	{ "k1", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[27]) },
	{ "gp", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[28]) },
	{ "sp", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[29]) },
	{ "s8", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[30]) },
	{ "ra", GDB_SIZEOF_REG, offsetof(struct pt_regs, regs[31]) },
	{ "sr", GDB_SIZEOF_REG, offsetof(struct pt_regs, cp0_status) },
	{ "lo", GDB_SIZEOF_REG, offsetof(struct pt_regs, lo) },
	{ "hi", GDB_SIZEOF_REG, offsetof(struct pt_regs, hi) },
	{ "bad", GDB_SIZEOF_REG, offsetof(struct pt_regs, cp0_badvaddr) },
	{ "cause", GDB_SIZEOF_REG, offsetof(struct pt_regs, cp0_cause) },
	{ "pc", GDB_SIZEOF_REG, offsetof(struct pt_regs, cp0_epc) },
	{ "f0", GDB_SIZEOF_REG, 0 },
	{ "f1", GDB_SIZEOF_REG, 1 },
	{ "f2", GDB_SIZEOF_REG, 2 },
	{ "f3", GDB_SIZEOF_REG, 3 },
	{ "f4", GDB_SIZEOF_REG, 4 },
	{ "f5", GDB_SIZEOF_REG, 5 },
	{ "f6", GDB_SIZEOF_REG, 6 },
	{ "f7", GDB_SIZEOF_REG, 7 },
	{ "f8", GDB_SIZEOF_REG, 8 },
	{ "f9", GDB_SIZEOF_REG, 9 },
	{ "f10", GDB_SIZEOF_REG, 10 },
	{ "f11", GDB_SIZEOF_REG, 11 },
	{ "f12", GDB_SIZEOF_REG, 12 },
	{ "f13", GDB_SIZEOF_REG, 13 },
	{ "f14", GDB_SIZEOF_REG, 14 },
	{ "f15", GDB_SIZEOF_REG, 15 },
	{ "f16", GDB_SIZEOF_REG, 16 },
	{ "f17", GDB_SIZEOF_REG, 17 },
	{ "f18", GDB_SIZEOF_REG, 18 },
	{ "f19", GDB_SIZEOF_REG, 19 },
	{ "f20", GDB_SIZEOF_REG, 20 },
	{ "f21", GDB_SIZEOF_REG, 21 },
	{ "f22", GDB_SIZEOF_REG, 22 },
	{ "f23", GDB_SIZEOF_REG, 23 },
	{ "f24", GDB_SIZEOF_REG, 24 },
	{ "f25", GDB_SIZEOF_REG, 25 },
	{ "f26", GDB_SIZEOF_REG, 26 },
	{ "f27", GDB_SIZEOF_REG, 27 },
	{ "f28", GDB_SIZEOF_REG, 28 },
	{ "f29", GDB_SIZEOF_REG, 29 },
	{ "f30", GDB_SIZEOF_REG, 30 },
	{ "f31", GDB_SIZEOF_REG, 31 },
	{ "fsr", GDB_SIZEOF_REG, 0 },
	{ "fir", GDB_SIZEOF_REG, 0 },
};

int dbg_set_reg(int regno, void *mem, struct pt_regs *regs)
{
	int fp_reg;

	if (regno < 0 || regno >= DBG_MAX_REG_NUM)
		return -EINVAL;

	if (dbg_reg_def[regno].offset != -1 && regno < 38) {
		memcpy((void *)regs + dbg_reg_def[regno].offset, mem,
				dbg_reg_def[regno].size);
	} else if (_tx_thread_identify_safe() && dbg_reg_def[regno].offset != -1 && regno < 72) {
#if 0
		/* FP registers 38 -> 69 */
		if (!(regs->cp0_status & ST0_CU1))
			return 0;
		if (regno == 70) {
			/* Process the fcr31/fsr (register 70) */
			memcpy((void *)&current->thread.fpu.fcr31, mem,
					dbg_reg_def[regno].size);
			goto out_save;
		} else if (regno == 71) {
			/* Ignore the fir (register 71) */
			goto out_save;
		}
		fp_reg = dbg_reg_def[regno].offset;
		memcpy((void *)&current->thread.fpu.fpr[fp_reg], mem,
				dbg_reg_def[regno].size);
out_save:
		restore_fp(current);
#endif
	}

	return 0;
}

char *dbg_get_reg(int regno, void *mem, struct pt_regs *regs)
{
	int fp_reg;

	if (regno >= DBG_MAX_REG_NUM || regno < 0)
		return NULL;

	if (dbg_reg_def[regno].offset != -1 && regno < 38) {
		/* First 38 registers */
		memcpy(mem, (void *)regs + dbg_reg_def[regno].offset,
				dbg_reg_def[regno].size);
	} else if (_tx_thread_identify_safe() && dbg_reg_def[regno].offset != -1 && regno < 72) {
		/* FP registers 38 -> 69 */
#if 0
		if (!(regs->cp0_status & ST0_CU1))
			goto out;
		save_fp(current);
		if (regno == 70) {
			/* Process the fcr31/fsr (register 70) */
			memcpy(mem, (void *)&current->thread.fpu.fcr31,
					dbg_reg_def[regno].size);
			goto out;
		} else if (regno == 71) {
			/* Ignore the fir (register 71) */
			memset(mem, 0, dbg_reg_def[regno].size);
			goto out;
		}
		fp_reg = dbg_reg_def[regno].offset;
		memcpy(mem, (void *)&current->thread.fpu.fpr[fp_reg],
				dbg_reg_def[regno].size);
#endif
	}

out:
	return dbg_reg_def[regno].name;

}

#if DBG_MAX_REG_NUM > 0
void pt_regs_to_gdb_regs(unsigned long *gdb_regs, struct pt_regs *regs)
{
	int i;
	int idx = 0;
	char *ptr = (char *)gdb_regs;

	for (i = 0; i < DBG_MAX_REG_NUM; i++) {
		dbg_get_reg(i, ptr + idx, regs);
		idx += dbg_reg_def[i].size;
	}
}

void gdb_regs_to_pt_regs(unsigned long *gdb_regs, struct pt_regs *regs)
{
	int i;
	int idx = 0;
	char *ptr = (char *)gdb_regs;

	for (i = 0; i < DBG_MAX_REG_NUM; i++) {
		dbg_set_reg(i, ptr + idx, regs);
		idx += dbg_reg_def[i].size;
	}
}
#endif /* DBG_MAX_REG_NUM > 0 */

static void sysrq_handle_dbg(int key)
{
	if (!dbg_io_ops) {
		Trid_Print("ERROR: No KGDB I/O module available\n");
		return;
	}
	if (!kgdb_connected) {
		Trid_Print("Entering KGDB\n");
	}

	//kgdb_breakpoint();
	atomic_inc(&kgdb_setting_breakpoint);
	wmb(); /* Sync point before breakpoint */
	arch_kgdb_breakpoint();
	wmb(); /* Sync point after breakpoint */
	atomic_dec(&kgdb_setting_breakpoint);
}

void kgdb_sysrq(void) {
	EicDisableInt(19);
	EicClearInt(19);
	char ch;
	UartspiReceive(&ch);
	// Trid_Print("sysrq get, ch=%x\n", ch);
	if (ch==0x3) sysrq_handle_dbg((int)ch); /* crtl+c */
	//atomic_inc(&kgdb_setting_breakpoint);
	//wmb(); /* Sync point before breakpoint */
	//     arch_kgdb_breakpoint();
	//   wmb(); /* Sync point after breakpoint */
	//atomic_dec(&kgdb_setting_breakpoint);
	EicEnableInt(19);
}


#define CACHE_INVALIDATE(addr, size)                               \
{                                                                           \
	unsigned long end_addr = (size) + (unsigned long)(addr);                     \
	unsigned long curr_addr = (unsigned long)(addr);                             \
	do {                                                                    \
		/* Invalidate valid instruction cache */                            \
		ESAL_TS_RTE_CACHE_EXECUTE(0x10, curr_addr); \
		ESAL_TS_RTE_CACHE_EXECUTE(0x11, curr_addr); \
		\
		/* Move to next line */                                             \
		curr_addr += 32;                           \
	} while (curr_addr <= end_addr);                                        \
}

int kgdb_arch_init(void)
{
	/*union mips_instruction insn = {
	  .r_format = {
	  .opcode = spec_op,
	  .func   = break_op,
	  }
	  };*/
	//unsigned long insn = 0x0D000000; //TODO :hard coded 
	unsigned long insn = 0x0000000d; //TODO :hard coded 
	//memcpy(arch_kgdb_ops.gdb_bpt_instr, insn.byte, BREAK_INSTR_SIZE);
	memcpy(arch_kgdb_ops.gdb_bpt_instr, breakinst, BREAK_INSTR_SIZE);
	arch_kgdb_ops.set_hw_breakpoint    = kgdb_set_hw_break;
	arch_kgdb_ops.remove_hw_breakpoint = kgdb_remove_hw_break;
	arch_kgdb_ops.remove_all_hw_break  = kgdb_remove_all_hw_break;
	arch_kgdb_ops.disable_hw_break     = kgdb_disable_hw_debug;
	arch_kgdb_ops.correct_hw_break     = kgdb_correct_hw_break;

	return 0;
}

void kgdb_breakpoint(void)
{
	if (!vec3_installed) { /* TODO move to suitable place */
		void *vec3_addr = memcpy((void *)(&__ram_excpt_base + 0x180), (const void *)(&except_vec3_generic), 0x80);
		vec3_installed = 1;
		//wmb();
		//CACHE_INVALIDATE(vec3_addr, 0x80);
		Trid_Print("copy vec3 to %x\n", vec3_addr);

		int i;
		for (i = 0; i < 0x80; i += 16) {
			unsigned int* p = (unsigned int*)vec3_addr + (i/4);
			Trid_Print("0x%08x: 0x%08x 0x%08x 0x%08x 0x%08x", vec3_addr + i, *p, *(p + 1), *(p + 2), *(p + 3));
		}

		Trid_Print("Waiting for connection from remote gdb...\n");
		dbg_io_ops = &kgdboc_io_ops;
		kgdb_arch_init();
		UartspiConfig(0x220, 0x68);
		//WriteReg(0x19e00010, 1);
		EicSetIntSrc(19, 13, 1, 0, 0, kgdb_sysrq);
		EicEnableInt(19);
		Trid_Setkgdbcons(1);
	}

	atomic_inc(&kgdb_setting_breakpoint);
	wmb(); /* Sync point before breakpoint */
	arch_kgdb_breakpoint();
	wmb(); /* Sync point after breakpoint */
	atomic_dec(&kgdb_setting_breakpoint);
}


/*
 * SW breakpoint management:
 */
# define KGDB_MAX_BREAKPOINTS   1000
/*
 * Holds information about breakpoints in a kernel. These breakpoints are
 * added and removed by gdb.
 */
static struct kgdb_bkpt         kgdb_break[KGDB_MAX_BREAKPOINTS] = {
	[0 ... KGDB_MAX_BREAKPOINTS-1] = { .state = BP_UNDEFINED }
};

int kgdb_arch_set_breakpoint(struct kgdb_bkpt *bpt)
{
	int err = 0;

	memcpy(bpt->saved_instr, (char *)bpt->bpt_addr, BREAK_INSTR_SIZE);//cached write
	memcpy((char *)((unsigned long)bpt->saved_instr|0xa0000000), (char *)bpt->bpt_addr, BREAK_INSTR_SIZE);//uncached write
	memcpy((char *)bpt->bpt_addr, arch_kgdb_ops.gdb_bpt_instr, BREAK_INSTR_SIZE);
	memcpy((char *)(bpt->bpt_addr|0xa0000000), arch_kgdb_ops.gdb_bpt_instr, BREAK_INSTR_SIZE);

	// unsigned int* p = (unsigned int*)(bpt->bpt_addr|0xa0000000);
	// Trid_Print("bpt->bpt_addr:0x%08x: c:0x%08x, uc:0x%08x\n", bpt->bpt_addr, *(unsigned int*)(bpt->bpt_addr), *p );


	// p = (unsigned int*)bpt->saved_instr;
	// Trid_Print("bpt->saved_instr:0x%08x: 0x%08x\n", bpt->saved_instr, *p);
	wmb();

	return err;
}

int kgdb_arch_remove_breakpoint(struct kgdb_bkpt *bpt)
{
	memcpy((char *)bpt->bpt_addr, (char *)bpt->saved_instr, BREAK_INSTR_SIZE);
	memcpy((char *)(bpt->bpt_addr|0xa0000000), (char *)bpt->saved_instr, BREAK_INSTR_SIZE);
	wmb();
	return 0;
}

int kgdb_validate_break_address(unsigned long addr)
{
	struct kgdb_bkpt tmp;
	int err;
	/* Validate setting the breakpoint and then removing it.  If the
	 * remove fails, the kernel needs to emit a bad message because we
	 * are deep trouble not being able to put things back the way we
	 * found them.
	 */
	tmp.bpt_addr = addr;
	err = kgdb_arch_set_breakpoint(&tmp);
	if (err)
		return err;
	err = kgdb_arch_remove_breakpoint(&tmp);
	if (err)
		Trid_Print("Critical breakpoint error, kernel memory destroyed at: %lx\n", addr);
	return err;
}

int dbg_activate_sw_breakpoints(void)
{
	int error;
	int ret = 0;
	int i;
	for (i = 0; i < KGDB_MAX_BREAKPOINTS; i++) {
		if (kgdb_break[i].state != BP_SET)
			continue;

		error = kgdb_arch_set_breakpoint(&kgdb_break[i]);
		if (error) {
			ret = error;
			Trid_Print("BP install failed: %lx\n",
					kgdb_break[i].bpt_addr);
			continue;
		}

		kgdb_break[i].state = BP_ACTIVE;
	}
	return ret;
}

int dbg_set_sw_break(unsigned long addr)
{
	int err = kgdb_validate_break_address(addr);
	int breakno = -1;
	int i;

	if (err)
		return err;

	for (i = 0; i < KGDB_MAX_BREAKPOINTS; i++) {
		if ((kgdb_break[i].state == BP_SET) &&
				(kgdb_break[i].bpt_addr == addr))
			return -EEXIST;
	}
	for (i = 0; i < KGDB_MAX_BREAKPOINTS; i++) {
		if (kgdb_break[i].state == BP_REMOVED &&
				kgdb_break[i].bpt_addr == addr) {
			breakno = i;
			break;
		}
	}

	if (breakno == -1) {
		for (i = 0; i < KGDB_MAX_BREAKPOINTS; i++) {
			if (kgdb_break[i].state == BP_UNDEFINED) {
				breakno = i;
				break;
			}
		}
	}

	if (breakno == -1)
		return -E2BIG;

	kgdb_break[breakno].state = BP_SET;
	kgdb_break[breakno].type = BP_BREAKPOINT;
	kgdb_break[breakno].bpt_addr = addr;

	return 0;
}

int dbg_deactivate_sw_breakpoints(void)
{
	int error;
	int ret = 0;
	int i;

	for (i = 0; i < KGDB_MAX_BREAKPOINTS; i++) {
		if (kgdb_break[i].state != BP_ACTIVE)
			continue;
		error = kgdb_arch_remove_breakpoint(&kgdb_break[i]);
		if (error) {
			Trid_Print("BP remove failed: %lx\n",
					kgdb_break[i].bpt_addr);
			ret = error;
		}

		kgdb_break[i].state = BP_SET;
	}
	return ret;
}

int dbg_remove_sw_break(unsigned long addr)
{
	int i;

	for (i = 0; i < KGDB_MAX_BREAKPOINTS; i++) {
		if ((kgdb_break[i].state == BP_SET) &&
				(kgdb_break[i].bpt_addr == addr)) {
			kgdb_break[i].state = BP_REMOVED;
			return 0;
		}
	}
	return -ENOENT;
}

int kgdb_isremovedbreak(unsigned long addr)
{
	int i;

	for (i = 0; i < KGDB_MAX_BREAKPOINTS; i++) {
		if ((kgdb_break[i].state == BP_REMOVED) &&
				(kgdb_break[i].bpt_addr == addr))
			return 1;
	}
	return 0;
}

int dbg_remove_all_break(void)
{
	int error;
	int i;

	/* Clear memory breakpoints. */
	for (i = 0; i < KGDB_MAX_BREAKPOINTS; i++) {
		if (kgdb_break[i].state != BP_ACTIVE)
			goto setundefined;
		error = kgdb_arch_remove_breakpoint(&kgdb_break[i]);
		if (error)
			Trid_Print("breakpoint remove failed: %lx\n", kgdb_break[i].bpt_addr);
setundefined:
		kgdb_break[i].state = BP_UNDEFINED;
	}

	/* Clear hardware breakpoints. */
	if (arch_kgdb_ops.remove_all_hw_break)
		arch_kgdb_ops.remove_all_hw_break();

	return 0;
}

const char hex_asc[] = "0123456789abcdef";
#define hex_asc_lo(x)   hex_asc[((x) & 0x0f)]
#define hex_asc_hi(x)   hex_asc[((x) & 0xf0) >> 4]

static inline char *hex_byte_pack(char *buf, unsigned char byte)
{
	*buf++ = hex_asc_hi(byte);
	*buf++ = hex_asc_lo(byte);
	return buf;
}

static inline char tolower(const char c)
{
	if (c >= 'A' && c <= 'Z')
		return c | 0x20;
	else
		return c;
}

int hex_to_bin(char ch)
{
	//if ((ch >= '') && (ch <= '9'))
	if (ch <= '9')
		return ch - '0';
	ch = tolower(ch);
	if ((ch >= 'a') && (ch <= 'f'))
		return ch - 'a' + 10;
	return -1;
}

/*
 * While we find nice hex chars, build a long_val.
 * Return number of chars processed.
 */
int kgdb_hex2long(char **ptr, unsigned long *long_val)
{
	int hex_val;
	int num = 0;
	int negate = 0;

	*long_val = 0;

	if (**ptr == '-') {
		negate = 1;
		(*ptr)++;
	}
	while (**ptr) {
		hex_val = hex_to_bin(**ptr);
		if (hex_val < 0)
			break;

		*long_val = (*long_val << 4) | hex_val;
		num++;
		(*ptr)++;
	}

	if (negate)
		*long_val = -*long_val;

	return num;
}

static inline long check_address(const void *src, int size)
{
	long ret = 0;
	unsigned long start = (unsigned long)src;
	unsigned long end = start + size;

	if (start < 0x80000000 || start > 0xc0000000)
		ret = -EFAULT;

	if (end < 0x80000000 || end > 0xc0000000)
		ret = -EFAULT;

	return ret;
}

/*
 * Convert the memory pointed to by mem into hex, placing result in
 * buf.  Return a pointer to the last char put in buf (null). May
 * return an error.
 */
char *kgdb_mem2hex(char *mem, char *buf, int count)
{
	char *tmp;
	int err;

	/*
	 * We use the upper half of buf as an intermediate buffer for the
	 * raw memory copy.  Hex conversion will work against this one.
	 */
	tmp = buf + count;

	err = check_address(mem, count);
	if (err)
		return NULL;

	memcpy(tmp, mem, count);

	while (count > 0) {
		buf = hex_byte_pack(buf, *tmp);
		tmp++;
		count--;
	}
	*buf = 0;

	return buf;
}

/*
 * Convert the hex array pointed to by buf into binary to be placed in
 * mem.  Return a pointer to the character AFTER the last byte
 * written.  May return an error.
 */
int kgdb_hex2mem(char *buf, char *mem, int count)
{
	char *tmp_raw;
	char *tmp_hex;

	/*
	 * We use the upper half of buf as an intermediate buffer for the
	 * raw memory that is converted from hex.
	 */
	tmp_raw = buf + count * 2;

	tmp_hex = tmp_raw - 1;
	while (tmp_hex >= buf) {
		tmp_raw--;
		*tmp_raw = hex_to_bin(*tmp_hex--);
		*tmp_raw |= hex_to_bin(*tmp_hex--) << 4;
	}

	memcpy(mem, tmp_raw, count);
	return 0;
}

/*
 * Copy the binary array pointed to by buf into mem.  Fix $, #, and
 * 0x7d escaped with 0x7d. Return -EFAULT on failure or 0 on success.
 * The input buf is overwitten with the result to write to mem.
 */
static int kgdb_ebin2mem(char *buf, char *mem, int count)
{
	int size = 0;
	char *c = buf;

	while (count-- > 0) {
		c[size] = *buf++;
		if (c[size] == 0x7d)
			c[size] = *buf++ ^ 0x20;
		size++;
	}

	memcpy(mem, c, size);
	return 0;
}

static inline unsigned long swap32(unsigned long a)
{
	return (a << 24) | ((a & 0xff00) << 8) | ((a >> 8) & 0xff00) | (a >> 24);
}

static inline void put_unaligned_be32(unsigned long val, void *p)
{
	*((unsigned long *)p) = swap32(val);
}

static void int_to_threadref(unsigned char *id, int value)
{
	put_unaligned_be32(value, id);
}

#define KSEG0                   0x80000000
TX_THREAD *kgdb_getthread(unsigned long threadid)
{
	return (TX_THREAD *)(threadid | KSEG0);
}

long kgdb_getpid(TX_THREAD *thread)
{
	return (long)( (unsigned long)thread & 0x1fffffff);
}

int kgdb_arch_handle_exception(int vector, int err_code,
		char *remcom_in_buffer, char *remcom_out_buffer,
		struct pt_regs *regs)
{
	char *ptr;
	unsigned long address;

	switch (remcom_in_buffer[0]) {
		case 'c':
			/* handle the optional parameter */
			ptr = &remcom_in_buffer[1];
			if (kgdb_hex2long(&ptr, &address))
				regs->cp0_epc = address;
			return 0;
	}

	return -1;
}

/*
 * Return true if there is a valid kgdb I/O module.  Also if no
 * debugger is attached a message can be printed to the console about
 * waiting for the debugger to attach.
 *
 * The print_wait argument is only to be true when called from inside
 * the core kgdb_handle_exception, because it will wait for the
 * debugger to attach.
 */
static int kgdb_io_ready(int print_wait)
{
	if (!dbg_io_ops)
		return 0;
	if (kgdb_connected)
		return 1;
	if (atomic_read(&kgdb_setting_breakpoint))
		return 1;
	if (print_wait) {
		Trid_Print("Waiting for remote debugger\n");
	}
	return 1;
}

static char gdbstub_read_wait(void)
{
	char ret = dbg_io_ops->read_char();
	//while (ret == NO_POLL_CHAR)
	//	ret = dbg_io_ops->read_char();
	return ret;
}

static void error_packet(char *pkt, int error)
{
	error = -error;
	pkt[0] = 'E';
	pkt[1] = hex_asc[(error / 10)];
	pkt[2] = hex_asc[(error % 10)];
	pkt[3] = '\0';
}

/* scan for the sequence $<data>#<checksum> */
static void get_packet(char *buffer)
{
	unsigned char checksum;
	unsigned char xmitcsum;
	int count;
	char ch;
#if 0
	ch = gdbstub_read_wait();
	Trid_Print("get char=%c\n", ch);
	buffer[0] = ch;
#else
	do {
		/*
		 * Spin and wait around for the start character, ignore all
		 * other characters:
		 */
		while ((ch = (gdbstub_read_wait())) != '$')
			/* nothing */;

		kgdb_connected = 1;
		checksum = 0;
		xmitcsum = -1;

		count = 0;

		/*
		 * now, read until a # or end of buffer is found:
		 */
		while (count < (BUFMAX - 1)) {
			ch = gdbstub_read_wait();
			if (ch == '#')
				break;
			checksum = checksum + ch;
			buffer[count] = ch;
			count = count + 1;
		}

		if (ch == '#') {
			xmitcsum = hex_to_bin(gdbstub_read_wait()) << 4;
			xmitcsum += hex_to_bin(gdbstub_read_wait());

			if (checksum != xmitcsum)
				/* failed checksum */
				dbg_io_ops->write_char('-');
			else
				/* successful transfer */
				dbg_io_ops->write_char('+');
			if (dbg_io_ops->flush)
				dbg_io_ops->flush();
		}
		buffer[count] = 0;
	} while (checksum != xmitcsum);
#endif
}

/*
 * Send the packet in buffer.
 * Check for gdb connection if asked for.
 */
static void put_packet(char *buffer)
{
	unsigned char checksum;
	int count;
	char ch;

	/*
	 * $<packet info>#<checksum>.
	 */
	while (1) {
		dbg_io_ops->write_char('$');
		checksum = 0;
		count = 0;

		while ((ch = buffer[count])) {
			dbg_io_ops->write_char(ch);
			checksum += ch;
			count++;
		}

		dbg_io_ops->write_char('#');
		dbg_io_ops->write_char(hex_asc_hi(checksum));
		dbg_io_ops->write_char(hex_asc_lo(checksum));
		if (dbg_io_ops->flush)
			dbg_io_ops->flush();

		/* Now see what we get in reply. */
		ch = gdbstub_read_wait();

		if (ch == 3)
			ch = gdbstub_read_wait();

		/* If we get an ACK, we are done. */
		if (ch == '+')
			return;

		/*
		 * If we get the start of another packet, this means
		 * that GDB is attempting to reconnect.  We will NAK
		 * the packet being sent, and stop trying to send this
		 * packet.
		 */
		if (ch == '$') {
			dbg_io_ops->write_char('-');
			if (dbg_io_ops->flush)
				dbg_io_ops->flush();
			return;
		}
	}
}

static void put_packet_nowait(char *buffer)
{
	unsigned char checksum;
	int count;
	char ch;

	/*
	 * $<packet info>#<checksum>.
	 */
	dbg_io_ops->write_char('$');
	checksum = 0;
	count = 0;

	while ((ch = buffer[count])) {
		dbg_io_ops->write_char(ch);
		checksum += ch;
		count++;
	}

	dbg_io_ops->write_char('#');
	dbg_io_ops->write_char(hex_asc_hi(checksum));
	dbg_io_ops->write_char(hex_asc_lo(checksum));
	if (dbg_io_ops->flush)
		dbg_io_ops->flush();

}

static char gdbmsgbuf[BUFMAX + 1];
void gdbstub_msg_write(const char *s, int len)
{
	char *bufptr;
	int wcount;
	int i;

	if (len == 0)
		len = strlen(s);

	/* 'O'utput */
	gdbmsgbuf[0] = 'O';

	/* Fill and send buffers... */
	while (len > 0) {
		bufptr = gdbmsgbuf + 1;

		/* Calculate how many this time */
		if ((len << 1) > (BUFMAX - 2))
			wcount = (BUFMAX - 2) >> 1;
		else
			wcount = len;

		/* Pack in hex chars */
		for (i = 0; i < wcount; i++)
			bufptr = hex_byte_pack(bufptr, s[i]);
		*bufptr = '\0';

		/* Move up */
		s += wcount;
		len -= wcount;

		/* Write packet */
		put_packet(gdbmsgbuf);
	}
}

void gdbstub_msg_write_nowait(const char *s, int len)
{
	char *bufptr;
	int wcount;
	int i;

	if (len == 0)
		len = strlen(s);

	/* 'O'utput */
	gdbmsgbuf[0] = 'O';

	/* Fill and send buffers... */
	while (len > 0) {
		bufptr = gdbmsgbuf + 1;

		/* Calculate how many this time */
		if ((len << 1) > (BUFMAX - 2))
			wcount = (BUFMAX - 2) >> 1;
		else
			wcount = len;

		/* Pack in hex chars */
		for (i = 0; i < wcount; i++)
			bufptr = hex_byte_pack(bufptr, s[i]);
		*bufptr = '\0';

		/* Move up */
		s += wcount;
		len -= wcount;

		/* Write packet */
		put_packet_nowait(gdbmsgbuf);
	}
}

void kgdb_console_write(const char *s, unsigned count)
{
	unsigned long flags;

	/* If we're debugging, or KGDB has not connected, don't try
	 * and print. */
	if (!kgdb_connected || atomic_read(&kgdb_active) != -1)
		return;

	flags = local_irq_save();
	gdbstub_msg_write_nowait(s, count);
	local_irq_restore(flags);
}

static char *pack_threadid(char *pkt, unsigned char *id)
{
	unsigned char *limit;
	int lzero = 1;

	limit = id + 4;
	while (id < limit) {
		if (!lzero || *id != 0) {
			pkt = hex_byte_pack(pkt, *id);
			lzero = 0;
		}
		id++;
	}

	if (lzero)
		pkt = hex_byte_pack(pkt, 0);

	return pkt;
}

#define KGDB_MAX_THREAD_QUERY 17
/* Handle the 'q' query packets */
static void gdb_cmd_query(struct kgdb_state *ks)
{
	TX_THREAD *g, *t, *thread_ptr;
	//struct task_struct *p;
	unsigned char thref[8];
	char *ptr;
	int i;
	int cpu;
	int finished = 0;

	switch (remcom_in_buffer[1]) {
		case 's':
			remcom_out_buffer[0] = 'l';
			break;
		case 'f':
#if 1
			if (memcmp(remcom_in_buffer + 2, "ThreadInfo", 10))
				break;

			i = 0;
			remcom_out_buffer[0] = 'm';
			ptr = remcom_out_buffer + 1;
			/*
			//do_each_thread(g, p) {
			for (g = t = _tx_thread_identify_safe(); (g = t = g->tx_thread_created_next) != _tx_thread_identify_safe() ; ) do {
			if (i >= ks->thr_query && !finished) {
			int_to_threadref(thref, kgdb_getpid(g));
			ptr = pack_threadid(ptr, thref);
			 *(ptr++) = ',';
			 ks->thr_query++;
			 if (ks->thr_query % KGDB_MAX_THREAD_QUERY == 0)
			 finished = 1;
			 }
			 i++;
			 } while ((t = t->tx_thread_created_next) != g);
			//} while_each_thread(g, p);
			 */
			/* Pickup the first thread and the number of created threads.  */
			thread_ptr = _tx_thread_created_ptr;
			i = _tx_thread_created_count;

			/* Loop to register all threads.  */
			while (i--) {
				/* Register this thread.  */
				int_to_threadref(thref, kgdb_getpid(thread_ptr));
				ptr = pack_threadid(ptr, thref);
				*(ptr++) = ',';
				ks->thr_query++;

				/* Move to the next thread.  */
				thread_ptr = thread_ptr->tx_thread_created_next;
			}
			*(--ptr) = '\0';
#endif
			break;

		case 'C':
			/* Current thread id */
			strcpy(remcom_out_buffer, "QC");
			ks->threadid = kgdb_getpid(_tx_thread_identify_safe());
			int_to_threadref(thref, ks->threadid);
			pack_threadid(remcom_out_buffer + 2, thref);
			break;
#if 1
		case 'T':
			if (memcmp(remcom_in_buffer + 1, "ThreadExtraInfo,", 16))
				break;

			ks->threadid = 0;
			ptr = remcom_in_buffer + 17;
			kgdb_hex2long(&ptr, &ks->threadid);
			if (!(thread_ptr = kgdb_getthread(ks->threadid))) {
				error_packet(remcom_out_buffer, -EINVAL);
				break;
			}
			if ((int)ks->threadid > 0) {
				kgdb_mem2hex(thread_ptr->tx_thread_name, remcom_out_buffer, 26);
			} else {

			}
			break;
#endif
	}
}

/* Handle the 'T' thread query packets */
static void gdb_cmd_thread(struct kgdb_state *ks)
{
	char *ptr = &remcom_in_buffer[1];
	TX_THREAD *thread;

	kgdb_hex2long(&ptr, (unsigned long*)&ks->threadid);
	thread = kgdb_getthread(ks->threadid);
	if (thread && ks->threadid > 0)
		strcpy(remcom_out_buffer, "OK");
	else
		error_packet(remcom_out_buffer, -EINVAL);
}

/* Handle the 'H' task query packets, target remote starts with Hc-1 */
static void gdb_cmd_task(struct kgdb_state *ks)
{
	TX_THREAD *thread;
	char *ptr;

	switch (remcom_in_buffer[1]) {
		case 'g':
			ptr = &remcom_in_buffer[2];
			kgdb_hex2long(&ptr, (unsigned long*)(&ks->threadid));
			thread = kgdb_getthread(ks->threadid);
			if (!thread && ks->threadid > 0) {
				error_packet(remcom_out_buffer, -EINVAL);
				break;
			}
			if (ks->threadid == 0) { //if in irq, current thread is 0
				error_packet(remcom_out_buffer, -EINVAL);
				break;
			}
			kgdb_usethread = thread;
			ks->kgdb_usethreadid = ks->threadid;
			strcpy(remcom_out_buffer, "OK");
			break;
		case 'c':
			ptr = &remcom_in_buffer[2];
			kgdb_hex2long(&ptr, (unsigned long*)(&ks->threadid));
			if (!ks->threadid) {
				kgdb_contthread = NULL;
			} else {
				thread = kgdb_getthread(ks->threadid);
				if (!thread && ks->threadid > 0) {
					error_packet(remcom_out_buffer, -EINVAL);
					break;
				}
				kgdb_contthread = thread;
			}
			strcpy(remcom_out_buffer, "OK");
			break;
	}
}

#define SIGTRAP          5

/* Handle the '?' status packets */
static void gdb_cmd_status(struct kgdb_state *ks)
{
	/*
	 * We know that this packet is only sent
	 * during initial connect.  So to be safe,
	 * we clear out our breakpoints now in case
	 * GDB is reconnecting.
	 */
	dbg_remove_all_break();

	remcom_out_buffer[0] = 'S';
	hex_byte_pack(&remcom_out_buffer[1], SIGTRAP);
}

void sleeping_thread_to_gdb_regs(unsigned long *gdb_regs, TX_THREAD *p)
{
	int reg;
	unsigned long *ksp = (unsigned long *)(p->tx_thread_stack_ptr);
	unsigned long *ptr = (unsigned long *)gdb_regs;

	if ((*ksp) == 0) { // see _tx_thread_synch_return
		*(ptr++) = 0; //zero
		for (reg = 1; reg < 16; reg++) /* $15-$1 is at ksp[56-112]*/
			//*(ptr++) = *(ksp+4*(28-reg+1));
			*(ptr++) = 0;

		/* S0 - S7 */
		*(ptr++) = *(ksp+9);//s0
		*(ptr++) = *(ksp+8);//s1
		*(ptr++) = *(ksp+7);//s2
		*(ptr++) = *(ksp+6);//s3
		*(ptr++) = *(ksp+5);//s4
		*(ptr++) = *(ksp+4);//s5
		*(ptr++) = *(ksp+3);//s6
		*(ptr++) = *(ksp+2);//s7

		for (reg = 24; reg < 29; reg++)
			*(ptr++) = 0;

		/* SP, FP, RA */
		*(ptr++) = (unsigned long)(ksp)+192; //sp
		*(ptr++) = *(ksp+1); //fp
		*(ptr++) = *(ksp+12); //ra

		*(ptr++) = *(ksp+13); //sr
		*(ptr++) = *(ksp+11); //lo
		*(ptr++) = *(ksp+10); //hi
		*(ptr++) = 0;//regs->cp0_badvaddr;
		*(ptr++) = 0;//regs->cp0_cause;
		//if (p->tx_thread_state != TX_COMPLETED)
		if (*(ksp+12) == 0xefefefef)
			*(ptr++) = 0;
		else
			*(ptr++) = *(ksp+12); //ra in synch frame;//regs->cp0_epc;
	}
	else { // from irq
		*(ptr++) = 0; //zero

		*(ptr++) = *(ksp+28); //at
		*(ptr++) = *(ksp+27); //v0
		*(ptr++) = *(ksp+26); //v1
		*(ptr++) = *(ksp+25); //a0
		*(ptr++) = *(ksp+24); //a1
		*(ptr++) = *(ksp+23); //a2
		*(ptr++) = *(ksp+22); //a3
		*(ptr++) = *(ksp+21); //t0
		*(ptr++) = *(ksp+20); //t1
		*(ptr++) = *(ksp+19); //t2
		*(ptr++) = *(ksp+18); //t3
		*(ptr++) = *(ksp+17); //t4
		*(ptr++) = *(ksp+16); //t5
		*(ptr++) = *(ksp+15); //t6
		*(ptr++) = *(ksp+14); //t7

		/* S0 - S7 */
		*(ptr++) = *(ksp+9);//s0
		*(ptr++) = *(ksp+8);//s1
		*(ptr++) = *(ksp+7);//s2
		*(ptr++) = *(ksp+6);//s3
		*(ptr++) = *(ksp+5);//s4
		*(ptr++) = *(ksp+4);//s5
		*(ptr++) = *(ksp+3);//s6
		*(ptr++) = *(ksp+2);//s7

		/* $24 - $28 */
		*(ptr++) = *(ksp+13);//t8
		*(ptr++) = *(ksp+12);//t9
		*(ptr++) = 0;//$26
		*(ptr++) = 0;//$27
		*(ptr++) = 0;//$28

		/* SP, FP, RA */
		*(ptr++) = (unsigned long)(ksp)+424; //sp
		*(ptr++) = *(ksp+1); //fp,s8
		*(ptr++) = *(ksp+29); //ra

		*(ptr++) = *(ksp+30); //sr
		*(ptr++) = *(ksp+11); //lo
		*(ptr++) = *(ksp+10); //hi
		*(ptr++) = 0;//regs->cp0_badvaddr;
		*(ptr++) = 0;//regs->cp0_cause;
		*(ptr++) = *(ksp+31); //regs->cp0_epc;
	}
}

static void gdb_get_regs_helper(struct kgdb_state *ks)
{
	TX_THREAD *thread;
	void *local_debuggerinfo;
	int i;

	thread = kgdb_usethread;
	if (!thread) {
		thread = kgdb_info[ks->cpu].task;
		local_debuggerinfo = kgdb_info[ks->cpu].debuggerinfo;
	} else {
		local_debuggerinfo = NULL;
		/*
		 * Try to find the task on some other
		 * or possibly this node if we do not
		 * find the matching task then we try
		 * to approximate the results.
		 */
		if (thread == kgdb_info[0].task)
			local_debuggerinfo = kgdb_info[0].debuggerinfo;
	}

	/*
	 * All threads that don't have debuggerinfo should be
	 * in schedule() sleeping, since all other CPUs
	 * are in kgdb_wait, and thus have debuggerinfo.
	 */
	if (local_debuggerinfo) {
		pt_regs_to_gdb_regs(gdb_regs, local_debuggerinfo);
	} else {
		/*
		 * Pull stuff saved during switch_to; nothing
		 * else is accessible (or even particularly
		 * relevant).
		 *
		 * This should be enough for a stack trace.
		 */
		sleeping_thread_to_gdb_regs(gdb_regs, thread);
	}
}

/* Handle the 'g' get registers request */
static void gdb_cmd_getregs(struct kgdb_state *ks)
{
	gdb_get_regs_helper(ks);
	kgdb_mem2hex((char *)gdb_regs, remcom_out_buffer, NUMREGBYTES);
}

/* Handle the 'm' memory read bytes */
static void gdb_cmd_memread(struct kgdb_state *ks)
{
	char *ptr = &remcom_in_buffer[1];
	unsigned long length;
	unsigned long addr;
	char *err;

	if (kgdb_hex2long(&ptr, &addr) > 0 && *ptr++ == ',' &&
			kgdb_hex2long(&ptr, &length) > 0) {
		err = kgdb_mem2hex((char *)addr, remcom_out_buffer, length);
		if (!err)
			error_packet(remcom_out_buffer, -EINVAL);
	} else {
		error_packet(remcom_out_buffer, -EINVAL);
	}
}

/* Write memory due to an 'M' or 'X' packet. */
static int write_mem_msg(int binary)
{
	char *ptr = &remcom_in_buffer[1];
	unsigned long addr;
	unsigned long length;
	int err;

	if (kgdb_hex2long(&ptr, &addr) > 0 && *(ptr++) == ',' &&
			kgdb_hex2long(&ptr, &length) > 0 && *(ptr++) == ':') {
		if (binary)
			err = kgdb_ebin2mem(ptr, (char *)addr, length);
		else
			err = kgdb_hex2mem(ptr, (char *)addr, length);
		if (err)
			return err;
		return 0;
	}

	return -EINVAL;
}

/* Handle the 'M' memory write bytes */
static void gdb_cmd_memwrite(struct kgdb_state *ks)
{
	int err = write_mem_msg(0);

	if (err)
		error_packet(remcom_out_buffer, err);
	else
		strcpy(remcom_out_buffer, "OK");
}

/* Handle the 'X' memory binary write bytes */
static void gdb_cmd_binwrite(struct kgdb_state *ks)
{
	int err = write_mem_msg(1);

	if (err)
		error_packet(remcom_out_buffer, err);
	else
		strcpy(remcom_out_buffer, "OK");
}

/* Handle the 'R' reboot packets */
static int gdb_cmd_reboot(struct kgdb_state *ks)
{
	return 0;
}

/* Handle the 'z' or 'Z' breakpoint remove or set packets */
static void gdb_cmd_break(struct kgdb_state *ks)
{
	/*
	 * Since GDB-5.3, it's been drafted that '' is a software
	 * breakpoint, '1' is a hardware breakpoint, so let's do that.
	 */
	char *bpt_type = &remcom_in_buffer[1];
	char *ptr = &remcom_in_buffer[2];
	unsigned long addr;
	unsigned long length;
	int error = 0;

	if (arch_kgdb_ops.set_hw_breakpoint && *bpt_type >= '1') {
		/* Support watchpoint 2-4 */
		if (*bpt_type > '4')
			return;
	} else {
		//if (*bpt_type != '' && *bpt_type != '1')
		/* old fashion: '0' is a software breakpoint */
		if (*bpt_type != 0x0 && *bpt_type != '1' && *bpt_type != '0')
			/* Unsupported. */
			return;
	}

	/*
	 * Test if this is a hardware breakpoint, and
	 * if we support it:
	 */
	if (*bpt_type == '1' && !(arch_kgdb_ops.flags & KGDB_HW_BREAKPOINT))
		/* Unsupported. */
		return;

	if (*(ptr++) != ',') {
		error_packet(remcom_out_buffer, -EINVAL);
		return;
	}
	if (!kgdb_hex2long(&ptr, &addr)) {
		error_packet(remcom_out_buffer, -EINVAL);
		return;
	}
	if (*(ptr++) != ',' ||
			!kgdb_hex2long(&ptr, &length)) {
		error_packet(remcom_out_buffer, -EINVAL);
		return;
	}

	//if (remcom_in_buffer[0] == 'Z' && *bpt_type == '')
	if (remcom_in_buffer[0] == 'Z' && (*bpt_type == 0x0 || *bpt_type == '0'))
		error = dbg_set_sw_break(addr);
	//else if (remcom_in_buffer[0] == 'z' && *bpt_type == '')
	else if (remcom_in_buffer[0] == 'z' && (*bpt_type == 0x0 || *bpt_type == '0'))
		error = dbg_remove_sw_break(addr);
	else if (remcom_in_buffer[0] == 'Z')
		error = arch_kgdb_ops.set_hw_breakpoint(addr,
				//(int)length, *bpt_type - '');
			  (int)length, *bpt_type - '0');
	else if (remcom_in_buffer[0] == 'z')
		error = arch_kgdb_ops.remove_hw_breakpoint(addr,
				//(int) length, *bpt_type - '');
			  (int) length, *bpt_type - '0');

	if (error == 0)
		strcpy(remcom_out_buffer, "OK");
	else
		error_packet(remcom_out_buffer, error);
}

/* Handle the 'C' signal / exception passing packets */
static int gdb_cmd_exception_pass(struct kgdb_state *ks)
{
	{
		gdbstub_msg_write("KGDB only knows signal 9 (pass)"
				" and 15 (pass and disconnect)\n"
				"Executing a continue without signal passing\n", 0);
		remcom_in_buffer[0] = 'c';
	}

	/* Indicate fall through */
	return -1;
}

/* Handle the 'D' or 'k', detach or kill packets */
static void gdb_cmd_detachkill(struct kgdb_state *ks)
{
	int error;

	/* The detach case */
	if (remcom_in_buffer[0] == 'D') {
		error = dbg_remove_all_break();
		if (error < 0) {
			error_packet(remcom_out_buffer, error);
		} else {
			strcpy(remcom_out_buffer, "OK");
			Trid_Setkgdbcons(0);
			kgdb_connected = 0;
		}
		put_packet(remcom_out_buffer);
	} else {
		/*
		 * Assume the kill case, with no exit code checking,
		 * trying to force detach the debugger:
		 */
		dbg_remove_all_break();
		Trid_Setkgdbcons(0);
		kgdb_connected = 0;
	}
}

/*
 * This function performs all gdbserial command procesing
 */
int gdb_serial_stub(struct kgdb_state *ks)
{
	int error = 0;
	int tmp;

	/* Initialize comm buffer and globals. */
	memset(remcom_out_buffer, 0, sizeof(remcom_out_buffer));
	kgdb_usethread = kgdb_info[ks->cpu].task;
	ks->kgdb_usethreadid = kgdb_getpid(kgdb_info[ks->cpu].task);
	ks->pass_exception = 0;

	/* for 'c' & 's' trapin */
	if (kgdb_connected) {
		unsigned char thref[8];
		char *ptr;

		/* Reply to host that an exception has occurred */
		ptr = remcom_out_buffer;
		*ptr++ = 'T';
		ptr = hex_byte_pack(ptr, SIGTRAP);
		ptr += strlen(strcpy(ptr, "thread:"));
		int_to_threadref(thref, kgdb_getpid(_tx_thread_identify_safe()));
		ptr = pack_threadid(ptr, thref);
		*ptr++ = ';';
		put_packet(remcom_out_buffer);
	}

	while (1) {
		error = 0;

		/* Clear the out buffer. */
		memset(remcom_out_buffer, 0, sizeof(remcom_out_buffer));

		get_packet(remcom_in_buffer);

		switch (remcom_in_buffer[0]) {
			case '?': /* gdbserial status */
				gdb_cmd_status(ks);
				break;
			case 'g': /* return the value of the CPU registers */
				gdb_cmd_getregs(ks);
				break;
			case 'G': /* set the value of the CPU registers - return OK */
				//gdb_cmd_setregs(ks);
				break;
			case 'm': /* mAA..AA,LLLL  Read LLLL bytes at address AA..AA */
				gdb_cmd_memread(ks);
				break;
			case 'M': /* MAA..AA,LLLL: Write LLLL bytes at address AA..AA */
				gdb_cmd_memwrite(ks);
				break;
#if DBG_MAX_REG_NUM > 0
			case 'p': /* pXX Return gdb register XX (in hex) */
				//gdb_cmd_reg_get(ks);
				break;
			case 'P': /* PXX=aaaa Set gdb register XX to aaaa (in hex) */
				//gdb_cmd_reg_set(ks);
				break;
#endif /* DBG_MAX_REG_NUM > 0 */
			case 'X': /* XAA..AA,LLLL: Write LLLL bytes at address AA..AA */
				gdb_cmd_binwrite(ks);
				break;
				/* kill or detach. KGDB should treat this like a
				 * continue.
				 */
			case 'D': /* Debugger detach */
			case 'k': /* Debugger detach via kill */
				gdb_cmd_detachkill(ks);
				goto default_handle;
			case 'R': /* Reboot */
				if (gdb_cmd_reboot(ks))
					goto default_handle;
				break;
			case 'q': /* query command */
				gdb_cmd_query(ks);
				break;
			case 'H': /* task related */
				gdb_cmd_task(ks);
				break;
			case 'T': /* Query thread status */
				gdb_cmd_thread(ks);
				break;
			case 'z': /* Break point remove */
			case 'Z': /* Break point set */
				gdb_cmd_break(ks);
				break;
			case 'C': /* Exception passing */
				tmp = gdb_cmd_exception_pass(ks);
				if (tmp > 0)
					goto default_handle;
				if (tmp == 0)
					break;
				/* Fall through on tmp < 0 */
			case 'c': /* Continue packet */
			case 's': /* Single step packet */
				if (kgdb_contthread && kgdb_contthread != _tx_thread_identify_safe()) {
					/* Can't switch threads in kgdb */
					error_packet(remcom_out_buffer, -EINVAL);
					break;
				}
				dbg_activate_sw_breakpoints();
				/* Fall through to default processing */
			default:
default_handle:
				error = kgdb_arch_handle_exception(ks->ex_vector,
						ks->err_code,
						remcom_in_buffer,
						remcom_out_buffer,
						ks->linux_regs);
				/*
				 * Leave cmd processing on error, detach,
				 * kill, continue, or single step.
				 */
				if (error >= 0 || remcom_in_buffer[0] == 'D' ||
						remcom_in_buffer[0] == 'k') {
					error = 0;
					goto kgdb_exit;
				}

		}

		/* reply to the request */
		put_packet(remcom_out_buffer);
	}

kgdb_exit:
	if (ks->pass_exception)
		error = 1;
	return error;
}

static int kgdb_cpu_enter(struct kgdb_state *ks, struct pt_regs *regs, int exception_state)
{
	unsigned long flags;
	int sstep_tries = 100;
	int error;
	int cpu;
	int trace_on = 0;
	int online_cpus = 1;

	kgdb_info[ks->cpu].enter_kgdb++;
	kgdb_info[ks->cpu].exception_state |= exception_state;

	if (exception_state == DCPU_WANT_MASTER)
		atomic_inc(&masters_in_kgdb);
	else
		atomic_inc(&slaves_in_kgdb);

	if (arch_kgdb_ops.disable_hw_break)
		arch_kgdb_ops.disable_hw_break(regs);

acquirelock:
	/*
	 * Interrupts will be restored by the 'trap return' code, except when
	 * single stepping.
	 */
	flags = local_irq_save();

	cpu = ks->cpu;
	kgdb_info[cpu].debuggerinfo = regs;
	kgdb_info[cpu].task = _tx_thread_identify_safe();
	kgdb_info[cpu].ret_state = 0;
	//kgdb_info[cpu].irq_depth = hardirq_count() >> HARDIRQ_SHIFT;

	/* Make sure the above info reaches the primary CPU */
	wmb();

	if (exception_level == 1) {
		goto cpu_master_loop;
	}

	/*
	 * CPU will loop if it is a slave or request to become a kgdb
	 * master cpu and acquire the kgdb_active lock:
	 */
	while (1) {
cpu_loop:
		if (kgdb_info[cpu].exception_state & DCPU_NEXT_MASTER) {
			kgdb_info[cpu].exception_state &= ~DCPU_NEXT_MASTER;
			goto cpu_master_loop;
		} else if (kgdb_info[cpu].exception_state & DCPU_WANT_MASTER) {
			break;

		} else if (kgdb_info[cpu].exception_state & DCPU_IS_SLAVE) {
			goto return_normal;
		} else {
return_normal:
			/* Return to normal operation by executing any
			 * hw breakpoint fixup.
			 */
			if (arch_kgdb_ops.correct_hw_break)
				arch_kgdb_ops.correct_hw_break();
			kgdb_info[cpu].exception_state &=
				~(DCPU_WANT_MASTER | DCPU_IS_SLAVE);
			kgdb_info[cpu].enter_kgdb--;
			wmb();
			atomic_dec(&slaves_in_kgdb);
			local_irq_restore(flags);
			return 0;
		}
	}

	/*
	 * For single stepping, try to only enter on the processor
	 * that was single stepping.  To guard against a deadlock, the
	 * kernel will only try for the value of sstep_tries before
	 * giving up and continuing on.
	 */
	if (atomic_read(&kgdb_cpu_doing_single_step) != -1 &&
			(kgdb_info[cpu].task &&
			 kgdb_info[cpu].task != kgdb_sstep_pid) && --sstep_tries) {
		atomic_set(&kgdb_active, -1);
		local_irq_restore(flags);

		goto acquirelock;
	}

	if (!kgdb_io_ready(1)) {
		kgdb_info[cpu].ret_state = 1;
		Trid_Print("io is not ready...\n");
		goto kgdb_restore; /* No I/O connection, resume the system */
	}

	/*
	 * Don't enter if we have hit a removed breakpoint.
	 */
	//if (kgdb_skipexception(ks->ex_vector, ks->linux_regs))
	//        goto kgdb_restore;

	/* Call the I/O driver's pre_exception routine */
	if (dbg_io_ops->pre_exception)
		dbg_io_ops->pre_exception();

	/*
	 * Get the passive CPU lock which will hold all the non-primary
	 * CPU in a spin state while the debugger is active
	 */
	//if (!kgdb_single_step)
	//           raw_spin_lock(&dbg_slave_lock);

	/*
	 * At this point the primary processor is completely
	 * in the debugger and all secondary CPUs are quiescent
	 */
	dbg_deactivate_sw_breakpoints();
	kgdb_single_step = 0;
	kgdb_contthread = _tx_thread_identify_safe();
	exception_level = 0;

	while (1) {
cpu_master_loop:
		error = gdb_serial_stub(ks);

		if (error == DBG_SWITCH_CPU_EVENT) {
			//kgdb_info[dbg_switch_cpu].exception_state |=
			//        DCPU_NEXT_MASTER;
			goto cpu_loop;
		} else {
			kgdb_info[cpu].ret_state = error;
			break;
		}
	}

	/* Call the I/O driver's post_exception routine */
	if (dbg_io_ops->post_exception)
		dbg_io_ops->post_exception();

kgdb_restore:
	if (atomic_read(&kgdb_cpu_doing_single_step) != -1) {
		int sstep_cpu = atomic_read(&kgdb_cpu_doing_single_step);
		if (kgdb_info[sstep_cpu].task)
			kgdb_sstep_pid = kgdb_info[sstep_cpu].task;
		else
			kgdb_sstep_pid = 0;
	}
	if (arch_kgdb_ops.correct_hw_break)
		arch_kgdb_ops.correct_hw_break();

	kgdb_info[cpu].exception_state &=
		~(DCPU_WANT_MASTER | DCPU_IS_SLAVE);
	kgdb_info[cpu].enter_kgdb--;
	wmb();
	atomic_dec(&masters_in_kgdb);
	/* Free kgdb_active */
	atomic_set(&kgdb_active, -1);
	local_irq_restore(flags);

	return kgdb_info[cpu].ret_state;
}



/*
 * kgdb_handle_exception() - main entry point from a kernel exception
 *
 * Locking hierarchy:
 *      interface locks, if any (begin_session)
 *      kgdb lock (kgdb_active)
 */
int kgdb_handle_exception(int evector, int ecode, struct pt_regs *regs)
{
	struct kgdb_state kgdb_var;
	struct kgdb_state *ks = &kgdb_var;
	int ret = 0;

	// if (arch_kgdb_ops.enable_nmi)
	//    arch_kgdb_ops.enable_nmi(0);

	memset(ks, 0, sizeof(struct kgdb_state));
	ks->cpu                 = 0; // only support 1 core
	ks->ex_vector           = evector;
	// ks->signo               = signo;
	ks->err_code            = ecode;
	ks->linux_regs          = regs;

	//if (kgdb_reenter_check(ks)) /* TODO */
	//    goto out; /* Ouch, double exception ! */
	if (kgdb_info[ks->cpu].enter_kgdb != 0)
		goto out;

	ret = kgdb_cpu_enter(ks, regs, DCPU_WANT_MASTER);
out:
	// if (arch_kgdb_ops.enable_nmi)
	//   arch_kgdb_ops.enable_nmi(1);
	return ret;
}

/*
 * try to fall into the debugger
 */
static int kgdb_mips_notify(unsigned long cmd, void *ptr)
{
	struct die_args *args = (struct die_args *)ptr;
	struct pt_regs *regs = args->regs;
	int trap = (regs->cp0_cause & 0x7c) >> 2;

	if (kgdb_handle_exception(trap, cmd, regs))
		return NOTIFY_DONE;

	if (atomic_read(&kgdb_setting_breakpoint)) {
		if ((trap == 9) && (regs->cp0_epc == (unsigned long)breakinst))
			regs->cp0_epc += 4;
	}

	/* In SMP mode, __flush_cache_all does IPI */
	local_irq_enable();
	// __flush_cache_all();

	return NOTIFY_STOP;
}

int kgdb_ll_trap(int cmd, const char *str, struct pt_regs *regs, long err)
{
	struct die_args args = {
		.regs   = regs,
		.str    = str,
		.err    = err,
	};
	return kgdb_mips_notify(cmd, &args);
}

void do_trap_or_bp(struct pt_regs *regs, unsigned int code, const char *str)
{
	// for now, we only support kgdb
	kgdb_ll_trap(DIE_TRAP, str, regs, code);
	return;
}

void do_bp(struct pt_regs *regs)
{
	unsigned long epc = regs->cp0_epc;
	unsigned int opcode, bcode;
	opcode = *((unsigned int*)epc);
	bcode = (opcode >> 6) & ((1 << 20) - 1);
	// Trid_Print("do bp, epc is 0x%x, opcode is 0x%x, bcode is %x\n", regs->cp0_epc, opcode, bcode);
	do_trap_or_bp(regs, bcode, "Break");
}

void do_tr(struct pt_regs *regs)
{
	Trid_Print("do tr...\n");
}

#define CAUSEF_WP               (_ULCAST_(1)   << 22)
#define CAUSEF_BD               (_ULCAST_(1)   << 31)
#define read_c0_cause()         __read_32bit_c0_register($13, 0)
#define write_c0_cause(val)     __write_32bit_c0_register($13, 0, val)
#define BRANCH_LIKELY_TAKEN 0x0001

static inline int delay_slot(struct pt_regs *regs)
{
	return regs->cp0_cause & CAUSEF_BD;
}

/**
 * __compute_return_epc_for_insn - Computes the return address and do emulate
 *                                  branch simulation, if required.
 *
 * @regs:       Pointer to pt_regs
 * @insn:       branch instruction to decode
 * @returns:    -EFAULT on error and forces SIGBUS, and on success
 *              returns 0 or BRANCH_LIKELY_TAKEN as appropriate after
 *              evaluating the branch.
 */
int __compute_return_epc_for_insn(struct pt_regs *regs, union mips_instruction insn)
{
	unsigned int bit, fcr31, dspcontrol;
	long epc = regs->cp0_epc;
	int ret = 0;

	switch (insn.i_format.opcode) {
		/*
		 * jr and jalr are in r_format format.
		 */
		case spec_op:
			switch (insn.r_format.func) {
				case jalr_op:
					regs->regs[insn.r_format.rd] = epc + 8;
					/* Fall through */
				case jr_op:
					regs->cp0_epc = regs->regs[insn.r_format.rs];
					break;
			}
			break;

			/*
			 * This group contains:
			 * bltz_op, bgez_op, bltzl_op, bgezl_op,
			 * bltzal_op, bgezal_op, bltzall_op, bgezall_op.
			 */
		case bcond_op:
			switch (insn.i_format.rt) {
				case bltz_op:
				case bltzl_op:
					if ((long)regs->regs[insn.i_format.rs] < 0) {
						epc = epc + 4 + (insn.i_format.simmediate << 2);
						if (insn.i_format.rt == bltzl_op)
							ret = BRANCH_LIKELY_TAKEN;
					} else
						epc += 8;
					regs->cp0_epc = epc;
					break;

				case bgez_op:
				case bgezl_op:
					if ((long)regs->regs[insn.i_format.rs] >= 0) {
						epc = epc + 4 + (insn.i_format.simmediate << 2);
						if (insn.i_format.rt == bgezl_op)
							ret = BRANCH_LIKELY_TAKEN;
					} else
						epc += 8;
					regs->cp0_epc = epc;
					break;

				case bltzal_op:
				case bltzall_op:
					regs->regs[31] = epc + 8;
					if ((long)regs->regs[insn.i_format.rs] < 0) {
						epc = epc + 4 + (insn.i_format.simmediate << 2);
						if (insn.i_format.rt == bltzall_op)
							ret = BRANCH_LIKELY_TAKEN;
					} else
						epc += 8;
					regs->cp0_epc = epc;
					break;

				case bgezal_op:
				case bgezall_op:
					regs->regs[31] = epc + 8;
					if ((long)regs->regs[insn.i_format.rs] >= 0) {
						epc = epc + 4 + (insn.i_format.simmediate << 2);
						if (insn.i_format.rt == bgezall_op)
							ret = BRANCH_LIKELY_TAKEN;
					} else
						epc += 8;
					regs->cp0_epc = epc;
					break;

				case bposge32_op:
					goto sigill;
#if 0
					if (!cpu_has_dsp)
						goto sigill;

					dspcontrol = rddsp(0x01);

					if (dspcontrol >= 32) {
						epc = epc + 4 + (insn.i_format.simmediate << 2);
					} else
						epc += 8;
					regs->cp0_epc = epc;
#endif
					break;
			}
			break;

			/*
			 * These are unconditional and in j_format.
			 */
		case jal_op:
			regs->regs[31] = regs->cp0_epc + 8;
		case j_op:
			epc += 4;
			epc >>= 28;
			epc <<= 28;
			epc |= (insn.j_format.target << 2);
			regs->cp0_epc = epc;
			/*if (insn.i_format.opcode == jalx_op)
			  set_isa16_mode(regs->cp0_epc); */
			break;

			/*
			 * These are conditional and in i_format.
			 */
		case beq_op:
		case beql_op:
			if (regs->regs[insn.i_format.rs] ==
					regs->regs[insn.i_format.rt]) {
				epc = epc + 4 + (insn.i_format.simmediate << 2);
				if (insn.i_format.rt == beql_op)
					ret = BRANCH_LIKELY_TAKEN;
			} else
				epc += 8;
			regs->cp0_epc = epc;
			break;

		case bne_op:
		case bnel_op:
			if (regs->regs[insn.i_format.rs] !=
					regs->regs[insn.i_format.rt]) {
				epc = epc + 4 + (insn.i_format.simmediate << 2);
				if (insn.i_format.rt == bnel_op)
					ret = BRANCH_LIKELY_TAKEN;
			} else
				epc += 8;
			regs->cp0_epc = epc;
			break;

		case blez_op: /* not really i_format */
		case blezl_op:
			/* rt field assumed to be zero */
			if ((long)regs->regs[insn.i_format.rs] <= 0) {
				epc = epc + 4 + (insn.i_format.simmediate << 2);
				if (insn.i_format.rt == bnel_op)
					ret = BRANCH_LIKELY_TAKEN;
			} else
				epc += 8;
			regs->cp0_epc = epc;
			break;

		case bgtz_op:
		case bgtzl_op:
			/* rt field assumed to be zero */
			if ((long)regs->regs[insn.i_format.rs] > 0) {
				epc = epc + 4 + (insn.i_format.simmediate << 2);
				if (insn.i_format.rt == bnel_op)
					ret = BRANCH_LIKELY_TAKEN;
			} else
				epc += 8;
			regs->cp0_epc = epc;
			break;
#if 0 //no fpu
			/*
			 * And now the FPA/cp1 branch instructions.
			 */
		case cop1_op:
			preempt_disable();
			if (is_fpu_owner())
				asm volatile("cfc1\t%0,$31" : "=r" (fcr31));
			else
				fcr31 = current->thread.fpu.fcr31;
			preempt_enable();

			bit = (insn.i_format.rt >> 2);
			bit += (bit != 0);
			bit += 23;
			switch (insn.i_format.rt & 3) {
				case 0: /* bc1f */
				case 2: /* bc1fl */
					if (~fcr31 & (1 << bit)) {
						epc = epc + 4 + (insn.i_format.simmediate << 2);
						if (insn.i_format.rt == 2)
							ret = BRANCH_LIKELY_TAKEN;
					} else
						epc += 8;
					regs->cp0_epc = epc;
					break;

				case 1: /* bc1t */
				case 3: /* bc1tl */
					if (fcr31 & (1 << bit)) {
						epc = epc + 4 + (insn.i_format.simmediate << 2);
						if (insn.i_format.rt == 3)
							ret = BRANCH_LIKELY_TAKEN;
					} else
						epc += 8;
					regs->cp0_epc = epc;
					break;
			}
			break;
#endif
	}

	return ret;

sigill:
	Trid_Print("DSP branch but not DSP ASE - sending SIGBUS.\n");
	return -EFAULT;
}

int __compute_return_epc(struct pt_regs *regs)
{
	unsigned int *addr;
	long epc;
	union mips_instruction insn;

	epc = regs->cp0_epc;
	if (epc & 3)
		goto unaligned;

	/*
	 * Read the instruction
	 */
	addr = (unsigned int *) epc;
	insn.word = *addr;

	return __compute_return_epc_for_insn(regs, insn);

unaligned:
	Trid_Print("unaligned epc - sending SIGBUS.\n");
	return -EFAULT;
}

static inline int compute_return_epc(struct pt_regs *regs)
{
	if (!delay_slot(regs)) {
		regs->cp0_epc += 4;
		return 0;
	}

	return __compute_return_epc(regs);
}

void do_watch(struct pt_regs *regs)
{
	unsigned int cause;
	int trap = (regs->cp0_cause & 0x7c) >> 2;
	cause = read_c0_cause();
	cause &= ~(1 << 22);
	write_c0_cause(cause);
	// Trid_Print("do watch..., cause=0x%x, clear=0x%x, epc=0x%x\n", cause, read_c0_cause(), regs->cp0_epc);

	//do_trap_or_bp(regs, trap, "Break");
	if (kgdb_handle_exception(trap, DIE_TRAP, regs))
		;
	// return NOTIFY_DONE;

	compute_return_epc(regs); 
	//Trid_Print("after do watch..., epc=0x%x\n", regs->cp0_epc);

	/* In SMP mode, __flush_cache_all does IPI */
	local_irq_enable();
	// __flush_cache_all();
	//return NOTIFY_STOP;
}
