#ifndef _ASM_MIPSREGS_H
#define _ASM_MIPSREGS_H

/*
 * Coprocessor 0 register names
 */
#define CP0_INDEX $0
#define CP0_RANDOM $1
#define CP0_ENTRYLO0 $2
#define CP0_ENTRYLO1 $3
#define CP0_CONF $3
#define CP0_CONTEXT $4
#define CP0_PAGEMASK $5
#define CP0_SEGCTL0 $5, 2
#define CP0_SEGCTL1 $5, 3
#define CP0_SEGCTL2 $5, 4
#define CP0_WIRED $6
#define CP0_INFO $7
#define CP0_HWRENA $7
#define CP0_BADVADDR $8
#define CP0_BADINSTR $8, 1
#define CP0_COUNT $9
#define CP0_ENTRYHI $10
#define CP0_GUESTCTL1 $10, 4
#define CP0_GUESTCTL2 $10, 5
#define CP0_GUESTCTL3 $10, 6
#define CP0_COMPARE $11
#define CP0_GUESTCTL0EXT $11, 4
#define CP0_STATUS $12
#define CP0_GUESTCTL0 $12, 6
#define CP0_GTOFFSET $12, 7
#define CP0_CAUSE $13
#define CP0_EPC $14
#define CP0_PRID $15
#define CP0_EBASE $15, 1
#define CP0_CMGCRBASE $15, 3
#define CP0_CONFIG $16
#define CP0_CONFIG3 $16, 3
#define CP0_CONFIG5 $16, 5
#define CP0_LLADDR $17
#define CP0_WATCHLO $18
#define CP0_WATCHHI $19
#define CP0_XCONTEXT $20
#define CP0_FRAMEMASK $21
#define CP0_DIAGNOSTIC $22
#define CP0_DEBUG $23
#define CP0_DEPC $24
#define CP0_PERFORMANCE $25
#define CP0_ECC $26
#define CP0_CACHEERR $27
#define CP0_TAGLO $28
#define CP0_TAGHI $29
#define CP0_ERROREPC $30
#define CP0_DESAVE $31


#define ST0_CH                  0x00040000
#define ST0_NMI                 0x00080000
#define ST0_SR                  0x00100000
#define ST0_TS                  0x00200000
#define ST0_BEV                 0x00400000
#define ST0_RE                  0x02000000
#define ST0_FR                  0x04000000
#define ST0_CU                  0xf0000000
#define ST0_CU0                 0x10000000
#define ST0_CU1                 0x20000000
#define ST0_CU2                 0x40000000
#define ST0_CU3                 0x80000000

/*
  * Cause.ExcCode trap codes.
  */
 #define EXCCODE_INT             0       /* Interrupt pending */
 #define EXCCODE_MOD             1       /* TLB modified fault */
 #define EXCCODE_TLBL            2       /* TLB miss on load or ifetch */
 #define EXCCODE_TLBS            3       /* TLB miss on a store */
 #define EXCCODE_ADEL            4       /* Address error on a load or ifetch */
 #define EXCCODE_ADES            5       /* Address error on a store */
 #define EXCCODE_IBE             6       /* Bus error on an ifetch */
 #define EXCCODE_DBE             7       /* Bus error on a load or store */
 #define EXCCODE_SYS             8       /* System call */
 #define EXCCODE_BP              9       /* Breakpoint */
 #define EXCCODE_RI              10      /* Reserved instruction exception */
 #define EXCCODE_CPU             11      /* Coprocessor unusable */
 #define EXCCODE_OV              12      /* Arithmetic overflow */
 #define EXCCODE_TR              13      /* Trap instruction */
 #define EXCCODE_MSAFPE          14      /* MSA floating point exception */
 #define EXCCODE_FPE             15      /* Floating point exception */
 #define EXCCODE_TLBRI           19      /* TLB Read-Inhibit exception */
 #define EXCCODE_TLBXI           20      /* TLB Execution-Inhibit exception */
 #define EXCCODE_MSADIS          21      /* MSA disabled exception */
 #define EXCCODE_MDMX            22      /* MDMX unusable exception */
 #define EXCCODE_WATCH           23      /* Watch address reference */
 #define EXCCODE_MCHECK          24      /* Machine check */
 #define EXCCODE_THREAD          25      /* Thread exceptions (MT) */
 #define EXCCODE_DSPDIS          26      /* DSP disabled exception */
 #define EXCCODE_GE              27      /* Virtualized guest exception (VZ) */

/* MIPS pt_regs offsets. */
 #define PT_R0 24 //offsetof(struct pt_regs, regs[0])
 #define PT_R1 28 //offsetof(struct pt_regs, regs[1])
 #define PT_R2 32 //offsetof(struct pt_regs, regs[2])
 #define PT_R3 36 //offsetof(struct pt_regs, regs[3])
 #define PT_R4 40 //offsetof(struct pt_regs, regs[4])
 #define PT_R5 44 //offsetof(struct pt_regs, regs[5])
 #define PT_R6 48 //offsetof(struct pt_regs, regs[6])
 #define PT_R7 52 //offsetof(struct pt_regs, regs[7])
 #define PT_R8 56 //offsetof(struct pt_regs, regs[8])
 #define PT_R9 60 //offsetof(struct pt_regs, regs[9])
 #define PT_R10 64 //offsetof(struct pt_regs, regs[10])
 #define PT_R11 68 //offsetof(struct pt_regs, regs[11])
 #define PT_R12 72 //offsetof(struct pt_regs, regs[12])
 #define PT_R13 76 //offsetof(struct pt_regs, regs[13])
 #define PT_R14 80 //offsetof(struct pt_regs, regs[14])
 #define PT_R15 84 //offsetof(struct pt_regs, regs[15])
 #define PT_R16 88 //offsetof(struct pt_regs, regs[16])
 #define PT_R17 92 //offsetof(struct pt_regs, regs[17])
 #define PT_R18 96 //offsetof(struct pt_regs, regs[18])
 #define PT_R19 100 //offsetof(struct pt_regs, regs[19])
 #define PT_R20 104 //offsetof(struct pt_regs, regs[20])
 #define PT_R21 108 //offsetof(struct pt_regs, regs[21])
 #define PT_R22 112 //offsetof(struct pt_regs, regs[22])
 #define PT_R23 116 //offsetof(struct pt_regs, regs[23])
 #define PT_R24 120 //offsetof(struct pt_regs, regs[24])
 #define PT_R25 124 //offsetof(struct pt_regs, regs[25])
 #define PT_R26 128 //offsetof(struct pt_regs, regs[26])
 #define PT_R27 132 //offsetof(struct pt_regs, regs[27])
 #define PT_R28 136 //offsetof(struct pt_regs, regs[28])
 #define PT_R29 140 //offsetof(struct pt_regs, regs[29])
 #define PT_R30 144 //offsetof(struct pt_regs, regs[30])
 #define PT_R31 148 //offsetof(struct pt_regs, regs[31])
 
 #define PT_LO 160 //offsetof(struct pt_regs, lo)
 #define PT_HI 156 //offsetof(struct pt_regs, hi)
 #define PT_EPC 172 //offsetof(struct pt_regs, cp0_epc)
 #define PT_BVADDR 164 //offsetof(struct pt_regs, cp0_badvaddr)
 #define PT_STATUS 152 //offsetof(struct pt_regs, cp0_status)
 #define PT_CAUSE 168 //offsetof(struct pt_regs, cp0_cause)
 
 #define PT_SIZE 176 //sizeof(struct pt_regs)

 #endif
