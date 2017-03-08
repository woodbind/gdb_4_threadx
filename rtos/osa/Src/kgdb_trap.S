#include "kgdb_mips.h"

#define STATMASK 0x1f

/*
 * NESTED - declare nested routine entry point
 */
#define NESTED(symbol, framesize, rpc)              \
			.globl  symbol;                         \
			.align  2;                              \
			.type   symbol, @function;              \
			.ent    symbol, 0;                      \
symbol:     


#define LEAF(symbol)                                    \
            .globl  symbol;                         \
            .align  2;                              \
            .type   symbol, @function;              \
            .ent    symbol, 0;                      \
symbol:
 

/*
 * END - mark end of function
 */
#define END(function)                               \
			.end    function;                       \
			.size   function, .-function


.macro  SAVE_AT
			.set    push
			.set    noat
			sw      $1, PT_R1($sp)
			.set    pop
.endm

.macro  SAVE_TEMP
			mfhi    $v1
			sw      $8, PT_R8($sp)
			sw      $9, PT_R9($sp)
			sw      $10, PT_R10($sp)
			sw      $11, PT_R11($sp)
			sw      $12, PT_R12($sp)
			sw      $v1, PT_HI($sp)
			mflo    $v1
			sw      $13, PT_R13($sp)
			sw      $14, PT_R14($sp)
			sw      $15, PT_R15($sp)
			sw      $24, PT_R24($sp)
			sw      $v1, PT_LO($sp)
.endm

.macro  SAVE_STATIC
	        sw  $16, PT_R16($sp)
	        sw  $17, PT_R17($sp)
	        sw  $18, PT_R18($sp)
	        sw  $19, PT_R19($sp)
	        sw  $20, PT_R20($sp)
	        sw  $21, PT_R21($sp)
	        sw  $22, PT_R22($sp)
	        sw  $23, PT_R23($sp)
         	sw  $30, PT_R30($sp)
.endm

.macro  SAVE_SOME
		         .set    push
		         .set    noat
		         .set    reorder
				 move    $k0, $sp
				 move    $k1, $sp
		         subu    $sp, $k1, PT_SIZE

		         sw  $k0, PT_R29($sp)
		         sw  $3, PT_R3($sp)
		         /*
		          * You might think that you don't need to save $0,
		          * but the FPU emulator and gdb remote debug stub
		          * need it to operate correctly
		          */
		         sw  $0, PT_R0($sp)
		         mfc0  $v1, CP0_STATUS
		         sw  $2, PT_R2($sp)
		         sw  $v1, PT_STATUS($sp)
		         sw  $4, PT_R4($sp)
		         mfc0    $v1, CP0_CAUSE
		         sw  $5, PT_R5($sp)
		         sw  $v1, PT_CAUSE($sp)
		         sw  $6, PT_R6($sp)
		         mfc0    $v1, CP0_EPC
		         sw  $7, PT_R7($sp)
		         sw  $v1, PT_EPC($sp)
		         sw  $25, PT_R25($sp)
		         sw  $28, PT_R28($sp)
		         sw  $31, PT_R31($sp)
		         /*ori $28, $sp, _THREAD_MASK
		         xori    $28, _THREAD_MASK */
		         .set    pop
.endm

.macro  SAVE_ALL
         	SAVE_SOME
         	SAVE_AT
         	SAVE_TEMP
         	SAVE_STATIC
.endm

        .macro  RESTORE_AT
		         .set    push
		         .set    noat
		         lw  $1,  PT_R1($sp)
		         .set    pop
        .endm

        .macro  RESTORE_TEMP
		         lw  $24, PT_LO($sp)
		         mtlo    $24
		         lw  $24, PT_HI($sp)
		         mthi    $24
		         lw  $8, PT_R8($sp)
		         lw  $9, PT_R9($sp)
		         lw  $10, PT_R10($sp)
		         lw  $11, PT_R11($sp)
		         lw  $12, PT_R12($sp)
		         lw  $13, PT_R13($sp)
		         lw  $14, PT_R14($sp)
		         lw  $15, PT_R15($sp)
		         lw  $24, PT_R24($sp)
		.endm

		.macro  RESTORE_STATIC
         		lw  $16, PT_R16($sp)
         		lw  $17, PT_R17($sp)
         		lw  $18, PT_R18($sp)
         		lw  $19, PT_R19($sp)
         		lw  $20, PT_R20($sp)
         		lw  $21, PT_R21($sp)
         		lw  $22, PT_R22($sp)
         		lw  $23, PT_R23($sp)
         		lw  $30, PT_R30($sp)
         .endm


.macro  RESTORE_SOME
         .set    push
         .set    reorder
         .set    noat
         mfc0    $a0, CP0_STATUS
         ori $a0, STATMASK
         xori    $a0, STATMASK
         mtc0    $a0, CP0_STATUS
         li  $v1, 0xff00
         and $a0, $v1
         lw  $v0, PT_STATUS($sp)
         nor $v1, $0, $v1
         and $v0, $v1
         or  $v0, $a0
         mtc0    $v0, CP0_STATUS
         lw  $v1, PT_EPC($sp)
         mtc0    $v1, CP0_EPC
         lw  $31, PT_R31($sp)
         lw  $28, PT_R28($sp)
         lw  $25, PT_R25($sp)
         lw  $7,  PT_R7($sp)
         lw  $6,  PT_R6($sp)
         lw  $5,  PT_R5($sp)
         lw  $4,  PT_R4($sp)
         lw  $3,  PT_R3($sp)
         lw  $2,  PT_R2($sp)
         .set    pop
        .endm

		 .macro  RESTORE_SP_AND_RET
		          lw  $sp, PT_R29($sp)
		          .set    mips3
		          eret
				  ssnop
				  ssnop
		          .set    mips0
		 .endm

 .align  2
exception_handlers:
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word handle_bp  /* 9 */
			.word handle_bp /* OSA_Debug_Exception_Handler*/
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word handle_tr  /* 13 */
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word handle_watch  /* 23 */
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.word OSA_Debug_Exception_Handler
			.size   exception_handlers,.-exception_handlers

    .macro  local_irq_enable reg=t0
	     ei
		 /*mfc0    $\reg, CP0_STATUS
		 ori $\reg, $\reg, 1
		 mtc0    $\reg, CP0_STATUS*/
	     ssnop
		 ssnop
		 sync
		 ehb
	.endm
	 
	.macro  local_irq_disable reg=t0
	     di
		 /*mfc0    $\reg, CP0_STATUS
		 ori $\reg, $\reg, 1
		 xori    $\reg, $\reg, 1
		 mtc0    $\reg, CP0_STATUS*/
	     ssnop
		 ssnop
		 sync
		 ehb
	.endm

    		.text
	      	.align  5
			.globl  ret_from_exception
			.type   ret_from_exception, @function
ret_from_exception:
	         local_irq_disable           # preempt stop
		     b   restore_all
			 nop

restore_all:                # restore full frame
	     .set    noat
	     RESTORE_TEMP
	     RESTORE_AT
	     RESTORE_STATIC
	     RESTORE_SOME
	     RESTORE_SP_AND_RET
	     .set    at

		
         .macro  CLI
		          mfc0    $t0, CP0_STATUS
		          li  $t1, ST0_CU0 | STATMASK
		          or  $t0, $t1
		          xori    $t0, STATMASK
		          mtc0    $t0, CP0_STATUS
		.endm

		.macro STI
				  mfc0    $t0, CP0_STATUS
				  li  $t1, ST0_CU0 | STATMASK
				  or  $t0, $t1
				  xori    $t0, STATMASK & ~1
				  mtc0    $t0, CP0_STATUS
		.endm

  	.macro  __build_clear_sti
			STI
       		ssnop
	        ssnop
	        ssnop
	        ehb
    .endm
   
    .macro  __build_clear_cli
			CLI
       		ssnop
	        ssnop
	        ssnop
	        ehb
    .endm

    .macro  __BUILD_HANDLER exception handler clear
	     .align  5
	     NESTED(handle_\exception, PT_SIZE, sp)
	     .set    noat
	     SAVE_ALL
	     __BUILD_clear_\clear
	     .set    at
	     move    $a0, $sp
	     la  $ra, ret_from_exception
	     j   do_\handler
	     END(handle_\exception)
	.endm
	 
	.macro  BUILD_HANDLER exception handler clear
	     __BUILD_HANDLER \exception \handler \clear
	.endm

    BUILD_HANDLER bp bp sti          /* #9  */
	BUILD_HANDLER tr tr sti          /* #13 */
	     /*
	      * For watch, interrupts will be enabled after the watch
	      * registers are read.
	      */
	BUILD_HANDLER watch watch cli       /* #23 */

/*
 * General exception vector for all other CPUs.
 */

NESTED(except_vec3_generic, 0, sp)
			.set    push
			.set    noat
			mfc0    $k1, CP0_CAUSE
			andi    $k1, $k1, 0x7c
			lw      $k0, exception_handlers($k1)
			jr      $k0
			.set    pop
END(except_vec3_generic)

