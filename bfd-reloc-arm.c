/* $Id$ */

/* 
 * Authorship
 * ----------
 * This software ('pmbfd' BFD emulation for cexpsh) was created by
 *     Till Straumann <strauman@slac.stanford.edu>, 2008,
 * 	   Stanford Linear Accelerator Center, Stanford University.
 * 
 * Acknowledgement of sponsorship
 * ------------------------------
 * This software was produced by
 *     the Stanford Linear Accelerator Center, Stanford University,
 * 	   under Contract DE-AC03-76SFO0515 with the Department of Energy.
 * 
 * Government disclaimer of liability
 * ----------------------------------
 * Neither the United States nor the United States Department of Energy,
 * nor any of their employees, makes any warranty, express or implied, or
 * assumes any legal liability or responsibility for the accuracy,
 * completeness, or usefulness of any data, apparatus, product, or process
 * disclosed, or represents that its use would not infringe privately owned
 * rights.
 * 
 * Stanford disclaimer of liability
 * --------------------------------
 * Stanford University makes no representations or warranties, express or
 * implied, nor assumes any liability for the use of this software.
 * 
 * Stanford disclaimer of copyright
 * --------------------------------
 * Stanford University, owner of the copyright, hereby disclaims its
 * copyright and all other rights in this software.  Hence, anyone may
 * freely use it for any purpose without restriction.  
 * 
 * Maintenance of notices
 * ----------------------
 * In the interest of clarity regarding the origin and status of this
 * SLAC software, this and all the preceding Stanford University notices
 * are to remain affixed to any copy or derivative of this software made
 * or distributed by the recipient and are to be affixed to any copy of
 * software made or distributed by the recipient that contains a copy or
 * derivative of this software.
 * 
 * ------------------ SLAC Software Notices, Set 4 OTT.002a, 2004 FEB 03
 */ 

#include "pmbfdP.h"

#define TARGET2_REL

int
pmbfd_make_veneer(bfd_vma symval, uint16_t symflags, uint8_t **text_mem)
{
const uint16_t bx_pc = 0x4778; 
const uint16_t nop   = 0x46c0;
uint32_t       b_arm;
int32_t        off;
uint8_t       *p;

	/* Make Thumb->ARM veneer */

	if ( symval & 1 )
		return 0;

	if ( text_mem ) {
		p = (uint8_t*) align_power( (uintptr_t)*text_mem, 2 );

		off = (int32_t)symval - ((int32_t)p + 8 + 4);
		if ( off > (int32_t)0x01ffffff || off < (int32_t)0xfe000000 ) {
			/* veneer cannot reach target */
			return 0;
		}

		if ( off & 2 ) {
			/* veneer target misaligned */
			return 0;
		}

		memcpy(p + 0, &bx_pc, sizeof(bx_pc));
		memcpy(p + 2, &nop,   sizeof(nop  ));

		b_arm = 0xea000000 | ( (off>>2) & 0x00ffffff);

		memcpy(p + 4, &b_arm, sizeof(b_arm));
	}
	return 8;

}


/* ARM relocs used by rtems-4.12 so far:
	R_ARM_ABS32
	R_ARM_PREL31
	R_ARM_THM_CALL
	R_ARM_THM_JUMP24
	R_ARM_THM_MOVT_ABS
	R_ARM_THM_MOVW_ABS_NC
*/

bfd_reloc_status_type
pmbfd_perform_relocation(bfd *abfd, pmbfd_relent_t rtype, pmbfd_arelent *r, asymbol *psym, asection *input_section, void **veneer_info)
{
Elf32_Word     pc;
int32_t        val, symval;
uint32_t       oval,nval;
uint8_t        type  = ELF32_R_TYPE(r->rel32.r_info);
uint32_t       offset;
uint32_t       addend = 0; /* keep compiler happy */
uint32_t       s,i1,i2,t;
int            pcrel;
int32_t        max, min;
int            fromThumb = -1, toThumb = -1;

	if ( R_ARM_NONE == type ) {
		/* No-op */
		return bfd_reloc_ok;
	}

	if ( bfd_is_und_section(bfd_get_section(psym)) )
		return bfd_reloc_undefined;

	/* REL or RELA ? */
	switch ( rtype ) {

		default:
			fprintf(stderr,"relocation neither REL nor RELA?\n");
			return bfd_reloc_other;

		case Relent_RELA32:
			type   = ELF32_R_TYPE( r->rela32.r_info );
			offset = r->rela32.r_offset;
			addend = r->rela32.r_addend;
		break;

		case Relent_REL32:
			type   = ELF32_R_TYPE( r->rel32.r_info );
			offset = r->rel32.r_offset;
		break;
	}

	if ( offset > bfd_get_section_size( input_section ) - sizeof(uint32_t) ) {
		return bfd_reloc_outofrange;
	}

	pc  = bfd_get_section_vma(abfd, input_section) + offset;

	if ( (pc & 1) ) {
		fprintf(stderr,"PC should be half-word aligned!\n");
		return bfd_reloc_other;
	}

	memcpy( &oval, (char*)pc, sizeof(addend) );

	/* fetch REL addend */
	if ( Relent_REL32 == rtype ) {
		addend = oval;
		switch ( type ) {
			default:
				return bfd_reloc_notsupported;

			case R_ARM_ABS32:
			case R_ARM_REL32:
			case R_ARM_TARGET1:
			case R_ARM_TARGET2:
				/* nothing to do */
				break;

			case R_ARM_PREL31:
				/* sign extend bit 30 */
				if ( (1<<30) & addend )
					addend |=  (1<<31);
				else
					addend &= ~(1<<31);
				break;

			case R_ARM_THM_JUMP24:
			case R_ARM_THM_CALL:
				fromThumb = 1;
				/* extract immediate operand */
				s  =  (addend & (1<<10)) ? 0xff000000 : 0;
				i1 = ~(addend ^ s); /* 's' mask includes j1 and j2 */
				i2 = (i1 & (1<<(16+11))) >> (16+11 - 22);
				i1 = (i1 & (1<<(16+13))) >> (16+13 - 23);
				addend  = ((addend >> 15) & 0xffe) | ( (addend & 0x3ff) << 12 );
				addend |= i1 | i2 | s;
				break;

			case R_ARM_THM_MOVW_ABS_NC:
			case R_ARM_THM_MOVT_ABS:
				fromThumb = 1;
				addend =   ((addend & 0xf)        << (12 + 16)   ) 
					| ((addend & (1<<10))    << (11-10 + 16))
					| ((addend & 0x70000000) >> (12 - 8)    )
					| ((addend & 0x00ff0000) >> ( 0 - 0)    );

				if ( R_ARM_THM_MOVW_ABS_NC == type ) {
					addend >>= 16;
				}
				break;
		}
	}

	max   = 0;
	min   = 0;
	pcrel = 0;

	switch ( type ) {
		case R_ARM_PREL31:
			pcrel = 1;
			max   = (1<<30) - 1;
		break;

		case R_ARM_THM_CALL:
		case R_ARM_THM_JUMP24:
			pcrel = 1;
			max   = (1<<24) - 1;
		break;

		case R_ARM_REL32:
#ifdef TARGET2_REL
		case R_ARM_TARGET2:
#endif
#ifdef TARGET1_REL
		case R_ARM_TARGET1:
#endif
			pcrel = 1;
		break;

		default:
		break;
	}

	if ( max && ! min )
		min = ~max;

	/* compute value */

	symval = val = (int32_t)bfd_asymbol_value(psym);

	t   = 0;

	/* strip thumb bit from symbol value */
	if ( fromThumb >= 0 ) {
		/* The built-in symbol table cannot always get the type of a symbol right
		 * (because 'nm' provides only a single-letter code; e.g., a weak function is
		 * reported just as 'W').
		 * Thus, if we are relocating a jump we assume that we are indeed targeting
		 * a function...
		 */
		switch ( type ) {
			default:
				if ( ! (BSF_FUNCTION & psym->flags) )
					break;
				/* else fall through */
			case R_ARM_THM_CALL:
			case R_ARM_THM_JUMP24:
				if ( (toThumb = !!(val & 1) ) ) {
					val        &= 0xfffffffe;
					t           = 1;
				} else {
					int32_t blx_offset = val + addend - pc;
					if ( R_ARM_THM_JUMP24 == type || (blx_offset & 2) ) {
						/* requires a veneer */
						if ( veneer_info ) {
							val  = ((int32_t)*veneer_info) & 0xfffffffe;
							/* change to/preserve b.w instruction */
							t    = 1;
						} else {
							fprintf(stderr,"No veneer found; cannot relocate thumb->ARM\n");
							return bfd_reloc_notsupported;
						}
					} else {
						/* ! toThumb && R_ARM_THM_CALL == type */
						oval &= ~(1<<(12+16));
					}

				}
				break;
		}
		if ( (addend & 1) ) {
			/* Can this happen ? */
			fprintf(stderr,"Unexpected odd addend\n");
			fprintf(stderr,"Relocating val: 0x%04"PRIx32", min: 0x%04"PRIx32", max: 0x%04"PRIx32", addend: 0x%04"PRIx32", pc: 0x%04"PRIx32", sym: 0x%08lx\n",
				val, min, max, addend, pc, symval);
			return bfd_reloc_notsupported;
		}
	}

	/* if we have a 't' from the symbol then let it override one that might
	 * be in the addend. Otherwise, preserve addend.
	 */
	val = (val + addend);

	if ( pcrel )
		val -= pc;

	if ( max > min && ( (int32_t)val > max || (int32_t)val < min ) ) {
		fprintf(stderr,"Relocating val: 0x%04"PRIx32", min: 0x%04"PRIx32", max: 0x%04"PRIx32", addend: 0x%04"PRIx32", pc: 0x%04"PRIx32", sym: 0x%08lx\n",
			val, min, max, addend, pc, symval);
		return bfd_reloc_overflow;
	}

	val |= t;

#if (DEBUG & DEBUG_RELOC)
	fprintf(stderr,"Relocating val: 0x%04"PRIx32", min: 0x%04"PRIx32", max: 0x%04"PRIx32", addend: 0x%04"PRIx32", pc: 0x%04"PRIx32", original val: 0x%04"PRIx32", sym: 0x%08lx\n",
		val, min, max, addend, pc, oval, symval);
#endif

	/* patch back */
	switch ( type ) {
		default:
			return bfd_reloc_notsupported;

		case R_ARM_ABS32:
		case R_ARM_REL32:
		case R_ARM_TARGET1:
		case R_ARM_TARGET2:
			nval = val;
			break;

		case R_ARM_PREL31:
			nval = (oval & (1<<31)) | (val & 0x7fffffff);
			break;

		case R_ARM_THM_JUMP24:
			/* B.W */
		case R_ARM_THM_CALL:

			/* BL <imm> / BLX <imm> */

			nval  =  (val & 0x000ffe) << (16 - 1);
			nval |=  (val & 0x3ff000) >> (12 - 0);
			nval |=  (val & (1<<24))  >> (24 - 10); /* S */
			i1    =  ((~val ^ (val >> 1)) & (1<<23)) << (13+16 - 23);
			i2    =  ((~val ^ (val >> 2)) & (1<<22)) << (11+16 - 22);

			nval |= (oval & 0xd000f800) | i1 | i2;

			break;

		case R_ARM_THM_MOVW_ABS_NC:
		case R_ARM_THM_MOVT_ABS:

			i2 = val;
			if ( R_ARM_THM_MOVW_ABS_NC == type ) {
				i2 <<= 16;
			}
			nval  = (i2 & 0x00ff0000);
			nval |= (i2 & 0x07000000) << 4;
			nval |= (i2 & 0x08000000) >> (11+16 - 10);
			nval |= (i2 & 0xf0000000) >> (12+16 -  0);
			nval |= (oval & 0x8f00fbf0);

			break;
	}

	memcpy( (char*)pc, &nval, sizeof(nval) );

	return bfd_reloc_ok;
}

const char *
pmbfd_reloc_get_name(bfd *abfd, pmbfd_arelent *r)
{
	return pmelf_arm_rel_name(&r->rel32);
}
