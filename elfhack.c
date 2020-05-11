//https://www.codeproject.com/Articles/30824/PLT-redirection-through-shared-object-injection-in
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <elf.h>
#include <unistd.h>

Elf32_Shdr *ztextShdr, *gotShdr, *dynShdr = NULL;
Elf32_Shdr *relBssShdr = NULL;
Elf32_Shdr *relZtextShdr = NULL;
Elf32_Shdr *relGotShdr, *relDynShdr, *relDataShdr, *relRoDataShdr;
Elf32_Shdr *initArrayShdr, *finiArrayShdr, *dataShdr, *roDataShdr;
Elf32_Shdr *relInitArrayShdr, *relFiniArrayShdr;
Elf32_Sym  *dynsymZtextStart, *symGotPlt, *symPltStart, *symPltEnd;
int dynamicSectionIndex, dynsymSectionIndex, xbssSectionIndex;
Elf32_Shdr *all_sections;
int ztext_start_symidx;
int e_machine;
            
int RELOC_PC32;
int RELOC_GOTPC;
int RELOC_GOTOFF;
int RELOC_PLT32;
int RELOC_GOT32X;
int RELOC_RELATIVE;
int RELOC_COPY;

int elf_is_valid(Elf32_Ehdr * elf_hdr)
{
	if ((elf_hdr->e_ident[EI_MAG0] != 0x7F) ||
	    (elf_hdr->e_ident[EI_MAG1] != 'E') ||
	    (elf_hdr->e_ident[EI_MAG2] != 'L') ||
	    (elf_hdr->e_ident[EI_MAG3] != 'F')) {
		return 0;
	}

	if (elf_hdr->e_ident[EI_CLASS] != ELFCLASS32) {
        fprintf(stderr, "ELF isn't ELFCLASS32\n");
		return 0;
    }

	if (elf_hdr->e_ident[EI_DATA] != ELFDATA2LSB)
		return 0;

	return 1;
}

static char *elf_types[] = {
	"ET_NONE",
	"ET_REL",
	"ET_EXEC",
	"ET_DYN",
	"ET_CORE",
	"ET_NUM"
};

char *get_elf_type(Elf32_Ehdr * elf_hdr)
{
	if (elf_hdr->e_type > 5)
		return NULL;

	return elf_types[elf_hdr->e_type];
}

int print_elf_header(Elf32_Ehdr * elf_hdr)
{
	char *sz_elf_type = NULL;

	if (!elf_hdr)
		return 0;

	printf("ELF header information\n");

	sz_elf_type = get_elf_type(elf_hdr);
	if (sz_elf_type)
		printf("- Type: %s\n", sz_elf_type);
	else
		printf("- Type: %04x\n", elf_hdr->e_type);

	printf("- Version: %d\n", elf_hdr->e_version);
    printf("- Machine: %d\n", elf_hdr->e_machine);
    e_machine = elf_hdr->e_machine;
    if (e_machine == EM_386) {
        RELOC_PC32 = R_386_PC32;
        RELOC_GOTPC = R_386_GOTPC;
        RELOC_GOTOFF = R_386_GOTOFF;
        RELOC_PLT32 = R_386_PLT32;
        RELOC_GOT32X = R_386_GOT32X;
        RELOC_RELATIVE = R_386_RELATIVE;
        RELOC_COPY = R_386_COPY;
    } else if (e_machine == EM_ARM) {
        RELOC_PC32 = R_ARM_REL32;
        RELOC_GOTPC = R_ARM_GOTPC;
        RELOC_GOTOFF = R_ARM_GOTOFF;
        RELOC_PLT32 = R_ARM_PLT32;
        RELOC_GOT32X = 0;
        RELOC_RELATIVE = R_ARM_RELATIVE;
        RELOC_COPY = R_ARM_COPY;
    } else {
        fprintf(stderr, "Unsupported ELF machine type %d\n", e_machine);
        exit(1);
    }
	printf("- Entrypoint: 0x%08x\n", elf_hdr->e_entry);
	printf("- Program header table offset: 0x%08x\n", elf_hdr->e_phoff);
	printf("- Section header table offset: 0x%08x\n", elf_hdr->e_shoff);
	printf("- Flags: 0x%08x\n", elf_hdr->e_flags);
	printf("- ELF header size: %d\n", elf_hdr->e_ehsize);
	printf("- Program header size: %d\n", elf_hdr->e_phentsize);
	printf("- Program header entries: %d\n", elf_hdr->e_phnum);
	printf("- Section header size: %d\n", elf_hdr->e_shentsize);
	printf("- Section header entries: %d\n", elf_hdr->e_shnum);
	printf("- Section string table index: %d\n", elf_hdr->e_shstrndx);

	return 1;
}

static char *btypes[] = {
	"STB_LOCAL",
	"STB_GLOBAL",
	"STB_WEAK"
};

static char *symtypes[] = {
	"STT_NOTYPE",
	"STT_OBJECT",
	"STT_FUNC",
	"STT_SECTION",
	"STT_FILE"
};

void print_bind_type(uint8_t info)
{
	uint8_t bind = ELF32_ST_BIND(info);
	if (bind <= 2)
		printf("- Bind type: %s\n", btypes[bind]);
	else
		printf("- Bind type: %d\n", bind);
}

void print_sym_type(uint8_t info)
{
	uint8_t type = ELF32_ST_TYPE(info);

	if (type <= 4)
		printf("- Symbol type: %s\n", symtypes[type]);
	else
		printf("- Symbol type: %d\n", type);
}

int print_sym_table(uint8_t * filebase, Elf32_Shdr * section, char *strtable)
{
	Elf32_Sym *symbols;
	size_t sym_size = section->sh_entsize;
	size_t cur_size = 0;

	if (section->sh_type == SHT_SYMTAB)
		printf("Symbol table\n");
	else
		printf("Dynamic symbol table\n");

	if (sym_size != sizeof(Elf32_Sym)) {
		printf("There's something evil with symbol table...\n");
		return 0;
	}

	symbols = (Elf32_Sym *) (filebase + section->sh_offset);
	symbols++;
	cur_size += sym_size;
	do {
		/*printf("- Name index: %d\n", symbols->st_name);
		printf("- Name: %s\n", strtable + symbols->st_name);*/
        char *name = strtable + symbols->st_name;
        if (!strcmp(name, "_GLOBAL_OFFSET_TABLE_")) {
            // Found _GLOBAL_OFFSET_TABLE_ which is .got.plt, part of .ztext with my linker script.
            // That one contains absolute pointers that need to be fixed up.
            symGotPlt = symbols;
        } else if (!strcmp(name, "_ztext_start") && section->sh_type == SHT_DYNSYM) {
            dynsymZtextStart = symbols;
            ztext_start_symidx = symbols - (Elf32_Sym *) (filebase + section->sh_offset);
        } else if (!strcmp(name, "_plt_start")) {
            symPltStart = symbols;
        } else if (!strcmp(name, "_plt_end")) {
            symPltEnd = symbols;
        }
/*		printf("- Value: 0x%08x\n", symbols->st_value);
		printf("- Size: 0x%08x\n", symbols->st_size);

		print_bind_type(symbols->st_info);
		print_sym_type(symbols->st_info);

		printf("- Section index: %d\n", symbols->st_shndx);*/
		cur_size += sym_size;
		symbols++;
	} while (cur_size < section->sh_size);

	return 1;
}
static char *ptypes[] = {
        "PT_NULL",
        "PT_LOAD",
        "PT_DYNAMIC",
        "PT_INTERP",
        "PT_NOTE",
        "PT_SHLIB",
        "PT_PHDR"
};

int print_program_header(Elf32_Phdr *phdr, uint index)
{
    if(!phdr)
        return 0;

//    printf("Program header %d\n", index);
    if(phdr->p_type <= 6)
        printf("  %s", ptypes[phdr->p_type]);
    else
        printf("  %08x", phdr->p_type);

    printf("\t%#08x", phdr->p_offset);
    printf("\t%#08x", phdr->p_vaddr);
    printf("\t%#08x", phdr->p_paddr);
    printf("\t%#08x", phdr->p_filesz);
    printf("\t%#08x", phdr->p_memsz);
    printf("\t%03d", phdr->p_flags);
    printf("\t%#08x\n", phdr->p_align);
}

static char *stypes[] = {
        "SHT_NULL",
        "SHT_PROGBITS",
        "SHT_SYMTAB",
        "SHT_STRTAB",
        "SHT_RELA",
        "SHT_HASH",
        "SHT_DYNAMIC",
        "SHT_NOTE",
        "SHT_NOBITS",
        "SHT_REL",
        "SHT_SHLIB",
        "SHT_DYNSYM"
};

int print_section_header(Elf32_Shdr *shdr, uint index, char *strtable, uint8_t *p_base)
{
    if(!shdr)
        return 0;

    printf("Section header: %d\n", index);
//    printf("\tName index: %d\n", shdr->sh_name);
    
    //as you can see, we're using sh_name as an index into the string table
    printf("\tName: %s\n", strtable + shdr->sh_name);

    char *name = strtable + shdr->sh_name;
    if (!strcmp(name, ".ztext")) {
        // Found .ztext
        ztextShdr = shdr;
    } else if (!strcmp(name, ".rel.bss")) {
        // Found .rel.bss
        // ... and it has bits that we can overwrite (executable vs. .so, possibly a ld bug)
        if (shdr->sh_type == SHT_NOBITS) {
            fprintf(stderr, "Error: found .rel.bss but is SHT_NOBITS, no space to inject a relocation there\n");
            exit(1);
        }
        relBssShdr = shdr;
    } else if (!strcmp(name, ".xbss")) {
        // Found .xbss
        xbssSectionIndex = index;
    } else if (!strcmp(name, ".rel.ztext")) {
        relZtextShdr = shdr;
    } else if (!strcmp(name, ".rel.got")) {
        relGotShdr = shdr;
    } else if (!strcmp(name, ".got")) {
        gotShdr = shdr;
    } else if (!strcmp(name, ".init_array")) {
        initArrayShdr = shdr;
    } else if (!strcmp(name, ".fini_array")) {
        finiArrayShdr = shdr;
    } else if (!strcmp(name, ".rel.init_array")) {
        relInitArrayShdr = shdr;
    } else if (!strcmp(name, ".rel.fini_array")) {
        relFiniArrayShdr = shdr;
    } else if (!strcmp(name, ".data")) {
        dataShdr = shdr;
    } else if (!strcmp(name, ".rodata")) {
        roDataShdr = shdr;
    } else if (!strcmp(name, ".rel.data")) {
        relDataShdr = shdr;
    } else if (!strcmp(name, ".rel.rodata")) {
        relRoDataShdr = shdr;
    }

    if(shdr->sh_type <= 11)
        printf("\tType: %s\n", stypes[shdr->sh_type]);
    else
        printf("\tType: %04x\n", shdr->sh_type);
    printf("\tFlags: %08x\n", shdr->sh_flags);
    printf("\tAddress: %08x\n", shdr->sh_addr);
    printf("\tOffset: %08x\n", shdr->sh_offset);
    printf("\tSize: %08x\n", shdr->sh_size);
    printf("\tLink %08x\n", shdr->sh_link);
    printf("\tInfo: %08x\n", shdr->sh_info);
    printf("\tAddress alignment: %08x\n", shdr->sh_addralign);
    printf("\tEntry size: %08x\n", shdr->sh_entsize);

}

int looks_like_code_address(Elf32_Addr addr)
{
    if (addr >= ztextShdr->sh_addr && addr < (Elf32_Addr)(ztextShdr->sh_addr + ztextShdr->sh_size)) {
        return 1;
    }
    return 0;
}
// Fix up relocation values for section s whose relocations are listed in relocs.
// e.g. fixup_relocations_for_section(.rel.ztext, .ztext)
void fixup_relocations_for_section(uint8_t *p_base, Elf32_Shdr *relocs, Elf32_Shdr *s, int32_t ztextToXbss, Elf32_Shdr *all_sections)
{
    int nb = relocs->sh_size / sizeof(Elf32_Rel);
    Elf32_Rel *rel = (Elf32_Rel *)(p_base + relocs->sh_offset);
    uint8_t *codePtr = (uint8_t *)(p_base + s->sh_offset);
    Elf32_Sym *symbols = (Elf32_Sym *)(p_base + all_sections[relocs->sh_link].sh_offset);

    for (int i = 0; i < nb; i++) {
        int type = ELF32_R_TYPE(rel->r_info);
        int symbol = ELF32_R_SYM(rel->r_info);
        Elf32_Addr symval = symbols[symbol].st_value;
        Elf32_Addr *fixup = (Elf32_Addr *)(codePtr + rel->r_offset - s->sh_addr);

//            https://docs.oracle.com/cd/E19120-01/open.solaris/819-0690/chapter6-26/index.html
        if (type == RELOC_PC32) {
            // PC-relative  S + A - P 
            // if P and S is in .ztext, nothing changes
            // otherwise handle it..
            uint8_t symbolIsText = looks_like_code_address(symval);
            uint8_t sectionIsText = looks_like_code_address(s->sh_addr);
            if (symbolIsText && !sectionIsText) {
                printf("\tRELOC_PC32 relocation @%p concerns code addr %p\n", rel->r_offset, symval);
                *fixup += ztextToXbss;
            }
        } else if (type == RELOC_GOTPC && e_machine == EM_386) {
            //  GOT + A - P 
            // P is moving by (.xbss - .ztext)
            printf("\tGOTPC reloc @%p %#x must be fixed\n", rel->r_offset);
            *fixup -= ztextToXbss;
        } else if (type == RELOC_GOTOFF) {
            // S + A - GOT
            if (looks_like_code_address(symval)) {
                printf("\tGOTOFF relocation @%p concerns code addr %p\n", rel->r_offset, symval);
                *fixup += ztextToXbss;
            }
        } else if (type == RELOC_PLT32) {
            //  L + A - P  (L is .plt)
            // Nothing to do, both L and P move so it's fine
        } else if (type == RELOC_GOT32X) {
            // XXX
        } else if (type == RELOC_RELATIVE) {
            *fixup += ztextToXbss;
            printf("\tRELATIVE reloc @%p fixed up\n", rel->r_offset);
        } else if (e_machine == EM_ARM) {
           if (type == R_ARM_GOTPC) {
               // B(S) + A - P
               if (!looks_like_code_address(symval)) {
                   printf("\tR_ARM_BASE_PREL reloc @%p fixed up\n", rel->r_offset);
                   *fixup -= ztextToXbss;
               }
            } else if (type == R_ARM_ABS32 || type == R_ARM_TARGET1) {
                // XXX TARGET1 could be REL on some platforms, I'm not sure how to know
                // S + A
                if (looks_like_code_address(symval)) {
                    printf("\tR_ARM_ABS32 relocation @%p concerns code addr %p\n", rel->r_offset, symval);
                    *fixup += ztextToXbss;
                }

            } 
        } else if (e_machine == EM_386) {
            if (type == R_386_32) {
                // S + A: if S moves, handle it
                if (looks_like_code_address(symval)) {
                    printf("\tR_386_32 relocation @%p concerns code addr %p\n", rel->r_offset, symval);
                    *fixup += ztextToXbss;
                }
            }

        }
/*
000090b4  0000591a R_ARM_GOT_BREL    00000000   __gmon_start__
GOT(S) + A - GOT_ORG
no change

00009080  0000571c R_ARM_CALL        0000902c   __libc_start_main@@GLI
00009084  0000541c R_ARM_CALL        00009020   abort@@GLIBC_2.4
0000911c  0000661c R_ARM_CALL        00009044   puts@@GLIBC_2.4
00009124  00006d1c R_ARM_CALL        00009050   exit@@GLIBC_2.4
((S + A) | T) - P
no change


00009088  00005502 R_ARM_ABS32       0000912c   __libc_csu_fini
0000908c  00006e02 R_ARM_ABS32       00009104   main
00009090  00006202 R_ARM_ABS32       00009130   __libc_csu_init
000090d0  00001602 R_ARM_ABS32       00011804   .bss
000090fc  00001202 R_ARM_ABS32       000116e4   .jcr
00009100  00005a02 R_ARM_ABS32       00000000   _Jv_RegisterClasses
00009128  00000c02 R_ARM_ABS32       00009660   .rodata
S+A

00009190  00004e18 R_ARM_GOTOFF32    000116dc   __init_array_start
00009194  00004d18 R_ARM_GOTOFF32    000116e0   __init_array_end
((S + A) | T) - GOT_ORG
    */


        rel++;
    }

}

uint32_t arm_encode_addimm(uint32_t encode) {
    int rotate;
    for (rotate = 0; rotate < 32; rotate += 2)
    {
        // print an encoding if the only significant bits
        // fit into an 8-bit immediate
        if (!(encode & ~0xffU))
        {
            printf("0x%X%02X\n", rotate/2, encode);
            return (encode & 0xFF) | (rotate/2)<<8;
        }

        // rotate left by two
        encode = (encode << 2) | (encode >> 30);
    }
    return 0;
}


int main(int argc, char *argv[])
{
	int fd_elf = -1;
	uint8_t *p_base = NULL;
	char *p_strtable = NULL;
	struct stat elf_stat;
	Elf32_Ehdr *p_ehdr = NULL;
	Elf32_Phdr *p_phdr = NULL;
	Elf32_Shdr *p_shdr = NULL;
	int i;

	if (argc < 2) {
		printf("Usage: %s <elffile>\n", argv[0]);
		return 1;
	}

	fd_elf = open(argv[1], O_RDONLY);
	if (fd_elf == -1) {
		fprintf(stderr, "Could not open %s: %s\n", argv[1],
			strerror(errno));
		return 1;
	}

	if (fstat(fd_elf, &elf_stat) == -1) {
		fprintf(stderr, "Could not stat %s: %s\n", argv[1],
			strerror(errno));
		close(fd_elf);
		return 1;
	}

	p_base = (uint8_t *) calloc(sizeof(uint8_t), elf_stat.st_size);
	if (!p_base) {
		fprintf(stderr, "Not enough memory\n");
		close(fd_elf);
		return 1;
	}

	if (read(fd_elf, p_base, elf_stat.st_size) != elf_stat.st_size) {
		fprintf(stderr, "Error while reading file: %s\n",
			strerror(errno));
		free(p_base);
		close(fd_elf);
		return 1;
	}

	close(fd_elf);

	p_ehdr = (Elf32_Ehdr *) p_base;
	if (elf_is_valid(p_ehdr)) {
		print_elf_header(p_ehdr);

		printf("\n");
		p_phdr = (Elf32_Phdr *) (p_base + p_ehdr->e_phoff);
		p_shdr = (Elf32_Shdr *) (p_base + p_ehdr->e_shoff);
        all_sections = p_shdr;
		p_strtable =
		    (char *)(p_base + p_shdr[p_ehdr->e_shstrndx].sh_offset);

        printf("Program headers\n  Type   \tOffset  \tVirtAddr\tPhysAddr\tFileSiz \tMemSiz  \tFlg\tAlign\n");
		for (i = 0; i < p_ehdr->e_phnum; i++) {
			print_program_header(&p_phdr[i], i);
		}
        printf("\n");

		for (i = 0; i < p_ehdr->e_shnum; i++) {
			print_section_header(&p_shdr[i], i, p_strtable, p_base);
            if (p_shdr[i].sh_type == SHT_SYMTAB
                    || p_shdr[i].sh_type == SHT_DYNSYM) {
                if (p_shdr[i].sh_type == SHT_DYNSYM) {
                    dynsymSectionIndex = i;
                }

                //being a symbol table, the field sh_link of the section header
                //will hold an index into the section table which gives the
                //section containing the string table
                print_sym_table(p_base, &p_shdr[i],
                        (char *)(p_base +
                            p_shdr[p_shdr[i].
                            sh_link].
                            sh_offset));
            } else if (p_shdr[i].sh_type == SHT_DYNAMIC) {
                dynamicSectionIndex = i;
            }
		}
	} else {
		printf("Invalid ELF file\n");
    }
   
    printf("Updating dynsym _ztext_start symbol\n"); //update size and binding type
    dynsymZtextStart->st_info = ELF32_ST_INFO(STB_LOCAL, STT_OBJECT);
    dynsymZtextStart->st_size = ztextShdr->sh_size;
    Elf32_Shdr *dynsymShdr = &all_sections[dynsymSectionIndex];
    dynsymShdr->sh_info = 1 + dynsymZtextStart - (Elf32_Sym *)(p_base + dynsymShdr->sh_offset);

    /* 
       bfd/elflink.c says "ELF requires that all
	     global symbols follow all local symbols, and that sh_info
	     point to the first global symbol."
      we need to make this symbol local, so we need to move it to the top of the list and update sh_info
      */
/*    Elf32_Shdr *dynsymShdr = &all_sections[dynsymSectionIndex];
    Elf32_Sym *sym = (Elf32_Sym *)(p_base + dynsymShdr->sh_offset);
    while (sym != dynsymZtextStart) { 
        if (ELF32_ST_TYPE(sym->st_info) != STB_LOCAL) {
            Elf32_Sym tmp = *sym;
            memcpy(sym, dynsymZtextStart, sizeof(Elf32_Sym));
            memcpy(dynsymZtextStart, &tmp, sizeof(Elf32_Sym));
            break;
        }
        sym++;
    }*/

    if (relBssShdr) {
        // Inject a COPY relocation of the ztext_start symbol to .xbss
        printf("Injecting COPY relocation from .ztext to .xbss\n");
        relBssShdr->sh_type = SHT_REL;
        relBssShdr->sh_flags = SHF_ALLOC | SHF_INFO_LINK;
        relBssShdr->sh_link = dynsymSectionIndex;
        relBssShdr->sh_info = xbssSectionIndex;
        relBssShdr->sh_addralign = 4;
        relBssShdr->sh_entsize = 8;

        int sz = 0;
        // Point at the end of the section
        Elf32_Rel *rel = (Elf32_Rel *)(p_base + relBssShdr->sh_offset + relBssShdr->sh_size);
        // Point at the latest relocation (the dummy one we injected)
        rel--;

        int type = ELF32_R_TYPE(rel->r_info);
        int symtab_index = ELF32_R_SYM(rel->r_info);

        printf("Found reloc type %d symtab index %d\n", type, symtab_index);
        if (e_machine == EM_386) {
            type = R_386_COPY;
        } else if (e_machine == EM_ARM) {
            type = R_ARM_COPY;
        }
        symtab_index = ztext_start_symidx;
        rel->r_info = ELF32_R_INFO(symtab_index, type);
        rel->r_offset =  all_sections[xbssSectionIndex].sh_addr;
        printf("Now reloc type %d symtab index %d\n", type, symtab_index);
    } else {
        fprintf(stderr, "Can't find section .rel.bss where to inject the COPY relocation!!!!\n");
        return 1;
    }

    int32_t zTextToXbss = all_sections[xbssSectionIndex].sh_addr - ztextShdr->sh_addr;
    if (relZtextShdr && ztextShdr) {
        // Fixup all GOT-involving relocations since the offset between code and GOT is about to change (- .ztext + .xbss)
        printf("Fixing up relocations for .ztext from .rel.ztext\n");
        fixup_relocations_for_section(p_base, relZtextShdr, ztextShdr, zTextToXbss, p_shdr);
    }

    if (relGotShdr && gotShdr) {
        // The GOT itself has addresses such as the address of main, fix it up
        printf("Fixing up relocations for .got from .rel.got\n");
        fixup_relocations_for_section(p_base, relGotShdr, gotShdr, zTextToXbss, p_shdr);
    }

    // XXX rel.data is also needed, because it can contain function pointers (e.g. elfutils' blkid). .rel.data
    if (relDataShdr && dataShdr) {
        printf("Fixing up relocations for .data from .rel.data\n");
        fixup_relocations_for_section(p_base, relDataShdr, dataShdr, zTextToXbss, p_shdr);
    }
    
    if (relRoDataShdr && roDataShdr) {
        printf("Fixing up relocations for .rodata from .rel.rodata\n");
        fixup_relocations_for_section(p_base, relRoDataShdr, roDataShdr, zTextToXbss, p_shdr);
    }

    if (relInitArrayShdr && initArrayShdr) {
        printf("Fixing up relocations for .init_array from .rel.init_array\n");
        fixup_relocations_for_section(p_base, relInitArrayShdr, initArrayShdr, zTextToXbss, p_shdr);
    }

    if (relFiniArrayShdr && finiArrayShdr) {
        printf("Fixing up relocations for .fini_array from .rel.fini_array\n");
        fixup_relocations_for_section(p_base, relFiniArrayShdr, finiArrayShdr, zTextToXbss, p_shdr);
    }

    if (symGotPlt) {
        // Fixup symbols in the GOT
        // Find the section in which the GOT lives
        Elf32_Shdr *s = &all_sections[symGotPlt->st_shndx];
        if (symGotPlt->st_shndx >= SHN_LORESERVE) {
            fprintf(stderr, "_GLOBAL_OFFSET_TABLE_ symbol has reserved section index 0x%04x, using .got as reference instead\n", symGotPlt->st_shndx);
            s = gotShdr;
        }
        int offset = symGotPlt->st_value - s->sh_addr; // offset from start of section
        Elf32_Addr *fixmeup = (Elf32_Addr *)(p_base + s->sh_offset + offset);
        printf("Found plt _GLOBAL_OFFSET_TABLE_ @%#x offse from ztext %#x file offset %#x\n", symGotPlt->st_value, offset, (uint8_t *)fixmeup - p_base);
        fixmeup += 3;
        // now I should be pointing at addresses
        while (1) {
            printf("Fixmeup GOT value %#x\n", *fixmeup);
            if (looks_like_code_address(*fixmeup)) {
                printf("Fixing up address at %p value %p to ", (uint8_t *)fixmeup - s->sh_offset - p_base + s->sh_addr, *fixmeup);
                *fixmeup = *fixmeup + zTextToXbss;
                printf("%p\n", *fixmeup);
            } else {
                break;
            }
            fixmeup ++;
        }

    }

    /* Fixup entries in the PLT: they do a bunch of PC-relative computations to
     point to the GOT, but because the PLT (which is executable) is moving,
     the offset between PLT and GOT changes. x86 doesn't have that problem
     because the PC-relative part happens in the caller itself, not in the
     PLT, and the linker properly emits relocations with -q for these. But it
     doesn't for changes in the PLT, so we have to fix this up manually.
     Look for :
         e28fc600        add     ip, pc, #0      ; 0x0
     in the PLT, and change the immediate value to add zTextToXbss
     */
                printf("ztexttobss %x\n", zTextToXbss);
    if (symPltStart && symPltEnd && e_machine == EM_ARM) {
        printf("Fixing up plt entries for ARM\n");
        int offset = symPltStart->st_value - ztextShdr->sh_addr; // offset from start of section
        uint32_t *fixmeup = (Elf32_Addr *)(p_base + ztextShdr->sh_offset + offset);
        int nb = (symPltEnd->st_value - symPltStart->st_value) / 4;
        for (int i = 0; i < nb; i++, fixmeup++) {
/*            https://alisdair.mcdiarmid.org/arm-immediate-value-encoding/
              ba98 | 76543210
              rot  | imm*/
            if (*fixmeup == 0xe28fc600) {
                // Can't encode a negative immediate value to add     ip, pc, #0 (that I know of, anyway)
                fprintf(stderr, "Error: cannot fix up PLT entry add     ip, pc, #0 because I do not know how to add a negative value\n");
            } else if (((*fixmeup) & 0xFFFFF000) == 0xe28cc000) {
                printf("Fixing up add     ip, ip, #102400\n");
                uint8_t imm = *fixmeup & 0xFF;
                uint8_t rot = (*fixmeup >> 8) & 0xF;
                uint32_t val=imm >> 2*rot  | imm << (32-2*rot);
                printf("instr %x was encoding value %x\n", *fixmeup, val);
                if ((zTextToXbss > (signed)val)) {
                    printf("Warning: cannot fix up PLT immediate value %#x (need to remove %#x and cannot be negative), changing instruction to sub\n", val, zTextToXbss);
                    *fixmeup = 0xe24cc000;
                    *fixmeup |= arm_encode_addimm(zTextToXbss - val);
                    continue;
                }
                val -= zTextToXbss;
                *fixmeup = 0xe28cc000;
                *fixmeup |= arm_encode_addimm(val);
            }
        }
        
    }

    /* Change entries in .dynamic so it points to the new code address */
    if (dynamicSectionIndex) {
        Elf32_Shdr *s = &all_sections[dynamicSectionIndex];
        Elf32_Dyn *d = (Elf32_Dyn *)(p_base + s->sh_offset);
        int nb = s->sh_size / sizeof(Elf32_Dyn);
        for (int i = 0; i < nb; i++, d++) {
            switch (d->d_tag) {
                case DT_INIT:
                case DT_FINI:
                    // Do not fix them up just kill them XXXX this sucks big time try not to suck so much dude
//                    d->d_tag = DT_BIND_NOW;
                    printf("Fixin up DT_INIT/DT_FINI from %p to %p\n", d->d_un.d_ptr ,d->d_un.d_ptr + zTextToXbss);
                    d->d_un.d_ptr += zTextToXbss;
                    break;
            }
        }
    }

    FILE *out = fopen("/tmp/out.elf", "w");
    fwrite(p_base, elf_stat.st_size, 1, out);
    fclose(out);
	free(p_base);
	return 0;
}
