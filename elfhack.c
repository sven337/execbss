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

Elf32_Shdr *ztextShdr = NULL;
Elf32_Shdr *xbssShdr = NULL;
Elf32_Shdr *relBssShdr = NULL;
Elf32_Shdr *relZtextShdr = NULL;
Elf32_Sym  *dynsymZtextStart, *symGotPlt;
int ztext_start_symidx;
int e_machine;

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
		printf("- Name index: %d\n", symbols->st_name);
		printf("- Name: %s\n", strtable + symbols->st_name);
        char *name = strtable + symbols->st_name;
        if (!strcmp(name, "_GLOBAL_OFFSET_TABLE_")) {
            // Found _GLOBAL_OFFSET_TABLE_ which is .got.plt, part of .ztext with my linker script.
            // That one contains absolute pointers that need to be fixed up.
            symGotPlt = symbols;
        } else if (!strcmp(name, "_ztext_start") && section->sh_type == SHT_DYNSYM) {
            dynsymZtextStart = symbols;
            ztext_start_symidx = symbols - (Elf32_Sym *) (filebase + section->sh_offset);
        }
		printf("- Value: 0x%08x\n", symbols->st_value);
		printf("- Size: 0x%08x\n", symbols->st_size);

		print_bind_type(symbols->st_info);
		print_sym_type(symbols->st_info);

		printf("- Section index: %d\n", symbols->st_shndx);
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
        relBssShdr = shdr;
    } else if (!strcmp(name, ".xbss")) {
        // Found .xbss
        xbssShdr = shdr;
    } else if (!strcmp(name, ".rel.ztext")) {
        relZtextShdr = shdr;
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
				printf
				    ("This section holds a symbol table...\n");

				//being a symbol table, the field sh_link of the section header
				//will hold an index into the section table which gives the
				//section containing the string table
				print_sym_table(p_base, &p_shdr[i],
						(char *)(p_base +
							 p_shdr[p_shdr[i].
								sh_link].
							 sh_offset));
			} else if (p_shdr[i].sh_type == SHT_REL || p_shdr[i].sh_type == SHT_RELA) {
                // Relocation section
            }
		}
	} else {
		printf("Invalid ELF file\n");
    }
   
    printf("Updating dynsym _ztext_start symbol\n"); //update size and binding type
    dynsymZtextStart->st_info = ELF32_ST_INFO(STB_LOCAL, STT_OBJECT);
    dynsymZtextStart->st_size = ztextShdr->sh_size;

    if (relBssShdr) {
        // Inject a COPY relocation of the ztext_start symbol to .xbss
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
        rel->r_offset =  xbssShdr->sh_addr;
        printf("Now reloc type %d symtab index %d\n", type, symtab_index);
    }


    if (relZtextShdr) {
        // Fixup all GOT-involving relocations since the offset between code and GOT is about to change (- .ztext + .xbss)
        int nb = relZtextShdr->sh_size / sizeof(Elf32_Rel);
        Elf32_Rel *rel = (Elf32_Rel *)(p_base + relZtextShdr->sh_offset);
        uint8_t *zTextPtr = (uint8_t *)(p_base + ztextShdr->sh_offset);
        int32_t ztextToXbss = xbssShdr->sh_addr - ztextShdr->sh_addr;
        for (int i = 0; i < nb; i++) {
            int type = ELF32_R_TYPE(rel->r_info);
            Elf32_Addr *fixup = (Elf32_Addr *)(zTextPtr + rel->r_offset - ztextShdr->sh_addr);

//            https://docs.oracle.com/cd/E19120-01/open.solaris/819-0690/chapter6-26/index.html
            switch (type) {
                case R_386_PC32:
                    // PC-relative  S + A - P 
                    // if S is in .ztext, nothing changes
                    // otherwise handle it..
                    break;
                case R_386_GOTPC:
                    //  GOT + A - P 
                    // P is moving by (.xbss - .ztext)
                    printf("value %#x must be fixed\n", *fixup);
                    *fixup -= ztextToXbss;
                    printf("Fixed up %p which is at %p\n", rel->r_offset, (uint8_t*)fixup-p_base);
                    break;
                case R_386_GOTOFF:
                    // S + A - GOT
                    // Nothing to do
                    break;
                case R_386_PLT32:
                    //  L + A - P  (L is .plt)
                    // Nothing to do, both L and P move so it's fine
                    break;
                case R_386_GOT32X:
                    // XXX
                    break;
                default:
                    ;
            };
            //#define ELF32_R_SYM(val)        ((val) >> 8)
            rel++;
        }

    }


    if (symGotPlt) {
        printf("Found _GLOBAL_OFFSET_TABLE_ value %#x size %d\n", symGotPlt->st_value);
        int offset = symGotPlt->st_value - ztextShdr->sh_addr; // offset from start of section
        Elf32_Addr *fixmeup = (Elf32_Addr *)(p_base + ztextShdr->sh_offset + offset);
        fixmeup += 3;
        // now I should be pointing at addresses
        while (1) {
            if (*fixmeup > ztextShdr->sh_addr && *fixmeup < (Elf32_Addr)(ztextShdr->sh_addr + ztextShdr->sh_size)) {
                printf("Fixing up address %p to ", *fixmeup);
                *fixmeup = *fixmeup - ztextShdr->sh_addr + xbssShdr->sh_addr;
                printf("%p\n", *fixmeup);
            } else {
                break;
            }
            fixmeup ++;
        }

    }

    FILE *out = fopen("/tmp/out.elf", "w");
    fwrite(p_base, elf_stat.st_size, 1, out);
    fclose(out);
	free(p_base);
	return 0;
}
