#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <mach-o/loader.h>
#include <mach-o/fat.h>
#include <mach-o/nlist.h>

typedef struct
{
    const uint8_t *data;
    size_t size;
    const char *path;
} MachOBuffer;

typedef struct
{
    bool is_64;
    bool swaps_bytes;
} ImageTraits;

static uint16_t read_u16(const void *ptr)
{
    uint16_t value;
    memcpy(&value, ptr, sizeof(value));
    return value;
}

static uint32_t read_u32(const void *ptr)
{
    uint32_t value;
    memcpy(&value, ptr, sizeof(value));
    return value;
}

static uint64_t read_u64(const void *ptr)
{
    uint64_t value;
    memcpy(&value, ptr, sizeof(value));
    return value;
}

static uint16_t maybe_swap16(uint16_t value, bool swap)
{
    return swap ? __builtin_bswap16(value) : value;
}

static uint32_t maybe_swap32(uint32_t value, bool swap)
{
    return swap ? __builtin_bswap32(value) : value;
}

static uint64_t maybe_swap64(uint64_t value, bool swap)
{
    return swap ? __builtin_bswap64(value) : value;
}

static bool in_bounds(const MachOBuffer *buffer, size_t offset, size_t amount)
{
    return offset <= buffer->size && amount <= buffer->size - offset;
}

static const char *cpu_type_desc(cpu_type_t type)
{
    switch (type)
    {
    case CPU_TYPE_X86:
        return "x86";
    case CPU_TYPE_X86_64:
        return "x86_64";
    case CPU_TYPE_ARM:
        return "ARM";
    case CPU_TYPE_ARM64:
        return "ARM64";
    case CPU_TYPE_POWERPC:
        return "PowerPC";
    case CPU_TYPE_POWERPC64:
        return "PowerPC64";
    default:
        return "Unknown";
    }
}

static const char *filetype_desc(uint32_t filetype)
{
    switch (filetype)
    {
    case MH_OBJECT:
        return "Relocatable object";
    case MH_EXECUTE:
        return "Executable";
    case MH_FVMLIB:
        return "Fixed VM shared library";
    case MH_DYLIB:
        return "Dynamic library";
    case MH_DYLINKER:
        return "Dynamic linker";
    case MH_BUNDLE:
        return "Bundle";
    case MH_DYLIB_STUB:
        return "Dynamic Library Stub";
    case MH_DSYM:
        return "Debug symbols";
    case MH_KEXT_BUNDLE:
        return "Kernel extension";
    default:
        return "Unknown";
    }
}

static void report_segment_32(const struct segment_command *segment, bool swap)
{
    printf("    Segment: %.16s\n", segment->segname);
    printf("      VM   : 0x%08" PRIx32 " - 0x%08" PRIx32 " (size 0x%08" PRIx32 ")\n",
           maybe_swap32(segment->vmaddr, swap),
           maybe_swap32(segment->vmaddr, swap) + maybe_swap32(segment->vmsize, swap),
           maybe_swap32(segment->vmsize, swap));
    printf("      File : offset 0x%08" PRIx32 " size 0x%08" PRIx32 "\n",
           maybe_swap32(segment->fileoff, swap),
           maybe_swap32(segment->filesize, swap));
    printf("      Prot : max 0x%08" PRIx32 " init 0x%08" PRIx32 "\n",
           maybe_swap32(segment->maxprot, swap),
           maybe_swap32(segment->initprot, swap));
}

static void report_segment_64(const struct segment_command_64 *segment, bool swap)
{
    printf("    Segment: %.16s\n", segment->segname);
    uint64_t vmaddr = maybe_swap64(segment->vmaddr, swap);
    uint64_t vmsize = maybe_swap64(segment->vmsize, swap);
    printf("      VM   : 0x%016" PRIx64 " - 0x%016" PRIx64 " (size 0x%016" PRIx64 ")\n",
           vmaddr, vmaddr + vmsize, vmsize);
    printf("      File : offset 0x%016" PRIx64 " size 0x%016" PRIx64 "\n",
           maybe_swap64(segment->fileoff, swap),
           maybe_swap64(segment->filesize, swap));
    printf("      Prot : max 0x%08" PRIx32 " init 0x%08" PRIx32 "\n",
           maybe_swap32(segment->maxprot, swap),
           maybe_swap32(segment->initprot, swap));
}

static void report_section_32(const struct section *section, bool swap)
{
    printf("      Section: %.16s (segment %.16s)\n", section->sectname, section->segname);
    printf("        VM addr : 0x%08" PRIx32 " size 0x%08" PRIx32 "\n",
           maybe_swap32(section->addr, swap), maybe_swap32(section->size, swap));
    printf("        File off: 0x%08" PRIx32 " align 2^%" PRIu32 "\n",
           maybe_swap32(section->offset, swap), maybe_swap32(section->align, swap));
    printf("        Flags   : 0x%08" PRIx32 "\n", maybe_swap32(section->flags, swap));
}

static void report_section_64(const struct section_64 *section, bool swap)
{
    printf("      Section: %.16s (segment %.16s)\n", section->sectname, section->segname);
    printf("        VM addr : 0x%016" PRIx64 " size 0x%016" PRIx64 "\n",
           maybe_swap64(section->addr, swap), maybe_swap64(section->size, swap));
    printf("        File off: 0x%08" PRIx32 " align 2^%" PRIu32 "\n",
           maybe_swap32(section->offset, swap), maybe_swap32(section->align, swap));
    printf("        Flags   : 0x%08" PRIx32 "\n", maybe_swap32(section->flags, swap));
}

static void describe_uuid(const struct uuid_command *uuid_cmd, bool swap)
{
    (void)swap;
    printf("    UUID: ");
    for (int i = 0; i < 16; ++i)
    {
        printf("%02x", uuid_cmd->uuid[i]);
        if (i == 3 || i == 5 || i == 7 || i == 9)
        {
            printf("-");
        }
    }
    printf("\n");
}

static void describe_entry_point(const struct entry_point_command *entry_cmd, bool swap)
{
    printf("    Entry offset : 0x%016" PRIx64 "\n", maybe_swap64(entry_cmd->entryoff, swap));
    printf("    Stack size   : 0x%016" PRIx64 "\n", maybe_swap64(entry_cmd->stacksize, swap));
}

static void describe_source_version(const struct source_version_command *cmd, bool swap)
{
    uint64_t version = maybe_swap64(cmd->version, swap);
    printf("    Source version: %" PRIu64 ".%" PRIu64 ".%" PRIu64 ".%" PRIu64 ".%" PRIu64 "\n",
           (version >> 40) & 0xffff,
           (version >> 30) & 0x3ff,
           (version >> 20) & 0x3ff,
           (version >> 10) & 0x3ff,
           version & 0x3ff);
}

static void describe_version_min(const struct version_min_command *cmd, bool swap)
{
    uint32_t version = maybe_swap32(cmd->version, swap);
    uint32_t sdk = maybe_swap32(cmd->sdk, swap);
    printf("    Min version: %u.%u.%u\n",
           (version >> 16) & 0xffff, (version >> 8) & 0xff, version & 0xff);
    printf("    SDK version: %u.%u.%u\n",
           (sdk >> 16) & 0xffff, (sdk >> 8) & 0xff, sdk & 0xff);
}

static void describe_dylib(const struct dylib_command *cmd, bool swap, const MachOBuffer *buffer, size_t offset)
{
    size_t name_off = maybe_swap32(cmd->dylib.name.offset, swap);
    if (!in_bounds(buffer, offset + name_off, 1))
    {
        printf("    Dylib name out of range\n");
        return;
    }
    const char *name = (const char *)buffer->data + offset + name_off;
    printf("    Dylib: %s\n", name);
    printf("      Timestamp: %u\n", maybe_swap32(cmd->dylib.timestamp, swap));
    printf("      Current version: %u.%u.%u\n",
           (maybe_swap32(cmd->dylib.current_version, swap) >> 16) & 0xffff,
           (maybe_swap32(cmd->dylib.current_version, swap) >> 8) & 0xff,
           maybe_swap32(cmd->dylib.current_version, swap) & 0xff);
    printf("      Compat version: %u.%u.%u\n",
           (maybe_swap32(cmd->dylib.compatibility_version, swap) >> 16) & 0xffff,
           (maybe_swap32(cmd->dylib.compatibility_version, swap) >> 8) & 0xff,
           maybe_swap32(cmd->dylib.compatibility_version, swap) & 0xff);
}

static void describe_dysymtab(const struct dysymtab_command *cmd, bool swap)
{
    printf("    Dysymtab:\n");
    printf("      Local symbols    : index %u count %u\n",
           maybe_swap32(cmd->ilocalsym, swap), maybe_swap32(cmd->nlocalsym, swap));
    printf("      External symbols : index %u count %u\n",
           maybe_swap32(cmd->iextdefsym, swap), maybe_swap32(cmd->nextdefsym, swap));
    printf("      Undefined symbols: index %u count %u\n",
           maybe_swap32(cmd->iundefsym, swap), maybe_swap32(cmd->nundefsym, swap));
    printf("      Indirect symbols : offset 0x%08" PRIx32 " count %u\n",
           maybe_swap32(cmd->indirectsymoff, swap), maybe_swap32(cmd->nindirectsyms, swap));
}

static void describe_function_starts(const struct linkedit_data_command *cmd, bool swap)
{
    printf("    Function starts: offset 0x%08" PRIx32 ", size 0x%08" PRIx32 "\n",
           maybe_swap32(cmd->dataoff, swap), maybe_swap32(cmd->datasize, swap));
}

static void describe_encryption_info(const struct encryption_info_command *cmd, bool swap)
{
    printf("    Encryption info:\n");
    printf("      Crypt offset  : 0x%08" PRIx32 "\n", maybe_swap32(cmd->cryptoff, swap));
    printf("      Crypt size    : 0x%08" PRIx32 "\n", maybe_swap32(cmd->cryptsize, swap));
    printf("      Crypt ID      : %u\n", maybe_swap32(cmd->cryptid, swap));
}

static void describe_encryption_info_64(const struct encryption_info_command_64 *cmd, bool swap)
{
    printf("    Encryption info (64):\n");
    printf("      Crypt offset  : 0x%08" PRIx32 "\n", maybe_swap32(cmd->cryptoff, swap));
    printf("      Crypt size    : 0x%08" PRIx32 "\n", maybe_swap32(cmd->cryptsize, swap));
    printf("      Crypt ID      : %u\n", maybe_swap32(cmd->cryptid, swap));
}

static void describe_rpath(const struct rpath_command *cmd, bool swap, const MachOBuffer *buffer, size_t lc_offset)
{
    size_t path_off = maybe_swap32(cmd->path.offset, swap);
    if (!in_bounds(buffer, lc_offset + path_off, 1))
    {
        printf("    RPath path out of range\n");
        return;
    }
    printf("    RPath: %s\n", (const char *)buffer->data + lc_offset + path_off);
}

static void parse_sections_32(const struct segment_command *segment, const MachOBuffer *buffer, size_t lc_offset, bool swap)
{
    uint32_t nsects = maybe_swap32(segment->nsects, swap);
    size_t section_offset = lc_offset + sizeof(struct segment_command);
    for (uint32_t i = 0; i < nsects; ++i)
    {
        if (!in_bounds(buffer, section_offset, sizeof(struct section)))
        {
            printf("      Section %u out of range\n", i);
            return;
        }
        const struct section *sec = (const struct section *)(buffer->data + section_offset);
        report_section_32(sec, swap);
        section_offset += sizeof(struct section);
    }
}

static void parse_sections_64(const struct segment_command_64 *segment, const MachOBuffer *buffer, size_t lc_offset, bool swap)
{
    uint32_t nsects = maybe_swap32(segment->nsects, swap);
    size_t section_offset = lc_offset + sizeof(struct segment_command_64);
    for (uint32_t i = 0; i < nsects; ++i)
    {
        if (!in_bounds(buffer, section_offset, sizeof(struct section_64)))
        {
            printf("      Section %u out of range\n", i);
            return;
        }
        const struct section_64 *sec = (const struct section_64 *)(buffer->data + section_offset);
        report_section_64(sec, swap);
        section_offset += sizeof(struct section_64);
    }
}

static void parse_symbol_table(uint32_t symoff, uint32_t nsyms, uint32_t stroff, uint32_t strsize,
                               const MachOBuffer *buffer, const ImageTraits *traits)
{
    if (!in_bounds(buffer, symoff, (size_t)nsyms * (traits->is_64 ? sizeof(struct nlist_64) : sizeof(struct nlist))))
    {
        printf("    Symbol table out of range\n");
        return;
    }
    if (!in_bounds(buffer, stroff, strsize))
    {
        printf("    String table out of range\n");
        return;
    }

    const char *strtab = (const char *)buffer->data + stroff;
    printf("    Symbols (%u entries):\n", nsyms);

    for (uint32_t i = 0; i < nsyms; ++i)
    {
        if (traits->is_64)
        {
            const struct nlist_64 *entry = (const struct nlist_64 *)(buffer->data + symoff + i * sizeof(struct nlist_64));
            uint32_t strx = maybe_swap32(entry->n_un.n_strx, traits->swaps_bytes);
            const char *name = (strx < strsize) ? strtab + strx : "<bad string index>";
            printf("      [%4u] type 0x%02x sect %u desc 0x%04x value 0x%016" PRIx64 " name %s\n",
                   i,
                   entry->n_type,
                   entry->n_sect,
                   maybe_swap16(entry->n_desc, traits->swaps_bytes),
                   maybe_swap64(entry->n_value, traits->swaps_bytes),
                   name);
        }
        else
        {
            const struct nlist *entry = (const struct nlist *)(buffer->data + symoff + i * sizeof(struct nlist));
            uint32_t strx = maybe_swap32(entry->n_un.n_strx, traits->swaps_bytes);
            const char *name = (strx < strsize) ? strtab + strx : "<bad string index>";
            printf("      [%4u] type 0x%02x sect %u desc 0x%04x value 0x%08" PRIx32 " name %s\n",
                   i,
                   entry->n_type,
                   entry->n_sect,
                   maybe_swap16(entry->n_desc, traits->swaps_bytes),
                   maybe_swap32(entry->n_value, traits->swaps_bytes),
                   name);
        }
    }
}

static void handle_load_command(const MachOBuffer *buffer, size_t lc_offset, const ImageTraits *traits)
{
    if (!in_bounds(buffer, lc_offset, sizeof(struct load_command)))
    {
        printf("  Load command header out of range\n");
        return;
    }
    const struct load_command *cmd = (const struct load_command *)(buffer->data + lc_offset);
    uint32_t cmdtype = maybe_swap32(cmd->cmd, traits->swaps_bytes);
    uint32_t cmdsize = maybe_swap32(cmd->cmdsize, traits->swaps_bytes);

    if (!in_bounds(buffer, lc_offset, cmdsize) || cmdsize < sizeof(struct load_command))
    {
        printf("  Malformed load command (cmdsize)\n");
        return;
    }

    switch (cmdtype)
    {
    case LC_SEGMENT:
    {
        const struct segment_command *segment = (const struct segment_command *)cmd;
        report_segment_32(segment, traits->swaps_bytes);
        parse_sections_32(segment, buffer, lc_offset, traits->swaps_bytes);
        break;
    }
    case LC_SEGMENT_64:
    {
        const struct segment_command_64 *segment = (const struct segment_command_64 *)cmd;
        report_segment_64(segment, traits->swaps_bytes);
        parse_sections_64(segment, buffer, lc_offset, traits->swaps_bytes);
        break;
    }
    case LC_UUID:
    {
        describe_uuid((const struct uuid_command *)cmd, traits->swaps_bytes);
        break;
    }
    case LC_MAIN:
    {
        describe_entry_point((const struct entry_point_command *)cmd, traits->swaps_bytes);
        break;
    }
    case LC_SOURCE_VERSION:
    {
        describe_source_version((const struct source_version_command *)cmd, traits->swaps_bytes);
        break;
    }
    case LC_VERSION_MIN_MACOSX:
    case LC_VERSION_MIN_IPHONEOS:
    case LC_VERSION_MIN_TVOS:
    case LC_VERSION_MIN_WATCHOS:
    {
        describe_version_min((const struct version_min_command *)cmd, traits->swaps_bytes);
        break;
    }
    case LC_LOAD_DYLIB:
    case LC_LOAD_WEAK_DYLIB:
    case LC_REEXPORT_DYLIB:
    case LC_LOAD_UPWARD_DYLIB:
    {
        describe_dylib((const struct dylib_command *)cmd, traits->swaps_bytes, buffer, lc_offset);
        break;
    }
    case LC_SYMTAB:
    {
        const struct symtab_command *sym = (const struct symtab_command *)cmd;
        uint32_t symoff = maybe_swap32(sym->symoff, traits->swaps_bytes);
        uint32_t nsyms = maybe_swap32(sym->nsyms, traits->swaps_bytes);
        uint32_t stroff = maybe_swap32(sym->stroff, traits->swaps_bytes);
        uint32_t strsize = maybe_swap32(sym->strsize, traits->swaps_bytes);
        parse_symbol_table(symoff, nsyms, stroff, strsize, buffer, traits);
        break;
    }
    case LC_DYSYMTAB:
    {
        describe_dysymtab((const struct dysymtab_command *)cmd, traits->swaps_bytes);
        break;
    }
    case LC_FUNCTION_STARTS:
    {
        describe_function_starts((const struct linkedit_data_command *)cmd, traits->swaps_bytes);
        break;
    }
    case LC_ENCRYPTION_INFO:
    {
        describe_encryption_info((const struct encryption_info_command *)cmd, traits->swaps_bytes);
        break;
    }
    case LC_ENCRYPTION_INFO_64:
    {
        describe_encryption_info_64((const struct encryption_info_command_64 *)cmd, traits->swaps_bytes);
        break;
    }
    case LC_RPATH:
    {
        describe_rpath((const struct rpath_command *)cmd, traits->swaps_bytes, buffer, lc_offset);
        break;
    }
    default:
        printf("    Unhandled load command: 0x%08" PRIx32 " (size %u)\n", cmdtype, cmdsize);
        break;
    }
}

static void parse_mach_header(const MachOBuffer *buffer, size_t offset)
{
    if (!in_bounds(buffer, offset, sizeof(struct mach_header)))
    {
        printf("  Mach header out of range\n");
        return;
    }
    const struct mach_header *header32 = (const struct mach_header *)(buffer->data + offset);
    uint32_t magic = read_u32(&header32->magic);
    ImageTraits traits = {0};

    if (magic == MH_MAGIC || magic == MH_CIGAM)
    {
        traits.is_64 = false;
        traits.swaps_bytes = (magic == MH_CIGAM);
    }
    else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64)
    {
        traits.is_64 = true;
        traits.swaps_bytes = (magic == MH_CIGAM_64);
    }
    else
    {
        printf("  Unsupported Mach-O magic 0x%08" PRIx32 "\n", magic);
        return;
    }

    printf("  Magic: 0x%08" PRIx32 " (%s, %s)\n",
           magic,
           traits.is_64 ? "64-bit" : "32-bit",
           traits.swaps_bytes ? "swapped" : "native");

    if (traits.is_64)
    {
        if (!in_bounds(buffer, offset, sizeof(struct mach_header_64)))
        {
            printf("  Incomplete 64-bit header\n");
            return;
        }
        const struct mach_header_64 *header = (const struct mach_header_64 *)(buffer->data + offset);
        cpu_type_t cputype = maybe_swap32(header->cputype, traits.swaps_bytes);
        cpu_subtype_t cpusubtype = maybe_swap32(header->cpusubtype, traits.swaps_bytes);
        uint32_t filetype = maybe_swap32(header->filetype, traits.swaps_bytes);
        uint32_t ncmds = maybe_swap32(header->ncmds, traits.swaps_bytes);
        uint32_t sizeofcmds = maybe_swap32(header->sizeofcmds, traits.swaps_bytes);
        printf("  CPU: %s (0x%08x), subtype 0x%08x\n", cpu_type_desc(cputype), cputype, cpusubtype);
        printf("  File type: %s (0x%08x)\n", filetype_desc(filetype), filetype);
        printf("  Commands: %u (total size %u)\n", ncmds, sizeofcmds);

        size_t lc_offset = offset + sizeof(struct mach_header_64);
        for (uint32_t i = 0; i < ncmds; ++i)
        {
            if (!in_bounds(buffer, lc_offset, sizeof(struct load_command)))
            {
                printf("  Load command %u header out of range\n", i);
                break;
            }
            printf("  Load command #%u:\n", i);
            const struct load_command *cmd = (const struct load_command *)(buffer->data + lc_offset);
            uint32_t cmdsize = maybe_swap32(cmd->cmdsize, traits.swaps_bytes);
            handle_load_command(buffer, lc_offset, &traits);
            if (cmdsize == 0)
            {
                printf("  Zero-sized load command encountered\n");
                break;
            }
            lc_offset += cmdsize;
        }
    }
    else
    {
        const struct mach_header *header = header32;
        cpu_type_t cputype = maybe_swap32(header->cputype, traits.swaps_bytes);
        cpu_subtype_t cpusubtype = maybe_swap32(header->cpusubtype, traits.swaps_bytes);
        uint32_t filetype = maybe_swap32(header->filetype, traits.swaps_bytes);
        uint32_t ncmds = maybe_swap32(header->ncmds, traits.swaps_bytes);
        uint32_t sizeofcmds = maybe_swap32(header->sizeofcmds, traits.swaps_bytes);
        printf("  CPU: %s (0x%08x), subtype 0x%08x\n", cpu_type_desc(cputype), cputype, cpusubtype);
        printf("  File type: %s (0x%08x)\n", filetype_desc(filetype), filetype);
        printf("  Commands: %u (total size %u)\n", ncmds, sizeofcmds);

        size_t lc_offset = offset + sizeof(struct mach_header);
        for (uint32_t i = 0; i < ncmds; ++i)
        {
            if (!in_bounds(buffer, lc_offset, sizeof(struct load_command)))
            {
                printf("  Load command %u header out of range\n", i);
                break;
            }
            printf("  Load command #%u:\n", i);
            const struct load_command *cmd = (const struct load_command *)(buffer->data + lc_offset);
            uint32_t cmdsize = maybe_swap32(cmd->cmdsize, traits.swaps_bytes);
            handle_load_command(buffer, lc_offset, &traits);
            if (cmdsize == 0)
            {
                printf("  Zero-sized load command encountered\n");
                break;
            }
            lc_offset += cmdsize;
        }
    }
}

static void parse_fat_archive(const MachOBuffer *buffer)
{
    if (!in_bounds(buffer, 0, sizeof(struct fat_header)))
    {
        printf("Fat header out of range\n");
        return;
    }
    const struct fat_header *fat = (const struct fat_header *)buffer->data;
    bool swaps = (read_u32(&fat->magic) == FAT_CIGAM);
    uint32_t narch = maybe_swap32(fat->nfat_arch, swaps);
    printf("Fat binary with %u architectures\n", narch);

    size_t offset = sizeof(struct fat_header);
    for (uint32_t i = 0; i < narch; ++i)
    {
        if (!in_bounds(buffer, offset, sizeof(struct fat_arch)))
        {
            printf("Fat arch %u out of range\n", i);
            break;
        }
        const struct fat_arch *arch = (const struct fat_arch *)(buffer->data + offset);
        cpu_type_t cputype = maybe_swap32(arch->cputype, swaps);
        cpu_subtype_t cpusubtype = maybe_swap32(arch->cpusubtype, swaps);
        uint32_t arch_offset = maybe_swap32(arch->offset, swaps);
        uint32_t arch_size = maybe_swap32(arch->size, swaps);
        printf("Architecture %u: CPU %s (0x%08x) subtype 0x%08x offset 0x%08x size 0x%08x align 2^%u\n",
               i,
               cpu_type_desc(cputype),
               cputype,
               cpusubtype,
               arch_offset,
               arch_size,
               maybe_swap32(arch->align, swaps));
        if (in_bounds(buffer, arch_offset, arch_size))
        {
            parse_mach_header(buffer, arch_offset);
        }
        else
        {
            printf("  Embedded Mach-O out of range\n");
        }
        offset += sizeof(struct fat_arch);
    }
}

static int load_file(const char *path, MachOBuffer *buffer)
{
    FILE *fp = fopen(path, "rb");
    if (!fp)
    {
        perror("fopen");
        return -1;
    }
    if (fseek(fp, 0, SEEK_END) != 0)
    {
        perror("fseek");
        fclose(fp);
        return -1;
    }
    long length = ftell(fp);
    if (length < 0)
    {
        perror("ftell");
        fclose(fp);
        return -1;
    }
    rewind(fp);
    uint8_t *data = malloc((size_t)length);
    if (!data)
    {
        perror("malloc");
        fclose(fp);
        return -1;
    }
    size_t read = fread(data, 1, (size_t)length, fp);
    fclose(fp);
    if (read != (size_t)length)
    {
        fprintf(stderr, "Failed to read entire file\n");
        free(data);
        return -1;
    }
    buffer->data = data;
    buffer->size = (size_t)length;
    buffer->path = path;
    return 0;
}

static void free_buffer(MachOBuffer *buffer)
{
    free((void *)buffer->data);
    buffer->data = NULL;
    buffer->size = 0;
    buffer->path = NULL;
}

static void parse_macho_or_fat(const MachOBuffer *buffer)
{
    if (buffer->size < sizeof(uint32_t))
    {
        printf("File too small\n");
        return;
    }
    uint32_t magic = read_u32(buffer->data);
    switch (magic)
    {
    case FAT_MAGIC:
    case FAT_CIGAM:
    case FAT_MAGIC_64:
    case FAT_CIGAM_64:
        parse_fat_archive(buffer);
        break;
    case MH_MAGIC:
    case MH_CIGAM:
    case MH_MAGIC_64:
    case MH_CIGAM_64:
        printf("Thin Mach-O image\n");
        parse_mach_header(buffer, 0);
        break;
    default:
        printf("Unknown magic: 0x%08" PRIx32 "\n", magic);
        break;
    }
}

int main(int argc, char **argv)
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <mach-o-file>\n", argv[0]);
        return EXIT_FAILURE;
    }
    MachOBuffer buffer = {0};
    if (load_file(argv[1], &buffer) != 0)
    {
        return EXIT_FAILURE;
    }
    printf("Parsing: %s (%zu bytes)\n", argv[1], buffer.size);
    parse_macho_or_fat(&buffer);
    free_buffer(&buffer);
    return EXIT_SUCCESS;
}
