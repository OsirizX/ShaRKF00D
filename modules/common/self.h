#pragma once

#include <inttypes.h>
#include <stdbool.h>

// some info taken from the wiki, see http://vitadevwiki.com/index.php?title=SELF_File_Format

#pragma pack(push, 1)
typedef struct {
	uint32_t magic;                 /* 53434500 = SCE\0 */
	uint32_t version;               /* header version 3*/
	uint16_t sdk_type;              /* */
	uint16_t header_type;           /* 1 self, 2 unknown, 3 pkg */
	uint32_t metadata_offset;       /* metadata offset */
	uint64_t header_len;            /* self header length */
	uint64_t elf_filesize;          /* ELF file length */
	uint64_t self_filesize;         /* SELF file length */
	uint64_t unknown;               /* UNKNOWN */
	uint64_t self_offset;           /* SELF offset */
	uint64_t appinfo_offset;        /* app info offset */
	uint64_t elf_offset;            /* ELF #1 offset */
	uint64_t phdr_offset;           /* program header offset */
	uint64_t shdr_offset;           /* section header offset */
	uint64_t section_info_offset;   /* section info offset */
	uint64_t sceversion_offset;     /* version offset */
	uint64_t controlinfo_offset;    /* control info offset */
	uint64_t controlinfo_size;      /* control info size */
	uint64_t padding;
} SCE_header;

typedef struct {
	uint64_t authid;                /* auth id */
	uint32_t vendor_id;             /* vendor id */
	uint32_t self_type;             /* app type */
	uint64_t version;               /* app version */
	uint64_t padding;               /* UNKNOWN */
} SCE_appinfo;

typedef struct {
	uint32_t unk1;
	uint32_t unk2;
	uint32_t unk3;
	uint32_t unk4;
} SCE_version;

typedef struct {
  uint32_t type; // 4==PSVita ELF digest info; 5==PSVita NPDRM info; 6==PSVita boot param info; 7==PSVita shared secret info
  uint32_t size;
  uint64_t next; // 1 if another Control Info structure follows else 0
  union {
    // type 4, 0x50 bytes
	struct  { // 0x40 bytes of data
      uint8_t constant[0x14]; // same for every PSVita/PS3 SELF, hardcoded in make_fself.exe: 627CB1808AB938E32C8C091708726A579E2586E4
      uint8_t elf_digest[0x20]; // on PSVita: SHA-256 of source ELF file, on PS3: SHA-1
      uint8_t padding[8];
      uint32_t min_required_fw; // ex: 0x363 for 3.63
    } PSVita_elf_digest_info;
    // type 5, 0x110 bytes
    struct { // 0x80 bytes of data
      uint32_t magic;               // 7F 44 52 4D (".DRM")
      uint32_t finalized_flag;      // ex: 80 00 00 01
      uint32_t drm_type;            // license_type ex: 2 local, 0XD free with license
      uint32_t padding;
      uint8_t content_id[0x30];
      uint8_t digest[0x10];         // ?sha-1 hash of debug self/sprx created using make_fself_npdrm?
      uint8_t padding_78[0x78];
      uint8_t hash_signature[0x38]; // unknown hash/signature
    } PSVita_npdrm_info;
    // type 6, 0x110 bytes
    struct { // 0x100 bytes of data
      uint32_t is_used; // 0=false, 1=true
      uint8_t boot_param[0x9C]; // ex: starting with 02 00 00 00
    } PSVita_boot_param_info;
    // type 7, 0x50 bytes
    struct { // 0x40 bytes of data
      uint8_t shared_secret_0[0x10]; // ex: 0x7E7FD126A7B9614940607EE1BF9DDF5E or full of zeroes
      uint8_t shared_secret_1[0x10]; // ex: full of zeroes
      uint8_t shared_secret_2[0x10]; // ex: full of zeroes
      uint8_t shared_secret_3[0x10]; // ex: full of zeroes
    } PSVita_shared_secret_info;
  };
} __attribute__((packed)) PSVita_CONTROL_INFO;

typedef struct {
	uint64_t offset;
	uint64_t length;
	uint64_t compression; // 1 = uncompressed, 2 = compressed
	uint64_t encryption; // 1 = encrypted, 2 = plain
} segment_info;

typedef struct {
	uint32_t type;
	uint32_t size;
	uint32_t unk;
	uint32_t pad;
} SCE_controlinfo;

typedef struct {
	SCE_controlinfo common;
	char unk[0x100];
} SCE_controlinfo_5;

typedef struct {
	SCE_controlinfo common;
	uint32_t is_used;               /* always set to 1 */
	uint32_t attr;                  /* controls several app settings */
	uint32_t phycont_memsize;       /* physically contiguous memory budget */
	uint32_t total_memsize;         /* total memory budget (user + phycont) */
	uint32_t filehandles_limit;     /* max number of opened filehandles simultaneously */
	uint32_t dir_max_level;         /* max depth for directories support */
	uint32_t encrypt_mount_max;     /* UNKNOWN */
	uint32_t redirect_mount_max;    /* UNKNOWN */
	char unk[0xE0];
} SCE_controlinfo_6;

typedef struct {
	SCE_controlinfo common;
	char unk[0x40];
} SCE_controlinfo_7;

typedef struct {
  uint32_t magic;
  uint32_t version;
  uint8_t _platform;
  uint8_t key_revision;
  uint16_t _sce_type;
  uint32_t metadata_offset;
  uint64_t header_length;
  uint64_t data_length;
} SceHeader;

typedef struct {
  uint64_t file_length;
  uint64_t field_8;
  uint64_t self_offset;
  uint64_t appinfo_offset;
  uint64_t elf_offset;
  uint64_t phdr_offset;
  uint64_t shdr_offset;
  uint64_t segment_info_offset;
  uint64_t sceversion_offset;
  uint64_t controlinfo_offset;
  uint64_t controlinfo_length;
} SelfHeader;

typedef struct {
	uint64_t authid;
	uint32_t vendor_id;
	uint32_t _self_type;
	uint64_t sys_version;
	uint64_t field_18;
} AppInfoHeader;

typedef struct {
  unsigned char e_ident_1[8];
  unsigned char e_ident_2[8];
  uint16_t e_type;
  uint16_t e_machine;
  uint32_t e_version;
  uint32_t e_entry;
  uint32_t e_phoff;
  uint32_t e_shoff;
  uint32_t e_flags;
  uint16_t e_ehsize;
  uint16_t e_phentsize;
  uint16_t e_phnum;
  uint16_t e_shentsize;
  uint16_t e_shnum;
  uint16_t e_shstrndx;
} ElfHeader;

typedef struct {
  uint32_t p_type;
  uint32_t p_offset;
  uint32_t p_vaddr;
  uint32_t p_paddr;
  uint32_t p_filesz;
  uint32_t p_memsz;
  uint32_t p_flags;
  uint32_t p_align;
} ElfPhdr;

typedef struct {
	uint64_t offset;
	uint64_t size;
	uint32_t _compressed;
  uint32_t field_14;
  uint32_t _plaintext;
  uint32_t field_1C;
} SegmentInfo;

typedef struct {
  unsigned char key[16];
  uint64_t pad0;
  uint64_t pad1;
  unsigned char iv[16];
  uint64_t pad2;
  uint64_t pad3;
} MetadataInfo;

typedef struct {
  uint64_t signature_input_length;
  uint32_t signature_type;
  uint32_t section_count;
  uint32_t key_count;
  uint32_t opt_header_size;
  uint32_t field_18;
  uint32_t field_1C;
} MetadataHeader;

typedef struct {
  uint64_t offset;
  uint64_t size;
  uint32_t type;
  int32_t seg_idx;
  uint32_t hashtype;
  int32_t hash_idx;
  uint32_t _encryption;
  int32_t key_idx;
  int32_t iv_idx;
  uint32_t _compression;
} MetadataSection;

typedef struct {
  uint32_t field_0;
  uint32_t field_4;
  uint64_t sys_version;
  uint32_t field_10;
  uint32_t field_14;
  uint32_t field_18;
  uint32_t field_1C;
} SrvkHeader;

typedef struct {
  uint32_t field_0;
  uint32_t _pkg_type;
  uint32_t flags;
  uint32_t field_C;
  uint64_t update_version;
  uint64_t final_size;
  uint64_t decrypted_size;
  uint32_t field_28;
  uint32_t field_30;
  uint32_t field_34;
  uint32_t field_38;
  uint64_t field_3C;
  uint64_t field_40;
  uint64_t field_48;
  uint64_t offset;
  uint64_t size;
  uint64_t part_idx;
  uint64_t total_parts;
  uint64_t field_70;
  uint64_t field_78;
} SpkgHeader;

typedef struct {
  uint32_t subtype;
  uint32_t is_present;
  uint64_t size;
} SceVersionInfo;

typedef struct {
  uint32_t control_type;
  uint32_t size;
  uint64_t more;
} SceControlInfo;

typedef struct {
  unsigned char sce_hash[20];
  unsigned char file_hash[32];
  uint32_t filler1;
  uint32_t filler2;
  uint32_t sdk_version;
} SceControlInfoDigest256;

typedef struct {
  uint32_t magic;
  uint16_t sig_offset;
  uint16_t size;
  uint32_t npdrm_type;
  uint32_t field_C;
  unsigned char content_id[0x30];
  unsigned char digest1[0x10];
  unsigned char hash1[0x20];
  unsigned char hash2[0x20];
  unsigned char sig1r[0x1C];
  unsigned char sig1s[0x1C];
  unsigned char sig2r[0x1C];
  unsigned char sig2s[0x1C];
} SceControlInfoDrm;

typedef struct {
  uint16_t majver;
  uint16_t minver;
  uint16_t style;
  uint16_t riftype;
  uint64_t cid;
  unsigned char content_id[0x30];
  unsigned char actidx[0x10];
  unsigned char klicense[0x10];
  unsigned char dates[0x10];
  unsigned char filler[0x8];
  unsigned char sig1r[0x14];
  unsigned char sig1s[0xC];
} SceRIF;

typedef struct {
  uint64_t offset;
  int32_t idx;
  uint64_t size;
  bool compressed;
  char *key;
  char *iv;
} SceSegment;

typedef struct {
} SCE_KEYS;

typedef struct {
  SCE_KEYS keys[1];
} KeyStore;

typedef struct {
  uint64_t minver;
  uint64_t maxver;
  int keyrev;
  char *key;
  char *iv;
} KeyEntry;

#pragma pack(pop)

enum {
	HEADER_LEN = 0x1000,
	SCE_MAGIC = 0x454353
};
