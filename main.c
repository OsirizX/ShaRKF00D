#include <string.h>
#include <stdbool.h>
#include "main.h"
#include "pfs.h"
#include "sha256.h"
#include "modules/common/elf.h"
#include "modules/common/self.h"
#include "modules/kplugin//kentente.h"
#include "modules/uplugin/userAllied.h"
#include "sce-elf.h"
#include "aes.h"

#include "debugscreen/debugScreen.h"
#define printf psvDebugScreenPrintf

#define OUT_FOLDER "ux0:/ShaRKF00D"
#define TITLEID "PCSI00011"

#define DECOMPRESS_NEW   0x01
#define DECOMPRESS_DONE  0x02
#define DECOMPRESS_SEGOK 0x04

#define CONTROL_TYPE_CONTROL_FLAGS 1
#define CONTROL_TYPE_DIGEST_SHA1 2
#define CONTROL_TYPE_NPDRM_PS3 3
#define CONTROL_TYPE_DIGEST_SHA256 4
#define CONTROL_TYPE_NPDRM_VITA 5
#define CONTROL_TYPE_UNK_SIG1 6
#define CONTROL_TYPE_UNK_HASH1 7

#define SECURE_BOOL_UNUSED 0
#define SECURE_BOOL_NO 1
#define SECURE_BOOL_YES 2

#define SCE_TYPE_SELF 1
#define SCE_TYPE_SRVK 2
#define SCE_TYPE_SPKG 3
#define SCE_TYPE_DEV 0xC0

#define SELF_TYPE_NONE 0
#define SELF_TPYPE_KERNEL 0x07
#define SELF_TYPE_APP 0x08
#define SELF_TYPE_BOOT 0x09
#define SELF_TYPE_SECURE 0x0B
#define SELF_TYPE_USER 0x0D

#define KEY_TYPE_METADATA 0
#define KEY_TYPE_NPDRM 1

#define SELF_PLATFORM_PS3 0
#define SELF_PLATFORM_VITA 0x40

#define SPKG_TYPE_TYPE_0 0x0
#define SPKG_TYPE_OS0 0x1
#define SPKG_TYPE_TYPE_2 0x2
#define SPKG_TYPE_TYPE_3 0x3
#define SPKG_TYPE_PERMISSIONS_4 0x4
#define SPKG_TYPE_TYPE_5 0x5
#define SPKG_TYPE_TYPE_6 0x6
#define SPKG_TYPE_TYPE_7 0x7
#define SPKG_TYPE_SYSCON_8 0x8
#define SPKG_TYPE_BOOT 0x9
#define SPKG_TYPE_VS0 0xA
#define SPKG_TYPE_CPFW 0xB
#define SPKG_TYPE_MOTION_C 0xC
#define SPKG_TYPE_BBMC_D 0xD
#define SPKG_TYPE_TYPE_E 0xE
#define SPKG_TYPE_MOTION_F 0xF
#define SPKG_TYPE_TOUCH_10 0x10
#define SPKG_TYPE_TOUCH_11 0x11
#define SPKG_TYPE_SYSCON_12 0x12
#define SPKG_TYPE_SYSCON_13 0x13
#define SPKG_TYPE_SYSCON_14 0x14
#define SPKG_TYPE_TYPE_15 0x15
#define SPKG_TYPE_VS0_TAR_PATCH 0x16
#define SPKG_TYPE_SA0 0x17
#define SPKG_TYPE_PD0 0x18
#define SPKG_TYPE_SYSCON_19 0x19
#define SPKG_TYPE_TYPE_1A 0x1A
#define SPKG_TYPE_PSPEMU_LIST 0x1B

#define CONTROL_TYPE_CONTROL_FLAGS 1
#define CONTROL_TYPE_DIGEST_SHA1 2
#define CONTROL_TYPE_NPDRM_PS3 3
#define CONTROL_TYPE_DIGEST_SHA256 4
#define CONTROL_TYPE_NPDRM_VITA 5
#define CONTROL_TYPE_UNK_SIG1 6
#define CONTROL_TYPE_UNK_HASH1 7

#define SECURE_BOOL_UNUSED 0
#define SECURE_BOOL_NO 1
#define SECURE_BOOL_YES 2

#define ENCRYPTION_TYPE_NONE 1
#define ENCRYPTION_TYPE_AES128CTR 3

#define HASH_TYPE_NONE 1
#define HASH_TYPE_HMACSHA1 2
#define HASH_TYPE_HMACSHA256 6

#define COMPRESSION_TYPE_NONE 1
#define COMPRESSION_TYPE_DEFLATE 2

#define htole32(x) ((uint32_t)(x))

enum {
	DUMP_SELF,
	DUMP_ELF
};

static SceUID decompressThread_tid, decompress_flag;
static char *current_file, *current_elf, *current_self;
static int dump_type = DUMP_ELF;

int extract(const char *src, const char *dst, const char *titleid) {
  int res;
  char path[MAX_PATH_LENGTH];

  pfsUmount();

  snprintf(path, MAX_PATH_LENGTH, "ux0:app/%s", titleid);
  res = pfsMount(path);

  copyFile(src, dst, 0);
  printf("extract done\n");
  pfsUmount();
  return 0;
}

int decompressThread(unsigned int argc,  void *argv) {
	while(1) {
		unsigned int outbits;
		sceKernelWaitEventFlag(decompress_flag, (DECOMPRESS_NEW | DECOMPRESS_DONE), (SCE_EVENT_WAITOR | SCE_EVENT_WAITCLEAR), &outbits, 0);
		if(outbits & DECOMPRESS_DONE)
			break;
		sceKernelClearEventFlag(decompress_flag, DECOMPRESS_SEGOK);
		SCE_header *shdr = (SCE_header*)(current_self);
		Elf32_Ehdr *ehdr = (Elf32_Ehdr*)(current_self + shdr->elf_offset);
		Elf32_Phdr *phdrs = (Elf32_Phdr*)(current_self + shdr->phdr_offset);
		printf("starting decompress\n");
		for(int i = 0; i < ehdr->e_phnum; i++) {
			char current_path[PATH_MAX];
			snprintf(current_path, PATH_MAX, "%s.seg%i", current_elf, i);
			printf("checking %s\n",current_path);
			if(checkExists(current_path)==0) {
				printf("found\n");
				size_t seg_sz = phdrs[i].p_filesz;
				int res;
				if(seg_sz <= 0) {
					printf("Empty segment, will skip and delete %i\n", i);
					if(i > 0) {
						uint64_t padding_off =  (phdrs[i-1].p_offset + phdrs[i-1].p_filesz);
						size_t padding_sz = phdrs[i].p_offset - padding_off;
						if(padding_sz > 0) {
							char *padding = malloc(padding_sz);
							if(padding) {
								memset(padding, 0, padding_sz);
								if((res = WriteFileSeek(current_elf, padding, padding_off, padding_sz))<0)
									printf("Could not write padding: %i,%i\n", i, res);
								free(padding);
							} else
								printf("Could not generate padding: %i,%x,%x\n", i, padding_sz, padding_off);
						}
					}
					sceIoRemove(current_path);
					continue;
				}
				size_t sz = getFileSize(current_path);
				char *file_buf = malloc(sz);
				if(!file_buf) {
					printf("Could not allocate memory for decompression(file) %i\n", i);
					break;
				}
				void *dest_buf = malloc(phdrs[i].p_filesz);
				if(!dest_buf) {
					printf("Could not allocate memory for decompression(dest) %i\n", i);
					free(file_buf);
					break;
				}
				if((res = ReadFile(current_path, file_buf,sz))<0) {
					printf("Could not read decrypted segment: %i,%x\n", i, res);
					free(file_buf);
					free(dest_buf);
					break;
				}
				if((res = uncompress(dest_buf, (long unsigned int *)&seg_sz, file_buf, sz))!= Z_OK) {
					seg_sz =  phdrs[i].p_filesz;
					printf("Could not decompress segment, will attempt inflate: %i,%i,%x\n", i, res, phdrs[i].p_type);
          free(file_buf);
          free(dest_buf);
          break;
				}
				if(dump_type == DUMP_SELF) {
					printf("Compressing segment for self: %i\n", i);
					if((res = compress(file_buf, (long unsigned int *)&sz, dest_buf, seg_sz))!= Z_OK) {
						printf("Could not compress: %i,%i,%x\n", i, res, phdrs[i].p_type);
						free(file_buf);
						free(dest_buf);
						break;
					}
					segment_info *seg = (segment_info*)(current_self + shdr->section_info_offset);
					seg[i].encryption = 2;
					if((res = WriteFileSeek(current_file, file_buf, seg[i].offset, sz)) < 0)
						printf("Could not write decrypted segment to self: %i,%x\n", i, res);
				}
				free(file_buf);
				if((res = WriteFileSeek(current_elf, dest_buf, phdrs[i].p_offset, phdrs[i].p_filesz))<0)
					printf("Could not write decrypted segment to elf: %i,%x\n", i, res);
				free(dest_buf);
				if((res = sceIoRemove(current_path))<0)
					printf("Could not remove decrypted segment to elf: %i,%x\n", i, res);
				printf("Finished segment %i\n", i);
			}
		}
		sceKernelSetEventFlag(decompress_flag, DECOMPRESS_SEGOK);

	}
	sceKernelSetEventFlag(decompress_flag, DECOMPRESS_SEGOK);
	sceClibPrintf("would exit\n");
	sceKernelExitDeleteThread(0);
	return 0;
}

void dumpExtractTitleId(const char *path, char *titleid) {
	char temp_path[PATH_MAX];
	strcpy(temp_path, path);
	char *folder = (char *)&temp_path;
	folder = strchr(folder, ':') + 1;
	if(folder[0] == '/')
		folder++;
	folder = strchr(folder, '/') + 1;
	char *end_path  = strchr(folder, '/');
	*end_path = 0;
	strncpy(titleid, folder, 20);
}

int dumpVerifyElf(const char *path,  uint8_t *orig_elf_digest) {
	int res =0;
	size_t sz = getFileSize(path);
	if(sz < 0)
		return 0;
	uint8_t *elf = (uint8_t*)malloc(sz);
	uint8_t elf_digest[0x20];
	if(elf) {
		if(ReadFile(path, elf, sz) <0) {
			free(elf);
			return 0;
		}
		SHA256_CTX ctx;
		sha256_init(&ctx);
		sha256_update(&ctx, elf, sz);
		sha256_final(&ctx, elf_digest);
		res = !memcmp(orig_elf_digest, &elf_digest, sizeof(elf_digest));
		free(elf);

	} else
		return 0;
	return res;
}

int decrypt(const char *text, const char *elf_path, const char *titleid) {
	char aid[8];
	int res;
	if(userAlliedStatus() != ENTENTE_DONE) {
		printf("ERROR kuEntente is busy\n");
	}
	if((res=sceRegMgrGetKeyBin("/CONFIG/NP", "account_id", aid, sizeof(aid)))<0) {
		printf("Obtaining AID: %x\n", res);
		return 0;
	}
	printf("Obtaining AID: %x\n", res);
	char rif_name[0x30];
	if((res=_sceNpDrmGetFixedRifName(rif_name, 0, 0LL))<0) {
		printf("Obtaining Fixed Rif name: %x\n", res);
		return 0;
	}
	printf("Obtaining Fixed Rif name: %s\n", rif_name);
	char rif_path[PATH_MAX];
	char mount_point[0x11];
	int auth_type = 0;
	int system = 0;

	decompress_flag = sceKernelCreateEventFlag( "DecompressEvent", 0, 0, NULL );
	decompressThread_tid = sceKernelCreateThread("decompress_thread", decompressThread, 0x10000100, 0x10000, 0, 0, NULL);
	if(decompressThread_tid>0)
		sceKernelStartThread(decompressThread_tid, 0, NULL);
    auth_type = 0;
    system = 1;
			printf("Decrypting: %s\n", text);
			current_file = current_elf = elf_path;
			printf("Outpath: %s\n", current_file);

			current_self = malloc(HEADER_LEN);
			if(!current_self) {
				printf("Could not allocate memory\n");
			}

			printf("ReadFile %s current_self\n", text);
			if((res = ReadFile(text, current_self, HEADER_LEN)) < 0) {
				printf("Could not read original self: %x\n", res);
				free(current_self);
			}

			char temp_outpath[PATH_MAX];
			snprintf(temp_outpath, PATH_MAX, "%s.temp", current_elf);
			printf("current_elf %s\n", temp_outpath);
			current_elf = temp_outpath;
			ententeParams param;
			param.rifpath = rif_path;
			param.path = text;
			param.outpath = temp_outpath;
			param.path_id = 24;
			param.self_type = 1;
			if(system) {
				if(strstr(text,"os0")!=NULL && strstr(text,".skprx")!=NULL) {
					param.self_type = 0;
					printf("Setting to system self\n");
				}
			  printf("menu_entr->text %s\n", text);
				if(strstr(text,"app_em")  != NULL)
					param.path_id = 23;
				else if(strstr(text,"patch_em")  != NULL)
					param.path_id = 24;
				else if(strstr(text,"vs0_em") != NULL)
					param.path_id = 3;
				else if(strstr(text,"os0_em") != NULL)
					param.path_id = 2;

			  printf("param.path_id %d\n", param.path_id);
				if(param.path_id == 24||param.path_id == 23) {
					auth_type = 1;
					printf("Setting title id to: %s\n", titleid);
					snprintf(rif_path, PATH_MAX, "ux0:app/%s/sce_sys/package/work.bin", titleid);
			    printf("rif_path %s\n", rif_path);
					if(checkExists(rif_path)!=0) {
						printf("work.bin not found: %s\n", rif_path);
						param.rifpath = NULL;
					} else
						printf("Using work.bin: %s\n", rif_path);

				} else
					param.rifpath = NULL;
				printf("Setting path id to %i\n", param.path_id);
			}

			char auth_outpath[PATH_MAX];
			char old_path[PATH_MAX];
			strcpy(old_path, old_path);
			snprintf(old_path, PATH_MAX, "%s.auth", current_elf);
			printf("old_path %s\n", old_path);
			SCE_header *shdr = (SCE_header*)(current_self);
			Elf32_Ehdr *ehdr = (Elf32_Ehdr*)(current_self + shdr->elf_offset);
			SCE_appinfo *appinfo = (SCE_appinfo*)(current_self + shdr->appinfo_offset);
			if(!auth_type) {
				strncpy(auth_outpath, old_path, PATH_MAX);
				strcpy(strstr(auth_outpath, ".temp"), ".auth");
			} else {
				if(appinfo->self_type != 0x8) {
					printf("Skipping because not needed\n");
					free(current_self);
				}
				strncpy(auth_outpath, old_path, PATH_MAX);
				snprintf(auth_outpath, PATH_MAX, "%s/self_auth.bin", OUT_FOLDER);
				printf("auth path: %s\n", auth_outpath);
			}
			param.self_auth =  (checkExists(auth_outpath) < 0);
			userAlliedDecryptSelf(&param);
			printf("Waiting for decrypter\n");
			char buffer[128];
			while(userAlliedStatus() != ENTENTE_UPDATE);
			while(1) {
				if(userAlliedStatus() == ENTENTE_DONESEG) {
					userAlliedGetLogs(buffer);
					printf("kuEntente: %s\n", buffer);
				}
				if(userAlliedStatus() == ENTENTE_UPDATE) {
					userAlliedGetLogs(buffer);
					printf("kuEntente: %s\n", buffer);
				} else if(userAlliedStatus() == ENTENTE_DONE)
					break;
			}
			userAlliedGetLogs(buffer);
			printf("kuEntente: %s\n", buffer);
			sceKernelWaitEventFlag(decompress_flag, DECOMPRESS_SEGOK, SCE_EVENT_WAITAND, 0, 0);
			sceKernelSetEventFlag(decompress_flag, DECOMPRESS_NEW);
			sceKernelWaitEventFlag(decompress_flag, DECOMPRESS_SEGOK, SCE_EVENT_WAITAND, 0, 0);

			ehdr->e_shnum = 0;
			ehdr->e_shoff = 0;

			if((res = WriteFileSeek(current_elf, current_self + shdr->elf_offset, 0, sizeof(Elf32_Ehdr))) < 0) {
				printf("Could not write original elfhdr to elf: %x\n", res);
				free(current_self);
			}
			if((res = WriteFileSeek(current_elf, current_self + shdr->phdr_offset, ehdr->e_phoff, ehdr->e_phentsize * ehdr->e_phnum)) < 0) {
				printf("Could not write original phdrs to elf: %x\n", res);
				free(current_self);
			}
			if(param.self_auth) {
				if((res = sceIoRename(old_path, auth_outpath)) < 0)
					printf("Could not properly save self auth: %x\n", res);
				else
					printf("Saved self auth: %s\n", auth_outpath);
			}
			printf("Stripping NpDRM from header...\n");
			uint8_t orig_elf_digest[0x20];
			PSVita_CONTROL_INFO *control_info = (PSVita_CONTROL_INFO *)(current_self + shdr->controlinfo_offset);
			while(control_info->next) {
				switch(control_info->type) {
					case 4:
						control_info->PSVita_elf_digest_info.min_required_fw = 0x0;
						memcpy(&orig_elf_digest, control_info->PSVita_elf_digest_info.elf_digest, sizeof(orig_elf_digest));
						printf("Got elf digest\n");
						break;
					case 5:
						memset(&control_info->PSVita_npdrm_info, 0, sizeof(control_info->PSVita_npdrm_info));
						break;
				}
				control_info = (PSVita_CONTROL_INFO*)((char*)control_info + control_info->size);
			}


			if(dump_type == DUMP_SELF) {
				if((res = WriteFileSeek(current_file, current_self + shdr->elf_offset, shdr->header_len, sizeof(Elf32_Ehdr))) < 0) {
					printf("Could not write original elfhdr to self: %x\n", res);
					free(current_self);
				}
				if((res = WriteFileSeek(current_file, current_self + shdr->phdr_offset, shdr->header_len + ehdr->e_phoff, ehdr->e_phentsize * ehdr->e_phnum)) < 0) {
					printf("Could not write original phdrs to self: %x\n", res);
					free(current_self);
				}
				appinfo->version = 0;
				shdr->sdk_type = 0xc0;
				if((res = WriteFileSeek(current_file, current_self, 0, 0x600)) < 0) {
					printf("Could not write original shdr to self: %x\n", res);
					free(current_self);
				}
				if(dumpVerifyElf(current_elf, orig_elf_digest)) {
					printf("ELF VERIFIED. PURIST REJOICE!\n");
					if((res = sceIoRemove(current_elf)) < 0)
						printf("Could not remove temp elf\n");
				} else
					printf("ELF IS CORRUPTED. IT IS AS BAD AS MAI. Or its too big.\n");
			} else {
        sceIoRemove(elf_path);
				if((res = sceIoRename(current_elf, elf_path)) < 0) {
						printf("Could not rename to output: %x\n", res);
						free(current_self);
				}
				snprintf(temp_outpath, PATH_MAX, "%s.sha256", elf_path);
				printf("Saving digest to: %s\n", temp_outpath);
				if((res = WriteFile(temp_outpath, &orig_elf_digest, sizeof(orig_elf_digest))) < 0)
					printf("Error saving digest: %x\n", res);
			}

			free(current_self);
			printf("Module done\n");
	sceKernelSetEventFlag(decompress_flag, DECOMPRESS_DONE);
	sceKernelWaitEventFlag(decompress_flag, DECOMPRESS_SEGOK, SCE_EVENT_WAITAND, 0, 0);
	sceKernelWaitThreadEnd(decompressThread_tid, &res, NULL);
	printf("Done\n");
	return 0;
}

SceSegment *get_segments(SceUID *inf, SceHeader *sce_hdr, KeyEntry *ke, const uint64_t sysver, uint32_t self_type, int keytype, unsigned char *klictxt) {
  unsigned char *dat = (unsigned char *)malloc(sizeof(unsigned char)*(sce_hdr->header_length - sce_hdr->metadata_offset - 48));
  sceIoLseek(*inf, sce_hdr->metadata_offset + 48, SCE_SEEK_SET);
  sceIoRead(*inf, &dat[0], sizeof(unsigned char)*(sce_hdr->header_length - sce_hdr->metadata_offset - 48));
  printf("dat: %llx\n", *(uint64_t *)dat);

  const char *key = ke->key;
  const char *iv = ke->iv;
  aes_context aes_ctx;
  MetadataInfo dec_in;

  if (self_type == SELF_TYPE_APP) {
    keytype = 0;
    if (sce_hdr->key_revision >= 2)
        keytype = 1;
    unsigned char np_key_bytes[16] = { 0x16, 0x41, 0x9d, 0xd3, 0xbf, 0xbe, 0x8b, 0xdc, 0x59, 0x69, 0x29, 0xb7, 0x2c, 0xe2, 0x37, 0xcd };
    unsigned char np_iv_bytes[16];
    unsigned char predec[16];
    aes_setkey_dec(&aes_ctx, np_key_bytes, 128);
    memset(np_iv_bytes, 0, sizeof(np_iv_bytes));
    aes_crypt_cbc(&aes_ctx, AES_DECRYPT, sizeof(predec), np_iv_bytes, klictxt, predec);
    printf("predec: %llx %llx\n", *(uint64_t *)&predec[0], *(uint64_t *)(&predec[8]));

    aes_setkey_dec(&aes_ctx, predec, 128);
    memset(np_iv_bytes, 0, sizeof(np_iv_bytes));
    aes_crypt_cbc(&aes_ctx, AES_DECRYPT, sizeof(MetadataInfo), np_iv_bytes, &dat[0], (unsigned char *)&dec_in);
    printf("dec_in: %llx\n", *(uint64_t *)&dec_in);
  } else {
    memcpy((unsigned char *)&dec_in, &dat[0], sizeof(MetadataInfo));
  }
  MetadataInfo dec;

  unsigned char key_bytes[32] = { 0x12, 0xd6, 0x4d, 0x01, 0x72, 0x49, 0x52, 0x26, 0x01, 0x0a, 0x68, 0x7d, 0xe2, 0x45, 0xa7, 0x3d, 0xe0, 0x28, 0xb3, 0x56, 0x1e, 0x25, 0xe6, 0x9b, 0xab, 0xc3, 0x25, 0x63, 0x6f, 0x3c, 0xae, 0x0a };
  unsigned char iv_bytes[16] = { 0xf1, 0x49, 0xee, 0xd1, 0x75, 0x7e, 0x5a, 0x91, 0x5b, 0x24, 0x30, 0x97, 0x95, 0xbf, 0xc3, 0x80 };
  aes_setkey_dec(&aes_ctx, key_bytes, 256);
  aes_crypt_cbc(&aes_ctx, AES_DECRYPT, 64, iv_bytes, (unsigned char *)&dec_in, (unsigned char *)&dec);

  MetadataInfo *metadata_info = (MetadataInfo *)(&dec);
  printf("key: %llx\n", *(uint64_t *)metadata_info->key);

  unsigned char *dec1 = (unsigned char *)malloc(sizeof(unsigned char) * (sce_hdr->header_length - sce_hdr->metadata_offset - 48 - sizeof(MetadataInfo)));
  aes_setkey_dec(&aes_ctx, metadata_info->key, 128);
  aes_crypt_cbc(&aes_ctx, AES_DECRYPT, sce_hdr->header_length - sce_hdr->metadata_offset - 48 - sizeof(MetadataInfo), metadata_info->iv, &dat[64], &dec1[0]);

  MetadataHeader *metadata_hdr = (MetadataHeader *)(&dec1[0]);
  printf("signature_input_length: 0x%llx\n", metadata_hdr->signature_input_length);

  SceSegment *segs = (SceSegment *)malloc(sizeof(SceSegment)*metadata_hdr->section_count);
  off_t start = sizeof(MetadataHeader) + metadata_hdr->section_count * sizeof(MetadataSection);
  char **key_vault = (char **)malloc(sizeof(char)*metadata_hdr->key_count);

  for (uint32_t i = 0; i < metadata_hdr->key_count; i++) {
    key_vault[i] = (char *)malloc(sizeof(char)*16);
    memcpy(key_vault[i], (char *)(&dec1[0] + (start + (16 * i))), sizeof(char)*16);
  }

  for (uint32_t i = 0; i < metadata_hdr->section_count; i++) {
    MetadataSection *metsec = (MetadataSection *)(&dec1[0] + sizeof(MetadataHeader) + (i * sizeof(MetadataSection)));

    if (metsec->_encryption == ENCRYPTION_TYPE_AES128CTR) {
      segs[i].offset = metsec->offset;
      segs[i].idx = metsec->seg_idx;
      segs[i].compressed = (metsec->_compression == COMPRESSION_TYPE_DEFLATE);
      segs[i].key = key_vault[metsec->key_idx];
      segs[i].iv = key_vault[metsec->iv_idx];
    }
  }

  if (dat)
    free(dat);

  return segs;
}

unsigned char *decompress_segments(const unsigned char *decrypted_data, const size_t size, size_t *decompressed_size) {
  z_stream stream;
  stream.zalloc = Z_NULL;
  stream.zfree = Z_NULL;
  stream.opaque = Z_NULL;
  stream.avail_in = 0;
  stream.next_in = Z_NULL;
  if (inflateInit(&stream) != Z_OK) {
      printf("inflateInit failed while decompressing\n");
      return "";
  }

  int ret = 0;
  stream.next_in = (Bytef *)decrypted_data;
  stream.avail_in = sizeof(unsigned char)*size;
  unsigned char *decompressed_data = (unsigned char *)malloc(sizeof(unsigned char)*5*1024*1024);;

  stream.next_out = (Bytef *)decompressed_data;
  stream.avail_out = 5*1024*1024;

  ret = inflate(&stream, 0);
  *decompressed_size = stream.total_out;

  inflateEnd(&stream);

  if (ret != Z_STREAM_END) {
      printf("Exception during zlib decompression: ({}) {}", ret, stream.msg);
      return "";
  }
  return decompressed_data;
}

int self2elf(const char *infile, const char *outfile, const char *klictxt) {
  SceUID inf = sceIoOpen(infile, SCE_O_RDONLY, 0777);
  SceUID outf = sceIoOpen(outfile, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0777);
  int npdrmtype = 0;

  SceHeader sce_hdr = { 0 };
  sceIoRead(inf, &sce_hdr, sizeof(SceHeader));
  printf("magic: 0x%x\n", sce_hdr.magic);
  printf("data_length: 0x%llx\n", sce_hdr.data_length);

  SelfHeader self_hdr = { 0 };
  sceIoRead(inf, &self_hdr, sizeof(SelfHeader));

  AppInfoHeader appinfo_hdr = { 0 };
  sceIoLseek(inf, self_hdr.appinfo_offset, SCE_SEEK_SET);
  sceIoRead(inf, &appinfo_hdr, sizeof(AppInfoHeader));
  printf("sys_version: 0x%llx\n", appinfo_hdr.sys_version);

  SceVersionInfo verinfo_hdr = { 0 };
  sceIoLseek(inf, self_hdr.sceversion_offset, SCE_SEEK_SET);
  sceIoRead(inf, &verinfo_hdr, sizeof(SceVersionInfo));

  SceControlInfo controlinfo_hdr = { 0 };
  sceIoLseek(inf, self_hdr.controlinfo_offset, SCE_SEEK_SET);
  sceIoRead(inf, &controlinfo_hdr, sizeof(SceControlInfo));
  printf("size: 0x%lx\n", controlinfo_hdr.size);
  size_t ci_off = sizeof(SceControlInfo);

  SceControlInfoDigest256 controldigest256 = { 0 };
  if (controlinfo_hdr.control_type == CONTROL_TYPE_DIGEST_SHA256) {
    sceIoLseek(inf, self_hdr.controlinfo_offset + ci_off, SCE_SEEK_SET);
    ci_off += sizeof(SceControlInfoDigest256);
    sceIoRead(inf, &controldigest256, sizeof(SceControlInfoDigest256));
  }
  sceIoLseek(inf, self_hdr.controlinfo_offset + ci_off, SCE_SEEK_SET);
  sceIoRead(inf, &controlinfo_hdr, sizeof(SceControlInfo));
  ci_off += sizeof(SceControlInfo);

  SceControlInfoDrm controlnpdrm = { 0 };
  if (controlinfo_hdr.control_type == CONTROL_TYPE_NPDRM_VITA) {
    sceIoLseek(inf, self_hdr.controlinfo_offset + ci_off, SCE_SEEK_SET);
    ci_off += sizeof(SceControlInfoDrm);
    sceIoRead(inf, &controlnpdrm, sizeof(SceControlInfoDrm));
    printf("content_id: %s\n", controlnpdrm.content_id);
    npdrmtype = controlnpdrm.npdrm_type;
  }

  // copy elf header
  ElfHeader elf_hdr = { 0 };
  sceIoLseek(inf, self_hdr.elf_offset, SCE_SEEK_SET);
  sceIoRead(inf, &elf_hdr, sizeof(ElfHeader));
  sceIoWrite(outf, &elf_hdr, sizeof(ElfHeader));

  // get segments
  ElfPhdr *elf_phdrs = (ElfPhdr *)malloc(sizeof(ElfPhdr)*elf_hdr.e_phnum);
  SegmentInfo *segment_infos = (SegmentInfo *)malloc(sizeof(SegmentInfo)*elf_hdr.e_phnum);
  size_t at = sizeof(ElfHeader);
  bool encrypted = false;
  for (int i = 0; i < elf_hdr.e_phnum; i++) {
    sceIoLseek(inf, self_hdr.phdr_offset + i*sizeof(ElfPhdr), SCE_SEEK_SET);
    sceIoRead(inf, &elf_phdrs[i], sizeof(ElfPhdr));
    sceIoWrite(outf, &elf_phdrs[i], sizeof(ElfPhdr));
    at += sizeof(ElfPhdr);
    sceIoLseek(inf, self_hdr.segment_info_offset + i*sizeof(SegmentInfo), SCE_SEEK_SET);
    sceIoRead(inf, &segment_infos[i], sizeof(SegmentInfo));
    if (segment_infos[i]._plaintext == SECURE_BOOL_NO)
      encrypted = true;
  }

  printf("self2elf SceSegment\n");
  SceSegment *scesegs;
  if (encrypted) {
    // keys hardcoded for now
    KeyEntry key = { 0x36300000000, 0xFFFFFFFFFFFFFFFF, 1, "12d64d0172495226010a687de245a73de028b3561e25e69babc325636f3cae0a", "f149eed1757e5a915b24309795bfc380" };
    scesegs = get_segments(&inf, &sce_hdr, &key, appinfo_hdr.sys_version, appinfo_hdr._self_type, npdrmtype, klictxt);
  }

  for (uint16_t i = 0; i < elf_hdr.e_phnum; i++) {
    int idx = 0;
    printf("Dumping segment[%d]...\n", i);

    if (scesegs)
      idx = scesegs[i].idx;
    else
      idx = i;
    if (elf_phdrs[idx].p_filesz == 0)
      continue;

    int pad_len = elf_phdrs[idx].p_offset - at;
    if (pad_len < 0) {
      pad_len = 0;
    }

    unsigned char *padding = (unsigned char *)malloc(sizeof(unsigned char)*pad_len);
    memset(padding, '\0', sizeof(unsigned char)*pad_len);
	  sceIoWrite(outf, padding, pad_len);
    if (padding)
      free(padding);

    at += pad_len;

    unsigned char *dat = (unsigned char *)malloc(sizeof(unsigned char)*segment_infos[idx].size);
    sceIoLseek(inf, segment_infos[idx].offset, SCE_SEEK_SET);
    sceIoRead(inf, &dat[0], segment_infos[idx].size);

    unsigned char *decrypted_data = (unsigned char *)malloc(sizeof(unsigned char)*segment_infos[idx].size);
    if (segment_infos[idx]._plaintext == SECURE_BOOL_NO) {
      aes_context aes_ctx;
      aes_setkey_enc(&aes_ctx, (unsigned char *)scesegs[i].key, 128);
      size_t ctr_nc_off = 0;
      unsigned char ctr_stream_block[0x10];
      aes_crypt_ctr(&aes_ctx, segment_infos[idx].size, &ctr_nc_off, (unsigned char *)scesegs[i].iv, ctr_stream_block, &dat[0], &decrypted_data[0]);
    }
    if (dat)
      free(dat);

    size_t decompressed_size;
    if (segment_infos[idx]._compressed == SECURE_BOOL_YES) {
      unsigned char *decompressed_data = decompress_segments(decrypted_data, segment_infos[idx].size, &decompressed_size);
      sceIoWrite(outf, decompressed_data, decompressed_size);
      at += decompressed_size;
      if (decompressed_data)
        free(decompressed_data);
    } else {
      sceIoWrite(outf, &decrypted_data[0], segment_infos[idx].size);
      at += segment_infos[idx].size;
    }

    if (decrypted_data)
      free(decrypted_data);
  }

  if (elf_phdrs)
    free(elf_phdrs);

  if (segment_infos)
    free(segment_infos);

  sceIoClose(inf);
  sceIoClose(outf);
  return 0;
}

int make_fself(const char *input_path, const char *output_path) {
	uint32_t mod_nid;
	uint64_t authid = 0;
	uint32_t mem_budget = 0;
	uint32_t phycont_mem_budget = 0;
	uint32_t attribute_cinfo = 0;
	int compressed = 0;
	int safe = 2;

  printf("make_fself %s -> %s\n", input_path, output_path);

  if (sha256_32_file(input_path, &mod_nid) != 0) {
		printf("Cannot generate module NID");
		goto error;
	}
	printf("module NID 0x%x\n", mod_nid);

  SceUID fin = sceIoOpen(input_path, SCE_O_RDONLY, 0777);
	if (!fin) {
		printf("Failed to open input file\n");
		goto error;
	}
	sceIoLseek(fin, 0, SCE_SEEK_END);
  size_t sz = sceIoLseek(fin, 0, SCE_SEEK_CUR);
	sceIoLseek(fin, 0, SCE_SEEK_SET);

	char *input = calloc(1, sz);
	if (!input) {
		printf("Failed to allocate buffer for input file\n");
		goto error;
	}
	if (sceIoRead(fin, input, sz) < 0) {
		static const char s[] = "Failed to read input file";
		goto error;
	}
	sceIoClose(fin);
	fin = 0;

	Elf32_Ehdr *ehdr = (Elf32_Ehdr*)input;

	// write module nid
	if (ehdr->e_type == ET_SCE_EXEC) {
		Elf32_Phdr *phdr = (Elf32_Phdr*)(input + ehdr->e_phoff);
		sce_module_info_raw *info = (sce_module_info_raw *)(input + phdr->p_offset + phdr->p_paddr);
		info->library_nid = htole32(mod_nid);
	} else if (ehdr->e_type == ET_SCE_RELEXEC) {
		int seg = ehdr->e_entry >> 30;
		int off = ehdr->e_entry & 0x3fffffff;
		Elf32_Phdr *phdr = (Elf32_Phdr*)(input + ehdr->e_phoff + seg * ehdr->e_phentsize);
		sce_module_info_raw *info = (sce_module_info_raw *)(input + phdr->p_offset + off);
		info->library_nid = htole32(mod_nid);
	}

	SCE_header hdr = { 0 };
	hdr.magic = 0x454353; // "SCE\0"
	hdr.version = 3;
	hdr.sdk_type = 0xC0;
	hdr.header_type = 1;
	hdr.metadata_offset = 0x600; // ???
	hdr.header_len = HEADER_LEN;
	hdr.elf_filesize = sz;
	// self_filesize
	hdr.self_offset = 4;
	hdr.appinfo_offset = 0x80;
	hdr.elf_offset = sizeof(SCE_header) + sizeof(SCE_appinfo);
	hdr.phdr_offset = hdr.elf_offset + sizeof(Elf32_Ehdr);
	hdr.phdr_offset = (hdr.phdr_offset + 0xf) & ~0xf; // align
	// hdr.shdr_offset = ;
	hdr.section_info_offset = hdr.phdr_offset + sizeof(Elf32_Phdr) * ehdr->e_phnum;
	hdr.sceversion_offset = hdr.section_info_offset + sizeof(segment_info) * ehdr->e_phnum;
	hdr.controlinfo_offset = hdr.sceversion_offset + sizeof(SCE_version);
	hdr.controlinfo_size = sizeof(SCE_controlinfo_5) + sizeof(SCE_controlinfo_6) + sizeof(SCE_controlinfo_7);
	hdr.self_filesize = 0;

	uint32_t offset_to_real_elf = HEADER_LEN;

	// SCE_header should be ok

	SCE_appinfo appinfo = { 0 };
	if (authid) {
		appinfo.authid = authid;
	} else {
		if (safe)
			appinfo.authid = 0x2F00000000000000ULL | safe;
		else
			appinfo.authid = 0x2F00000000000001ULL;
	}
	appinfo.vendor_id = 0;
	appinfo.self_type = 8;
	appinfo.version = 0x1000000000000;
	appinfo.padding = 0;

	SCE_version ver = { 0 };
	ver.unk1 = 1;
	ver.unk2 = 0;
	ver.unk3 = 16;
	ver.unk4 = 0;

	SCE_controlinfo_5 control_5 = { 0 };
	control_5.common.type = 5;
	control_5.common.size = sizeof(SCE_controlinfo_5);
	control_5.common.unk = 1;
	SCE_controlinfo_6 control_6 = { 0 };
	control_6.common.type = 6;
	control_6.common.size = sizeof(SCE_controlinfo_6);
	control_6.common.unk = 1;
	control_6.is_used = 1;
	if (mem_budget) {
		control_6.attr = attribute_cinfo;
		control_6.phycont_memsize = phycont_mem_budget;
		control_6.total_memsize = mem_budget;
	}
	SCE_controlinfo_7 control_7 = { 0 };
	control_7.common.type = 7;
	control_7.common.size = sizeof(SCE_controlinfo_7);

	Elf32_Ehdr myhdr = { 0 };
	memcpy(myhdr.e_ident, "\177ELF\1\1\1", 8);
	myhdr.e_type = ehdr->e_type;
	myhdr.e_machine = 0x28;
	myhdr.e_version = 1;
	myhdr.e_entry = ehdr->e_entry;
	myhdr.e_phoff = 0x34;
	myhdr.e_flags = 0x05000000U;
	myhdr.e_ehsize = 0x34;
	myhdr.e_phentsize = 0x20;
	myhdr.e_phnum = ehdr->e_phnum;

  SceUID fout = sceIoOpen(output_path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0777);
	if (!fout) {
		printf("Failed to open output file\n");
		goto error;
	}

	sceIoLseek(fout, hdr.appinfo_offset, SCE_SEEK_SET);
	if (sceIoWrite(fout, &appinfo, sizeof(SCE_appinfo)) < 0) {
		printf("Failed to write appinfo\n");
		goto error;
	}

	sceIoLseek(fout, hdr.elf_offset, SCE_SEEK_SET);
	sceIoWrite(fout, &myhdr, sizeof(Elf32_Ehdr));

	// copy elf phdr in same format
	sceIoLseek(fout, hdr.phdr_offset, SCE_SEEK_SET);
	for (int i = 0; i < ehdr->e_phnum; ++i) {
		Elf32_Phdr *phdr = (Elf32_Phdr*)(input + ehdr->e_phoff + ehdr->e_phentsize * i);
		if (phdr->p_align > 0x1000)
			phdr->p_align = 0x1000;
		if (sceIoWrite(fout, phdr, sizeof(Elf32_Phdr)) < 0) {
			printf("Failed to write phdr\n");
			goto error;
		}
	}

	// convert elf phdr info to segment info that sony loader expects
	// first round we assume no compression
	sceIoLseek(fout, hdr.section_info_offset, SCE_SEEK_SET);
	for (int i = 0; i < ehdr->e_phnum; ++i) {
		Elf32_Phdr *phdr = (Elf32_Phdr*)(input + ehdr->e_phoff + ehdr->e_phentsize * i);
		segment_info sinfo = { 0 };
		sinfo.offset = offset_to_real_elf + phdr->p_offset;
		sinfo.length = phdr->p_filesz;
		sinfo.compression = 1;
		sinfo.encryption = 2;
		if (sceIoWrite(fout, &sinfo, sizeof(segment_info)) < 0) {
			printf("Failed to write segment info\n");
			goto error;
		}
	}

	sceIoLseek(fout, hdr.sceversion_offset, SCE_SEEK_SET);
	if (sceIoWrite(fout, &ver, sizeof(SCE_version)) < 0) {
		printf("Failed to write SCE_version\n");
		goto error;
	}

	sceIoLseek(fout, hdr.controlinfo_offset, SCE_SEEK_SET);
	sceIoWrite(fout, &control_5, sizeof(SCE_controlinfo_5));
	sceIoWrite(fout, &control_6, sizeof(SCE_controlinfo_6));
	sceIoWrite(fout, &control_7, sizeof(SCE_controlinfo_7));

	if (!compressed) {
		sceIoLseek(fout, HEADER_LEN, SCE_SEEK_SET);
		if (sceIoWrite(fout, input, sz) < 0) {
			printf("Failed to write a copy of input ELF\n");
			goto error;
		}
	} else {
		for (int i = 0; i < ehdr->e_phnum; ++i) {
			Elf32_Phdr *phdr = (Elf32_Phdr*)(input + ehdr->e_phoff + ehdr->e_phentsize * i);
			segment_info sinfo = { 0 };
			unsigned char *buf = malloc(2 * phdr->p_filesz + 12);
			sinfo.length = 2 * phdr->p_filesz + 12;
			if (compress2(buf, (uLongf *)&sinfo.length, (unsigned char *)input + phdr->p_offset, phdr->p_filesz, Z_BEST_COMPRESSION) != Z_OK) {
				free(buf);
				printf("compress failed\n");
				goto error;
			}
			// padding
			uint64_t pad = ((sinfo.length + 3) & ~3) - sinfo.length;
			for (int i = 0; i < pad; i++) {
				buf[pad+sinfo.length] = 0;
			}
      sinfo.offset = sceIoLseek(fout, 0, SCE_SEEK_CUR);
			sinfo.compression = 2;
			sinfo.encryption = 2;
			sceIoLseek(fout, hdr.section_info_offset + i * sizeof(segment_info), SCE_SEEK_SET);
			if (sceIoWrite(fout, &sinfo, sizeof(sinfo)) < 0) {
				printf("Failed to write segment info\n");
				free(buf);
				goto error;
			}
			sceIoLseek(fout, sinfo.offset, SCE_SEEK_SET);
			if (sceIoWrite(fout, buf, sinfo.length) < 0) {
				printf("Failed to write segment to fself\n");
				goto error;
			}
			free(buf);
		}
	}

	sceIoLseek(fout, 0, SCE_SEEK_END);
  hdr.self_filesize = sceIoLseek(fout, 0, SCE_SEEK_CUR);
	sceIoLseek(fout, 0, SCE_SEEK_SET);
	if (sceIoWrite(fout, &hdr, sizeof(hdr)) < 0) {
		printf("Failed to write SCE header\n");
		goto error;
	}

	sceIoClose(fout);
  printf("make_fself done\n");
	return 0;
error:
  printf("make_fself error\n");
	if (fin)
		sceIoClose(fin);
	if (fout)
		sceIoClose(fout);
	return 1;

}

int main(int argc, const char *argv[]) {
  SceUID patch_modid = -1, kernel_modid = -1, user_modid = -1;
  SceUID kentente_modid = -1, userallied_modid = -1;

  psvDebugScreenInit();

  // Load modules
  int search_unk[2];
  SceUID search_modid;
  search_modid = _vshKernelSearchModuleByName("VitaShellPatch", search_unk);
    printf("_vshKernelSearchModuleByName VitaShellPatch 0x%x\n", search_modid);
  if(search_modid < 0) {
    patch_modid = taiLoadKernelModule("ux0:app/SHARKF00D/sce_module/patch.skprx", 0, NULL);
    printf("taiLoadKernelModule patch skprx 0x%x\n", patch_modid);
    if (patch_modid >= 0) {
      int res = taiStartKernelModule(patch_modid, 0, NULL, 0, NULL, NULL);
    printf("taiStartKernelModule patch skprx 0x%x\n", res);
      if (res < 0)
        taiStopUnloadKernelModule(patch_modid, 0, NULL, 0, NULL, NULL);
    }
  }
  search_modid = _vshKernelSearchModuleByName("VitaShellKernel2", search_unk);
  if(search_modid < 0) {
    kernel_modid = taiLoadKernelModule("ux0:app/SHARKF00D/sce_module/kernel.skprx", 0, NULL);
    printf("taiLoadKernelModule kernel skprx 0x%x\n", kernel_modid);
    if (kernel_modid >= 0) {
      int res = taiStartKernelModule(kernel_modid, 0, NULL, 0, NULL, NULL);
    printf("taiStartKernelModule kernel skprx 0x%x\n", res);
      if (res < 0)
        taiStopUnloadKernelModule(kernel_modid, 0, NULL, 0, NULL, NULL);
    }
  }
  user_modid = sceKernelLoadStartModule("app0:sce_module/user.suprx", 0, NULL, 0, NULL, NULL);

#if 0
  search_modid = _vshKernelSearchModuleByName("kentente", search_unk);
  if(search_modid < 0) {
    kentente_modid = taiLoadKernelModule("ux0:app/SHARKF00D/sce_module/kentente.skprx", 0, NULL);
    if (kentente_modid >= 0) {
      int res = taiStartKernelModule(kentente_modid, 0, NULL, 0, NULL, NULL);
      if (res < 0)
        taiStopUnloadKernelModule(kentente_modid, 0, NULL, 0, NULL, NULL);
    }
  }
  userallied_modid = sceKernelLoadStartModule("app0:sce_module/userAllied.suprx", 0, NULL, 0, NULL, NULL);
#endif

	sceIoMkdir(OUT_FOLDER, 0777);

  // input, output, titleid
  extract("ux0:/patch/PCSI00011/module/libshacccg.suprx", OUT_FOLDER"/libshacccg.suprx.ext", TITLEID);

#if 0 // decrypt method 1
  // input, output, titleid
  decrypt(OUT_FOLDER"/libshacccg.suprx.ext", OUT_FOLDER"/libshacccg.suprx.elf", TITLEID);
#else // decrypt method 2
  SceRIF sce_rif = { 0 };
  //SceUID kf = sceIoOpen("ux0:/license/app/"TITLEID"/6488b73b912a753a492e2714e9b38bc7.rif", SCE_O_RDONLY, 0777);
  SceUID kf = sceIoOpen("ux0:app/"TITLEID"/sce_sys/package/work.bin", SCE_O_RDONLY, 0777);
  sceIoRead(kf, &sce_rif, sizeof(SceRIF));
  sceIoClose(kf);
  printf("content_id: %s\n", sce_rif.content_id);
  printf("klicense: %llx\n", *(uint64_t *)sce_rif.klicense);
  // input, output, license
  self2elf(OUT_FOLDER"/libshacccg.suprx.ext", OUT_FOLDER"/libshacccg.suprx.elf", sce_rif.klicense);
#endif
  make_fself(OUT_FOLDER"/libshacccg.suprx.elf", OUT_FOLDER"/libshacccg.suprx");

	sceIoMkdir("ur0:data", 0777);
  copyFile("ux0:/ShaRKF00D/libshacccg.suprx", "ur0:data/libshacccg.suprx", 0);

	sceKernelExitProcess(0);
  return 0;
}
