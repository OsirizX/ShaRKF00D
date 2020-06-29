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

#include "debugscreen/debugScreen.h"
#define printf psvDebugScreenPrintf

#define OUT_FOLDER "ux0:/ShaRKF00D"
#define DECOMPRESS_NEW   0x01
#define DECOMPRESS_DONE  0x02
#define DECOMPRESS_SEGOK 0x04

#define htole32(x) ((uint32_t)(x))

enum {
	DUMP_SELF,
	DUMP_ELF
};

static SceUID decompressThread_tid, decompress_flag;
static char *current_file, *current_elf, *current_self;
static int dump_type = DUMP_ELF;

int extract(const char *path) {
  int res;

  pfsUmount();

  res = pfsMount(path);

  // In case we're at ux0:patch or grw0:patch we need to apply the mounting at ux0:app or gro0:app
  if (res < 0) {
    if (strncasecmp(path, "ux0:patch", 9) == 0 ||
        strncasecmp(path, "grw0:patch", 10) == 0) {
        snprintf(path, MAX_PATH_LENGTH, "ux0:app/%s", "PCSI00011");
        res = pfsMount(path);
    }
  }

  copyFile("ux0:/patch/PCSI00011/module/libshacccg.suprx", "ux0:/data/libshacccg.suprx", 0);
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

int decrypt(void) {
	char aid[8];
	int res;
	sceIoMkdir(OUT_FOLDER"",6);
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
  char *text = "ux0:/data/libshacccg.suprx";
	char titleid[20];
	char rif_path[PATH_MAX];
	char out_path[PATH_MAX];
	char elf_path[PATH_MAX];
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
			snprintf(elf_path, PATH_MAX, OUT_FOLDER"/%s.elf","libshacccg.suprx"); 
			current_file = current_elf = elf_path;
			if(dump_type == DUMP_SELF) {
				snprintf(out_path, PATH_MAX, OUT_FOLDER"/%s","libshacccg.suprx"); 
				current_file = out_path;
				current_elf = elf_path;
			}
			printf("Outpath: %s\n", current_file);

			current_self = malloc(HEADER_LEN);
			if(!current_self) {
				printf("Could not allocate memory\n");
			}

			printf("ReadFile %s current_self\n", text);
			if((res = ReadFile(text, current_self, HEADER_LEN)) < 0) {
				printf("Could not read original self: %x\n", res);
				free(current_self);
				//menu_entry = menu_entry->next ;
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
	        strncpy(titleid, "PCSI00011", 20);
					printf("Setting title id to: %s\n", titleid);
					snprintf(rif_path, PATH_MAX, "ux0:app/%s/sce_sys/package/work.bin",titleid);
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

int make_fself(void) {
	uint32_t mod_nid;
	uint64_t authid = 0;
	uint32_t mem_budget = 0;
	uint32_t phycont_mem_budget = 0;
	uint32_t attribute_cinfo = 0;
	int compressed = 0;
	int safe = 2;
  char *input_path = OUT_FOLDER "/" "libshacccg.suprx.elf";
  char *output_path = OUT_FOLDER "/" "libshacccg.suprx";

  printf("make_fself %s -> %s\n", input_path, output_path);

  if (sha256_32_file(input_path, &mod_nid) != 0) {
		printf("Cannot generate module NID");
		goto error;
	}
	printf("module NID 0x%x\n", mod_nid);

  SceUID fin = sceIoOpen(input_path, SCE_O_RDONLY, 0);
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

  extract("ux0:/patch/PCSI00011/");
  decrypt();
  make_fself();

	sceIoMkdir("ur0:/data",6);
  copyFile("ux0:/ShaRKF00D/libshacccg.suprx", "ur0:/data/libshacccg.suprx", 0);

	sceKernelExitProcess(0);
  return 0;
}
