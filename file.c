/*
  VitaShell
  Copyright (C) 2015-2018, TheFloW

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "main.h"
#include "vitashell_error.h"
//#include "browser.h"
//#include "init.h"
//#include "archive.h"
//#include "file.h"
//#include "utils.h"
//#include "sha1.h"
//#include "strnatcmp.h"

static char *devices[] = {
    "gro0:",
    "grw0:",
    "imc0:",
    "os0:",
    "pd0:",
    "sa0:",
    "sd0:",
    "tm0:",
    "ud0:",
    "uma0:",
    "ur0:",
    "ux0:",
    "vd0:",
    "vs0:",
    "xmc0:",
    "host0:",
};

#define N_DEVICES (sizeof(devices) / sizeof(char **))

const char symlink_header_bytes[SYMLINK_HEADER_SIZE] = {0xF1, 0x1E, 0x00, 0x00};

int ReadFile(const char *file, void *buf, int size) {
  SceUID fd = sceIoOpen(file, SCE_O_RDONLY, 0);
  if (fd < 0)
    return fd;

  int read = sceIoRead(fd, buf, size);

  sceIoClose(fd);
  return read;
}

int WriteFileSeek(const char *file, void *buf, size_t seek, size_t size) {
	SceUID fd = sceIoOpen(file, SCE_O_WRONLY | SCE_O_CREAT, 0777);
	if (fd < 0)
	return fd;
	sceIoLseek(fd, seek, SCE_SEEK_SET);
	int written = sceIoWrite(fd, buf, size);

	sceIoClose(fd);
	return written;
}

int WriteFile(const char *file, const void *buf, int size) {
  SceUID fd = sceIoOpen(file, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0777);
  if (fd < 0)
    return fd;

  int written = sceIoWrite(fd, buf, size);

  sceIoClose(fd);
  return written;
}

int getFileSize(const char *file) {
  SceUID fd = sceIoOpen(file, SCE_O_RDONLY, 0);
  if (fd < 0)
    return fd;

  int fileSize = sceIoLseek(fd, 0, SCE_SEEK_END);

  sceIoClose(fd);
  return fileSize;
}

int checkExists(const char *path) {
	SceIoStat stat;
	return sceIoGetstat(path, &stat);
}

int checkFileExist(const char *file) {
  SceUID fd = sceIoOpen(file, SCE_O_RDONLY, 0);
  if (fd < 0)
    return 0;

  sceIoClose(fd);
  return 1;
}

int checkFolderExist(const char *folder) {
  SceUID dfd = sceIoDopen(folder);
  if (dfd < 0)
    return 0;

  sceIoDclose(dfd);
  return 1;
}

int copyFile(const char *src_path, const char *dst_path, FileProcessParam *param) {
  // The source and destination paths are identical
  if (strcasecmp(src_path, dst_path) == 0) {
    return VITASHELL_ERROR_SRC_AND_DST_IDENTICAL;
  }

  // The destination is a subfolder of the source folder
  int len = strlen(src_path);
  if (strncasecmp(src_path, dst_path, len) == 0 && (dst_path[len] == '/' || dst_path[len - 1] == '/')) {
    return VITASHELL_ERROR_DST_IS_SUBFOLDER_OF_SRC;
  }

  SceUID fdsrc = sceIoOpen(src_path, SCE_O_RDONLY, 0);
  if (fdsrc < 0)
    return fdsrc;

  SceUID fddst = sceIoOpen(dst_path, SCE_O_WRONLY | SCE_O_CREAT | SCE_O_TRUNC, 0777);
  if (fddst < 0) {
    sceIoClose(fdsrc);
    return fddst;
  }

  void *buf = memalign(4096, TRANSFER_SIZE);

  while (1) {
    int read = sceIoRead(fdsrc, buf, TRANSFER_SIZE);

    if (read < 0) {
      free(buf);

      sceIoClose(fddst);
      sceIoClose(fdsrc);

      sceIoRemove(dst_path);

      return read;
    }

    if (read == 0)
      break;

    int written = sceIoWrite(fddst, buf, read);

    if (written < 0) {
      free(buf);

      sceIoClose(fddst);
      sceIoClose(fdsrc);

      sceIoRemove(dst_path);

      return written;
    }

    if (param) {
      if (param->value)
        (*param->value) += read;

      if (param->SetProgress)
        param->SetProgress(param->value ? *param->value : 0, param->max);

      if (param->cancelHandler && param->cancelHandler()) {
        free(buf);

        sceIoClose(fddst);
        sceIoClose(fdsrc);

        sceIoRemove(dst_path);

        return 0;
      }
    }
  }

  free(buf);

  // Inherit file stat
  SceIoStat stat;
  memset(&stat, 0, sizeof(SceIoStat));
  sceIoGetstatByFd(fdsrc, &stat);
  sceIoChstatByFd(fddst, &stat, 0x3B);

  sceIoClose(fddst);
  sceIoClose(fdsrc);

  return 1;
}

int hasEndSlash(const char *path) {
  return path[strlen(path) - 1] == '/';
}

int removePath(const char *path, FileProcessParam *param) {
  SceUID dfd = sceIoDopen(path);
  if (dfd >= 0) {
    int res = 0;

    do {
      SceIoDirent dir;
      memset(&dir, 0, sizeof(SceIoDirent));

      res = sceIoDread(dfd, &dir);
      if (res > 0) {
        char *new_path = malloc(strlen(path) + strlen(dir.d_name) + 2);
        snprintf(new_path, MAX_PATH_LENGTH, "%s%s%s", path, hasEndSlash(path) ? "" : "/", dir.d_name);

        if (SCE_S_ISDIR(dir.d_stat.st_mode)) {
          int ret = removePath(new_path, param);
          if (ret <= 0) {
            free(new_path);
            sceIoDclose(dfd);
            return ret;
          }
        } else {
          int ret = sceIoRemove(new_path);
          if (ret < 0) {
            free(new_path);
            sceIoDclose(dfd);
            return ret;
          }

          if (param) {
            if (param->value)
              (*param->value)++;

            if (param->SetProgress)
              param->SetProgress(param->value ? *param->value : 0, param->max);

            if (param->cancelHandler && param->cancelHandler()) {
              free(new_path);
              sceIoDclose(dfd);
              return 0;
            }
          }
        }

        free(new_path);
      }
    } while (res > 0);

    sceIoDclose(dfd);

    int ret = sceIoRmdir(path);
    if (ret < 0)
      return ret;

    if (param) {
      if (param->value)
        (*param->value)++;

      if (param->SetProgress)
        param->SetProgress(param->value ? *param->value : 0, param->max);

      if (param->cancelHandler && param->cancelHandler()) {
        return 0;
      }
    }
  } else {
    int ret = sceIoRemove(path);
    if (ret < 0)
      return ret;

    if (param) {
      if (param->value)
        (*param->value)++;

      if (param->SetProgress)
        param->SetProgress(param->value ? *param->value : 0, param->max);

      if (param->cancelHandler && param->cancelHandler()) {
        return 0;
      }
    }
  }

  return 1;
}

