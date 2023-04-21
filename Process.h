#ifndef PROCESS_H
#define PROCESS_H

#include <cstdint>
#include <cstring>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

class Process {
 private:
  char processName[1024];
  pid_t processId;
  void* processHandle;

  uintptr_t findBaseAddress();

 public:
  uintptr_t baseAddress;
  Process(const char* szProcessName);
  ~Process();

  bool writeMemory(uintptr_t address, void* buffer, uint32_t size);
  bool readMemory(uintptr_t address, void* buffer, uint32_t size);
  uintptr_t allocateMemory(uint32_t size);
  bool freeMemory(uintptr_t address);
};

#endif // PROCESS_H
