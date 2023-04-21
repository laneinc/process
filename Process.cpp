#include "Process.h"

Process::Process(const char* szProcessName)
    : processId(0), processHandle(nullptr), baseAddress(0) {
  // Save the process name.
  strncpy(processName, szProcessName, sizeof(processName) - 1);

  // Find all processes with the given name.
  std::vector<pid_t> processIds;
  DIR* procDir = opendir("/proc");
  if (procDir == nullptr) {
    fprintf(stderr, "Error: Failed to open /proc directory: %s\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }

  struct dirent* entry;
  while ((entry = readdir(procDir)) != nullptr) {
    if (!isdigit(entry->d_name[0])) {
      continue;
    }

    char exePath[1024];
    snprintf(exePath, sizeof(exePath), "/proc/%s/exe", entry->d_name);

    char buffer[1024];
    ssize_t len = readlink(exePath, buffer, sizeof(buffer));
    if (len == -1) {
      continue;
    }
    buffer[len] = '\0';

    const char* exeName = strrchr(buffer, '/');
    if (exeName != nullptr) {
      exeName++;
    } else {
      exeName = buffer;
    }

    if (strcasecmp(exeName, szProcessName) == 0) {
      processIds.push_back(atoi(entry->d_name));
    }
  }
  closedir(procDir);

  if (processIds.empty()) {
    fprintf(stderr, "Error: Failed to find process %s.\n", szProcessName);
    exit(EXIT_FAILURE);
  }

  if (processIds.size() == 1) {
    // Only one process with the given name, use it.
    processId = processIds[0];
  } else {
    // Multiple processes with the given name, prompt the user to select one.
    std::cout << "Multiple processes with name " << szProcessName
              << " found. Please select one to inject into:\n";
    for (size_t i = 0; i < processIds.size(); i++) {
      std::cout << i + 1 << ": Process " << processIds[i] << std::endl;
    }

    int selection;
    std::cin >> selection;
    if (selection < 1 || selection > static_cast<int>(processIds.size())) {
      fprintf(stderr, "Error: Invalid selection.\n");
      exit(EXIT_FAILURE);
    }

    processId = processIds[selection - 1];
  }

  // Check if the user has permission to access process information.
  if (geteuid() != 0) {
    fprintf(stderr,
            "Warning: It is recommended to run as root to access process "
            "information.\n");
  }

  // Open the process for reading and writing.
  char processPath[1024];
  snprintf(processPath, sizeof(processPath), "/proc/%d/mem", processId);

  processHandle = fopen(processPath, "r+b");
  if (processHandle == nullptr) {
    fprintf(stderr, "Error: Failed to open process %s: %s\n", szProcessName,
            strerror(errno));
    exit(EXIT_FAILURE);
  }

  // Find the base address of the process.
  baseAddress = findBaseAddress();
}

Process::~Process() {
  if (processHandle != nullptr) {
    fclose(static_cast<FILE*>(processHandle));
    processHandle = nullptr;
  }
}

bool Process::writeMemory(uintptr_t address,
                          void* buffer,
                          uint32_t size) {
  checkProcess();

  if (processHandle == nullptr) {
    fprintf(stderr, "Error: Process is not open.\n");
    return false;
  }

  if (fseek(static_cast<FILE*>(processHandle), address, SEEK_SET) != 0) {
    fprintf(stderr, "Error: Failed to seek to memory address 0x%lx: %s\n",
            address, strerror(errno));
    return false;
  }

  if (fwrite(buffer, size, 1, static_cast<FILE*>(processHandle)) != 1) {
    fprintf(stderr, "Error: Failed to write memory at address 0x%lx: %s\n",
            address, strerror(errno));
    return false;
  }

  return true;
}

bool Process::readMemory(uintptr_t address,
                         void* buffer,
                         uint32_t size) {
  checkProcess();

  if (processHandle == nullptr) {
    fprintf(stderr, "Error: Process is not open.\n");
    return false;
  }

  if (fseek(static_cast<FILE*>(processHandle), address, SEEK_SET) != 0) {
    fprintf(stderr, "Error: Failed to seek to memory address 0x%lx: %s\n",
            address, strerror(errno));
    return false;
  }

  if (fread(buffer, size, 1, static_cast<FILE*>(processHandle)) != 1) {
    fprintf(stderr, "Error: Failed to read memory at address 0x%lx: %s\n",
            address, strerror(errno));
    return false;
  }

  return true;
}

uintptr_t Process::allocateMemory(uint32_t size) {
  checkProcess();

  void* address = mmap(nullptr, size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (address == MAP_FAILED) {
    fprintf(stderr, "Error: Failed to allocate memory: %s\n", strerror(errno));
    return 0;
  }

  return reinterpret_cast<uintptr_t>(address);
}

bool Process::freeMemory(uintptr_t address) {
  checkProcess();

  if (munmap(reinterpret_cast<void*>(address), sizeof(address)) == -1) {
    fprintf(stderr, "Error: Failed to free memory: %s\n", strerror(errno));
    return false;
  }

  return true;
}

bool Process::createRemoteThread(void* startAddress, void* parameter) {
  checkProcess();

  // Allocate memory for the thread start routine and parameter.
  uintptr_t startRoutineAddress = allocateMemory(1024);
  uintptr_t parameterAddress = allocateMemory(sizeof(parameter));

  // Write the start routine and parameter to the allocated memory.
  writeMemory(startRoutineAddress, startAddress, sizeof(startAddress));
  writeMemory(parameterAddress, parameter, sizeof(parameter));

  // Create a new thread in the process.
  pid_t pid = fork();
  if (pid == -1) {
    fprintf(stderr, "Error: Failed to create new thread: %s\n", strerror(errno));
    return false;
  } else if (pid == 0) {
    // Child process.
    void* startRoutine;
    void* parameter;

    // Read the start routine and parameter from the allocated memory.
    readMemory(startRoutineAddress, &startRoutine, sizeof(startRoutine));
    readMemory(parameterAddress, &parameter, sizeof(parameter));

    // Call the start routine with the parameter.
    int result = reinterpret_cast<int (*)(void*)>(startRoutine)(parameter);

    // Free the allocated memory.
    freeMemory(startRoutineAddress);
    freeMemory(parameterAddress);

    exit(result);
  }

  // Wait for the child process to finish.
  int status;
  if (waitpid(pid, &status, 0) == -1) {
    fprintf(stderr, "Error: Failed to wait for new thread: %s\n",
            strerror(errno));
    return false;
  }

  return true;
}

uintptr_t Process::findBaseAddress() {
  checkProcess();

  char mapsPath[1024];
  snprintf(mapsPath, sizeof(mapsPath), "/proc/%d/maps", processId);

  FILE* mapsFile = fopen(mapsPath, "r");
  if (mapsFile == nullptr) {
    fprintf(stderr, "Error: Failed to open process memory map: %s\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }

  uintptr_t baseAddress = 0;

  char line[1024];
  while (fgets(line, sizeof(line), mapsFile) != nullptr) {
    if (strstr(line, "r-xp") == nullptr) {
      continue;
    }

    char* endptr;
    uintptr_t startAddress = strtoull(line, &endptr, 16);
    if (endptr == line || *endptr != '-') {
      continue;
    }

    uintptr_t endAddress = strtoull(endptr + 1, nullptr, 16);
    if (endAddress <= startAddress) {
      continue;
    }

    char* perm = strstr(line, "r-xp");
    if (perm == nullptr) {
      continue;
    }

    // Ignore VDSO and VVAR regions.
    if (strstr(line, "[vdso]") != nullptr ||
        strstr(line, "[vvar]") != nullptr) {
      continue;
    }

    baseAddress = startAddress;
    break;
  }

  fclose(mapsFile);

  if (baseAddress == 0) {
    fprintf(stderr, "Error: Failed to find base address of process.\n");
    exit(EXIT_FAILURE);
  }

  return baseAddress;
}

void Process::checkProcess() {
  if (processHandle == nullptr) {
    exit(EXIT_FAILURE);
  }

  struct stat st;
  if (fstat(fileno(static_cast<FILE*>(processHandle)), &st) == -1) {
    if (errno == ENOENT) {
      // The process mem file no longer exists, so the process has ended.
      exit(EXIT_FAILURE);
    }

    // Some other error occurred.
    fprintf(stderr, "Error: Failed to stat process memory file: %s\n",
            strerror(errno));
    exit(EXIT_FAILURE);
  }
}
