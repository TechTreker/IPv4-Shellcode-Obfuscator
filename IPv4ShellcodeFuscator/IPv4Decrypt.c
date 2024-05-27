#include <windows.h>
#include <stdio.h>

char* ipArray[] = { // Shellcode for calc.exe
    "252.72.131.228", "240.232.192.0", "0.0.65.81", "65.80.82.81", "86.72.49.210",
    "101.72.139.82", "96.72.139.82", "24.72.139.82", "32.72.139.114", "80.72.15.183",
    "74.74.77.49", "201.72.49.192", "172.60.97.124", "2.44.32.65", "193.201.13.65",
    "1.193.226.237", "82.65.81.72", "139.82.32.139", "66.60.72.1", "208.139.128.136",
    "0.0.0.72", "133.192.116.103", "72.1.208.80", "139.72.24.68", "139.64.32.73",
    "1.208.227.86", "72.255.201.65", "139.52.136.72", "1.214.77.49", "201.72.49.192",
    "172.65.193.201", "13.65.1.193", "56.224.117.241", "76.3.76.36", "8.69.57.209",
    "117.216.88.68", "139.64.36.73", "1.208.102.65", "139.12.72.68", "139.64.28.73",
    "1.208.65.139", "4.136.72.1", "208.65.88.65", "88.94.89.90", "65.88.65.89",
    "65.90.72.131", "236.32.65.82", "255.224.88.65", "89.90.72.139", "18.233.87.255",
    "255.255.93.72", "186.1.0.0", "0.0.0.0", "0.72.141.141", "1.1.0.0",
    "65.186.49.139", "111.135.255.213", "187.240.181.162", "86.65.186.166", "149.189.157.255",
    "213.72.131.196", "40.60.6.124", "10.128.251.224", "117.5.187.71", "19.114.111.106",
    "0.89.65.137", "218.255.213.99", "97.108.99.46", "101.120.101.0"
};

PBYTE deobfuscate(const char * IpString) {
  char * duplicate = strdup(IpString);
  char * token = strtok(duplicate, ".");
  int index = 0;
  BYTE * output = malloc(4);

  while (token != NULL && index < 4) {
    output[index] = (BYTE) atoi(token);
    token = strtok(NULL, ".");
    index++;
  };

  free(duplicate);
  return output;
};

PBYTE deobfuscateShellcode(char ** iIpArray, SIZE_T iIpArraySize) {
  if (iIpArray == NULL || iIpArraySize == 0) {
    printf("No IP addresses provided");
    return FALSE;
  }

  PBYTE shellcode;
  PBYTE pBuffer = NULL;
  SIZE_T sBuffSize = 0;

  sBuffSize = iIpArraySize * 4;
  pBuffer = (PBYTE) HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sBuffSize);
  if (pBuffer == NULL) {
    printf("Failed to allocate memory to the size of the shellcode.");
    return FALSE;
  };

  PBYTE currentIndex = pBuffer;

  for (int i = 0; i < iIpArraySize; i++) {
    shellcode = deobfuscate(iIpArray[i]);
    if (!shellcode) {
      printf("Failed to deobfuscate IP: %s\n", iIpArray[i]);
      HeapFree(GetProcessHeap(), 0, pBuffer);
      return FALSE;
    };

    memcpy(currentIndex, shellcode, 4);
    currentIndex += 4;
    free(shellcode);
  };

  return pBuffer;
};

int main() {
  int ipArraySize = sizeof(ipArray) / sizeof(ipArray[0]);
  PBYTE shellcodeBuffer = deobfuscateShellcode(ipArray, ipArraySize);

  printf("\nShellcode Array:\n\n");

  if (shellcodeBuffer == NULL) {
    printf("Failed to deobfuscate IP addresses into shellcode.\n");
  }
  
  int bytesPerLine = 16;
  for (int i = 0; i < ipArraySize * 4; i++) {
    printf("%02x ", shellcodeBuffer[i]);

    if ((i + 1) % bytesPerLine == 0) {
      printf("\n");
    };
  };

  if (shellcodeBuffer) {
    HeapFree(GetProcessHeap(), 0, shellcodeBuffer);
  };

  return 0;
}
