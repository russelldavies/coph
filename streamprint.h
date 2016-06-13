#ifndef STREAMPRINT__H
#define STREAMPRINT__H

#include <stddef.h>

int streamPrint(char *server, char *username, char *password, char *printerName,
                char *title, char *buffer, size_t bufferSize);
#endif
