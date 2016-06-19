#include "cups/cups.h"

char *cupsPassword;

char const *passwordCallback(char const *prompt) {
    return cupsPassword;
}

int streamPrint(char *server, char *username, char *password,
                char *printerName, char *title, char *buffer,
                size_t bufferSize) {
    cupsSetServer(server);
    cupsSetUser(username);
    cupsPassword = password;
    cupsSetPasswordCB(passwordCallback);

    cups_dest_t *dests;
    int numDests = cupsGetDests(&dests);
    if (numDests == 0) {
        return -1;
    }
    cups_dest_t *dest = cupsGetDest(printerName, NULL, numDests, dests);
    if (dest == NULL) {
        return -1;
    }

    if (title == NULL) {
        title = "title";
    }
    int jobId = cupsCreateJob(CUPS_HTTP_DEFAULT, dest->name, title, 0, NULL);
    if (jobId == 0) {
        int errorCode = cupsLastError();
        char const *errorMsg = cupsLastErrorString();
        return -1;
    }
    cupsStartDocument(CUPS_HTTP_DEFAULT, dest->name, jobId, title, CUPS_FORMAT_RAW, 1);
    cupsWriteRequestData(CUPS_HTTP_DEFAULT, buffer, bufferSize);
    cupsFinishDocument(CUPS_HTTP_DEFAULT, dest->name);
    cupsFreeDests(numDests, dests);
    return jobId;
}
