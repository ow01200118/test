#ifdef _MSC_VER
#include <Windows.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>

#include <IoTyzer/define.h>
#include <IoTyzer/return.h>

#include <util/print.h>


#define TITLE1_COLOR            BOLD_BLUE
#define TITLE2_COLOR            BOLD_CYAN
#define LABEL_COLOR             YELLOW
#define LOG_COLOR               CYAN
#define RETURN_COLOR            RED
#define OK_COLOR                BOLD_GREEN
#define FAIL_COLOR              BOLD_RED
#define CLEAR                   WHITE

#define GUIDE_STR               "********************************************************************************"
#define BLANK_STR               "                                                                                "
#define DOT_STR                 "................................................................................"
#define BAR_STR                 ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
#define PRINT_BANDWIDTH         80
#define PRINT_BYTE_BANDWIDTH    32


static IOTZ_CHAR LOG_FILE[FILE_NAME_SIZE] = "";


IOTZ_VOID set_print_log_file_path(const IOTZ_CHAR* path)
{
#ifdef _MSC_VER
    HANDLE stdoutHandle;
    DWORD outMode;

    stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);

    if (stdoutHandle != INVALID_HANDLE_VALUE)
    {
        if (GetConsoleMode(stdoutHandle, &outMode))
        {
            outMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;

            SetConsoleMode(stdoutHandle, outMode);
        }
    }

#endif

    if ((path != NULL) && (strlen(path) > 0))
    {
#ifdef _MSC_VER
        strncpy_s(LOG_FILE, FILE_NAME_SIZE, path, strlen(path));
#else
        strncpy(LOG_FILE, path, strlen(path));
#endif
    }

}

IOTZ_VOID print_file(const IOTZ_CHAR* format, ...)
{
    IOTZ_CHAR str[BUF_SIZE] = "";
    va_list arg;
    IOTZ_FILE* fp = NULL;
    time_t cur_time;
#ifdef _MSC_VER
    struct tm cur_tm;
#else
    struct tm* cur_tm;
#endif

    cur_time = time(NULL);
#ifdef _MSC_VER
    localtime_s(&cur_tm, &cur_time);
#else
    cur_tm = localtime(&cur_time);
#endif

#ifdef _MSC_VER
    sprintf_s(str, BUF_SIZE, "%s_%04d%02d%02d.log", LOG_FILE,
        cur_tm.tm_year + 1900, cur_tm.tm_mon + 1, cur_tm.tm_mday);
    fopen_s(&fp, str, "a");
#else
    sprintf(str, "%s_%04d%02d%02d.log", LOG_FILE,
        cur_tm->tm_year + 1900, cur_tm->tm_mon + 1, cur_tm->tm_mday);
    fp = fopen(str, "a");
#endif

    if (fp == NULL)
        fp = stdout;

    va_start(arg, format);
#ifdef _MSC_VER
    vsprintf_s(str, BUF_SIZE, format, arg);
#else
    vsprintf(str, format, arg);
#endif
    va_end(arg);

#ifdef _MSC_VER
    fprintf(fp, "[%4d-%02d-%02d %02d:%02d:%02d] %s\n",
        cur_tm.tm_year + 1900, cur_tm.tm_mon + 1, cur_tm.tm_mday,
        cur_tm.tm_hour, cur_tm.tm_min, cur_tm.tm_sec,
        str);
#else
    fprintf(fp, "[%4d-%02d-%02d %02d:%02d:%02d] %s\n",
        cur_tm->tm_year + 1900, cur_tm->tm_mon + 1, cur_tm->tm_mday,
        cur_tm->tm_hour, cur_tm->tm_min, cur_tm->tm_sec,
        str);
#endif

    if (fp != NULL)
        fclose(fp);
}

IOTZ_VOID print_log(const IOTZ_CHAR* format, ...)
{
    IOTZ_CHAR str[BUF_SIZE] = "";
    va_list arg;

    va_start(arg, format);
#ifdef _MSC_VER
    vsprintf_s(str, BUF_SIZE, format, arg);
#else
    vsprintf(str, format, arg);
#endif
    va_end(arg);

    print_file("%s", str);
}

IOTZ_VOID print_msg(const IOTZ_CHAR* format, ...)
{
    IOTZ_CHAR str[BUF_SIZE] = "";
    va_list arg;

    va_start(arg, format);
#ifdef _MSC_VER
    vsprintf_s(str, BUF_SIZE, format, arg);
#else
    vsprintf(str, format, arg);
#endif
    va_end(arg);

    print_file("%s", str);
    printf("%s\n", str);
}

IOTZ_VOID print_process(const IOTZ_INT current, const IOTZ_INT total)
{
    IOTZ_INT barLen = 0;
    IOTZ_INT nDot = 0, nBlank = 0;
    IOTZ_DOUBLE percent = 0.0;

    percent = (IOTZ_DOUBLE)current * 100 / (IOTZ_DOUBLE)total;

    barLen = PRINT_BANDWIDTH - (IOTZ_INT)strlen("    Processing [] 100.00% done");

    nDot = (IOTZ_INT)(barLen * (percent / 100));
    nBlank = barLen - nDot;

    printf("    Processing [");
    printf("%.*s%.*s", nDot, BAR_STR, nBlank, BLANK_STR);
    printf("] %.2lf%%", percent);

    if (current == total)
        printf(" done\n");
    else
        printf("\r");

    fflush(stdout);
}

IOTZ_VOID print_title(const IOTZ_CHAR* format, ...)
{
    IOTZ_CHAR str[BUF_SIZE] = "";
    va_list arg;

    va_start(arg, format);
#ifdef _MSC_VER
    vsprintf_s(str, BUF_SIZE, format, arg);
#else
    vsprintf(str, format, arg);
#endif
    va_end(arg);

    print_file("%s", GUIDE_STR);
    print_file("****%.*s""%s%.*s""****",
        (IOTZ_INT)((PRINT_BANDWIDTH - strlen("********") - strlen(str)) / 2), BLANK_STR,
        str, strlen(str) & 1 ? (IOTZ_INT)((PRINT_BANDWIDTH - strlen("********") - strlen(str) + 1) / 2) :
        (IOTZ_INT)((PRINT_BANDWIDTH - strlen("********") - strlen(str)) / 2), BLANK_STR);
    print_file("%s", GUIDE_STR);

    printf(TITLE1_COLOR"%s\n"CLEAR, GUIDE_STR);
    printf(TITLE1_COLOR"****"CLEAR"%.*s"TITLE2_COLOR"%s"CLEAR"%.*s"TITLE1_COLOR"****\n"CLEAR,
        (IOTZ_INT)((PRINT_BANDWIDTH - strlen("********") - strlen(str)) / 2), BLANK_STR,
        str, strlen(str) & 1 ? (IOTZ_INT)((PRINT_BANDWIDTH - strlen("********") - strlen(str) + 1) / 2) :
        (IOTZ_INT)((PRINT_BANDWIDTH - strlen("********") - strlen(str)) / 2), BLANK_STR);
    printf(TITLE1_COLOR"%s\n\n"CLEAR, GUIDE_STR);
}

IOTZ_VOID print_8bit_hex_msg(const IOTZ_CHAR* tag, const IOTZ_UBYTE* buf, const IOTZ_INT byteLen)
{
    IOTZ_CHAR str[BUF_SIZE] = "";
    IOTZ_INT len = byteLen / sizeof(IOTZ_UBYTE);
    IOTZ_INT unit = PRINT_BYTE_BANDWIDTH / sizeof(IOTZ_UBYTE);
    IOTZ_INT col = len % unit;
    IOTZ_INT row = len / unit;
    IOTZ_INT i, j;

    print_file("%s [%d]", tag, len);

    for (i = 0; i < row; i++)
    {
        memset(str, 0x00, BUF_SIZE);

        for (j = 0; j < unit; j++)
#ifdef _MSC_VER
            sprintf_s(str, BUF_SIZE, "%s %02X", str, buf[(i * unit) + j]);
#else
            sprintf(str, "%s %02X", str, buf[(i * unit) + j]);
#endif

        print_file("%s", str);
    }

    if (col)
    {
        memset(str, 0x00, BUF_SIZE);

        for (j = 0; j < col; j++)
#ifdef _MSC_VER
            sprintf_s(str, BUF_SIZE, "%s %02X", str, buf[(i * unit) + j]);
#else
            sprintf(str, "%s %02X", str, buf[(i * unit) + j]);
#endif

        print_file("%s", str);
    }
}

IOTZ_VOID print_32bit_hex_msg(const IOTZ_CHAR* tag, const IOTZ_UWORD* buf, const IOTZ_INT byteLen)
{
    IOTZ_CHAR str[BUF_SIZE] = "";
    IOTZ_INT len = (byteLen + 3) / sizeof(IOTZ_UWORD);
    IOTZ_INT unit = PRINT_BYTE_BANDWIDTH / sizeof(IOTZ_UWORD);
    IOTZ_INT col = len % unit;
    IOTZ_INT row = len / unit;
    IOTZ_INT i, j;

    print_file("%s [%d]", tag, len);

    for (i = 0; i < row; i++)
    {
        memset(str, 0x00, BUF_SIZE);

        for (j = 0; j < unit; j++)
#ifdef _MSC_VER
            sprintf_s(str, BUF_SIZE, "%s %08X", str, buf[(i * unit) + j]);
#else
            sprintf(str, "%s %08X", str, buf[(i * unit) + j]);
#endif

        print_file("%s", str);
    }

    if (col)
    {
        memset(str, 0x00, BUF_SIZE);

        for (j = 0; j < col; j++)
#ifdef _MSC_VER
            sprintf_s(str, BUF_SIZE, "%s %08X", str, buf[(i * unit) + j]);
#else
            sprintf(str, "%s %08X", str, buf[(i * unit) + j]);
#endif

        print_file("%s", str);
    }
}

IOTZ_VOID print_64bit_hex_msg(const IOTZ_CHAR* tag, const IOTZ_UDWORD* buf, const IOTZ_INT byteLen)
{
    IOTZ_CHAR str[BUF_SIZE] = "";
    IOTZ_INT len = (byteLen + 7) / sizeof(IOTZ_UDWORD);
    IOTZ_INT unit = PRINT_BYTE_BANDWIDTH / sizeof(IOTZ_UDWORD);
    IOTZ_INT col = len % unit;
    IOTZ_INT row = len / unit;
    IOTZ_INT i, j;

    print_file("%s [%d]", tag, len);

    for (i = 0; i < row; i++)
    {
        memset(str, 0x00, BUF_SIZE);

        for (j = 0; j < unit; j++)
#ifdef _MSC_VER
            sprintf_s(str, BUF_SIZE, "%s %016llX", str, buf[(i * unit) + j]);
#else
            sprintf(str, "%s %016lX", str, buf[(i * unit) + j]);
#endif

        print_file("%s", str);
    }

    if (col)
    {
        memset(str, 0x00, BUF_SIZE);

        for (j = 0; j < col; j++)
#ifdef _MSC_VER
            sprintf_s(str, BUF_SIZE, "%s %016llX", str, buf[(i * unit) + j]);
#else
            sprintf(str, "%s %016lX", str, buf[(i * unit) + j]);
#endif

        print_file("%s", str);
    }
}

IOTZ_VOID print_return_msg(IOTZ_RETURN ret, const IOTZ_CHAR* format, ...)
{
    IOTZ_CHAR str[BUF_SIZE] = "";
    va_list arg;

    va_start(arg, format);
#ifdef _MSC_VER
    vsprintf_s(str, BUF_SIZE, format, arg);
#else
    vsprintf(str, format, arg);
#endif
    va_end(arg);

    if (ret != 0)
    {
        print_file("%s [0x%08X] %.*s [Fail]",
            str, ret,
            (IOTZ_INT)(PRINT_BANDWIDTH - strlen(str) - strlen(" [0x]  [Fail]") - (sizeof(IOTZ_RETURN) * 2)), DOT_STR);

        printf("%s ["RETURN_COLOR"0x%08X"CLEAR"] %.*s [" FAIL_COLOR "Fail" CLEAR "]\n",
            str, ret,
            (IOTZ_INT)(PRINT_BANDWIDTH - strlen(str) - strlen(" [0x]  [Fail]") - (sizeof(IOTZ_RETURN) * 2)), DOT_STR);
    }
    else
    {
        print_file("%s %.*s [OK]",
            str, (IOTZ_INT)(PRINT_BANDWIDTH - strlen(str) - strlen("  [OK]")), DOT_STR);

        printf("%s %.*s [" OK_COLOR "OK" CLEAR "]\n",
            str, (IOTZ_INT)(PRINT_BANDWIDTH - strlen(str) - strlen("  [OK]")), DOT_STR);
    }
}

IOTZ_VOID print_error_msg(const IOTZ_CHAR* format, ...)
{
    IOTZ_CHAR str[BUF_SIZE] = "";
#ifdef _MSC_VER
    IOTZ_CHAR emsg[BUF_SIZE];
#endif
    va_list arg;

    va_start(arg, format);
#ifdef _MSC_VER
    vsprintf_s(str, BUF_SIZE, format, arg);
#else
    vsprintf(str, format, arg);
#endif
    va_end(arg);

#ifdef _MSC_VER
    strerror_s(emsg, BUF_SIZE, errno);
    print_file("%s %.*s [%s]",
        str, (IOTZ_INT)(PRINT_BANDWIDTH - strlen(str) - strlen(emsg) - strlen("  []")),
        DOT_STR, emsg);

    printf(LOG_COLOR"%s"CLEAR" %.*s [" FAIL_COLOR "%s" CLEAR "]\n",
        str, (IOTZ_INT)(PRINT_BANDWIDTH - strlen(str) - strlen(emsg) - strlen("  []")),
        DOT_STR, emsg);
#else
    print_file("%s %.*s [%s]",
        str, (IOTZ_INT)(PRINT_BANDWIDTH - strlen(str) - strlen(strerror(errno)) - strlen("  []")),
        DOT_STR, strerror(errno));

    printf(LOG_COLOR"%s"CLEAR" %.*s [" FAIL_COLOR "%s" CLEAR "]\n",
        str, (IOTZ_INT)(PRINT_BANDWIDTH - strlen(str) - strlen(strerror(errno)) - strlen("  []")),
        DOT_STR, strerror(errno));
#endif
}

IOTZ_VOID print_status()
{
}
