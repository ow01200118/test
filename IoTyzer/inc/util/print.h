#ifndef _IOTZ_PRINT_H_
#define _IOTZ_PRINT_H_


#define RED                     "\033[0;31m"
#define GREEN                   "\033[0;32m"
#define YELLOW                  "\033[0;33m"
#define BLUE                    "\033[0;34m"
#define PUPLE                   "\033[0;35m"
#define CYAN                    "\033[0;36m"
#define BOLD_RED                "\033[1;31m"
#define BOLD_GREEN              "\033[1;32m"
#define BOLD_YELLOW             "\033[1;33m"
#define BOLD_BLUE               "\033[1;34m"
#define BOLD_PUPLE              "\033[1;35m"
#define BOLD_CYAN               "\033[1;36m"
#define WHITE                   "\033[0m"


IOTZ_VOID set_print_log_file_path(const IOTZ_CHAR* path);
IOTZ_VOID print_log(const IOTZ_CHAR* format, ...);
IOTZ_VOID print_msg(const IOTZ_CHAR* format, ...);
IOTZ_VOID print_process(const IOTZ_INT current, const IOTZ_INT total);
IOTZ_VOID print_title(const IOTZ_CHAR* format, ...);
IOTZ_VOID print_8bit_hex_msg(const IOTZ_CHAR* tag, const IOTZ_UBYTE* buf, const IOTZ_INT len);
IOTZ_VOID print_32bit_hex_msg(const IOTZ_CHAR* tag, const IOTZ_UWORD* buf, const IOTZ_INT len);
IOTZ_VOID print_64bit_hex_msg(const IOTZ_CHAR* tag, const IOTZ_UDWORD* buf, const IOTZ_INT len);
IOTZ_VOID print_return_msg(IOTZ_RETURN ret, const IOTZ_CHAR* format, ...);
IOTZ_VOID print_error_msg(const IOTZ_CHAR* format, ...);



#else

#endif
