#include <stdio.h>

main(argc, argv)
int     argc;
char  **argv;
{
#ifdef LOGIN_ACCESS
    if (argc != 3) {
	fprintf(stderr, "usage: %s user from\n", argv[0]);
	exit(1);
    }
    printf (login_access(argv[1], argv[2]) ? "Yes\n" : "No\n");
#else
    fprintf(stderr, "Login access control not enabled\n");
#endif
}
