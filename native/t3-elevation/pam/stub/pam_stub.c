/* Link-time stand-in for libpam.so.0 so cross builds don't need a target
 * sysroot. It only gives the module its NEEDED entry; sudo's real libpam
 * provides these symbols at runtime. Never install this. */
int pam_get_item(const void *h, int t, const void **i) { return 0; }
int pam_get_data(const void *h, const char *n, const void **d) { return 0; }
int pam_set_data(void *h, const char *n, void *d, void (*c)(void *, void *, int)) { return 0; }
