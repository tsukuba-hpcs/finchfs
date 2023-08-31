void log_error(const char *, ...);
void log_warning(const char *, ...);
void log_info(const char *, ...);
void log_debug(const char *, ...);

void log_fatal(const char *, ...);

void log_set_level(const char *);

int get_log_priority(void);
