#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include "log.h"

static struct {
	char *name;
	int val;
} priority_names[] = {
    {"emerg", LOG_EMERG},     /* system in unusable */
    {"alert", LOG_ALERT},     /* action must be taken immediately */
    {"crit", LOG_CRIT},	      /* critical conditions */
    {"err", LOG_ERR},	      /* error conditions */
    {"warning", LOG_WARNING}, /* warning conditions */
    {"notice", LOG_NOTICE},   /* normal but significant condition */
    {"info", LOG_INFO},	      /* informational */
    {"debug", LOG_DEBUG},     /* debug-level messages */
    {NULL, -1}};

static int log_prio = LOG_INFO;

static void
log_time(char *s, int size)
{
	struct timespec ts;
	struct tm *tm;
	size_t s0, s1;

	clock_gettime(CLOCK_REALTIME, &ts);
	tm = localtime(&ts.tv_sec);
	s0 = strftime(s, size, "%Y-%m-%d %H:%M:%S", tm);
	s1 = snprintf(s + s0, size - s0, ".%09ld ", ts.tv_nsec);
	strftime(s + s0 + s1, size - s0 - s1, "%z", tm);
}

char *
log_name_from_priority(int priority)
{
	if (priority < 0 || priority > LOG_DEBUG)
		return ("unknown");
	if (priority_names[priority].val == priority)
		return (priority_names[priority].name);
	return ("unknown");
}

#define TIMEBUF_SIZE 256

void
log_vmessage(int priority, const char *format, va_list ap)
{
	if (priority > log_prio)
		return;
	char buffer[2048];
	char tb[TIMEBUF_SIZE];

	log_time(tb, TIMEBUF_SIZE);

	vsnprintf(buffer, sizeof buffer, format, ap);
	fprintf(stderr, "%s: <%s> %s\n", tb, log_name_from_priority(priority),
		buffer);
}

void
log_error(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	log_vmessage(LOG_ERR, format, ap);
	va_end(ap);
}

void
log_warning(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	log_vmessage(LOG_WARNING, format, ap);
	va_end(ap);
}

void
log_info(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	log_vmessage(LOG_INFO, format, ap);
	va_end(ap);
}

void
log_debug(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	log_vmessage(LOG_DEBUG, format, ap);
	va_end(ap);
}

void
log_fatal(const char *format, ...)
{
	va_list ap;

	va_start(ap, format);
	log_vmessage(LOG_ERR, format, ap);
	va_end(ap);
	exit(2);
}

void
log_set_level(const char *level)
{
	for (int i = 0; i <= LOG_DEBUG; ++i) {
		if (strcmp(priority_names[i].name, level) == 0) {
			log_prio = priority_names[i].val;
			return;
		}
	}
}

int
get_log_priority(void)
{
	return log_prio;
}
