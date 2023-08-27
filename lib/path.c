/*
Copyright (c) 2021-2023 Osamu Tatebe.  All Rights Reserved.

The authors hereby grant permission to use, copy, modify, and
distribute this software and its documentation for any purpose,
provided that existing copyright notices are retained in all copies
and that this notice is included verbatim in any distributions.  The
name of the authors may not be used to endorse or promote products
derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE AUTHORS OR DISTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, ITS
DOCUMENTATION, OR ANY DERIVATIVES THEREOF, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
*/

#include <stdlib.h>
#include <string.h>
#include <errno.h>

#define IS_SLASH_OR_NULL(c) (c == '/' || c == '\0')

static const char *
next_token(const char *p, int *s)
{
	const char *save_p = p;

	if (p[0] == '.') {
		if (IS_SLASH_OR_NULL(p[1])) {
			*s = 0;
			return (p + 1);
		}
		if (p[1] == '.' && IS_SLASH_OR_NULL(p[2])) {
			*s = -1;
			return (p + 2);
		}
	}
	while (!IS_SLASH_OR_NULL(*p))
		++p;
	*s = p - save_p;
	return (p);
}

static const char *
skip_slash(const char *p)
{
	while (*p == '/')
		++p;
	return (p);
}

#define MAX_DEPTH 50

char *
canonical_path(const char *path)
{
	struct entry {
		const char *s;
		int l;
	} d[MAX_DEPTH];
	int depth = 0, i, l;
	const char *p = path;
	char *pp;

	p = skip_slash(p);
	while (*p) {
		if (depth >= MAX_DEPTH) {
			errno = ENAMETOOLONG;
			return (NULL);
		}
		d[depth].s = p;
		p = next_token(p, &l);
		if (l > 0)
			d[depth++].l = l;
		else if (l == -1) {
			--depth;
			if (depth < 0)
				depth = 0;
		}
		p = skip_slash(p);
	}
	for (l = 0, i = 0; i < depth; ++i) {
		l += d[i].l;
		if (i < depth - 1)
			l++;
	}
	pp = malloc(l + 1);
	if (pp == NULL) {
		errno = ENOMEM;
		return (NULL);
	}
	for (l = 0, i = 0; i < depth; ++i) {
		strncpy(&pp[l], d[i].s, d[i].l);
		l += d[i].l;
		if (i < depth - 1)
			pp[l++] = '/';
	}
	pp[l] = '\0';
	return (pp);
}
