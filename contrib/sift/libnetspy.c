/*
 * libnetspy.c — the git-sift Layer 2 network guard.
 *
 * LD_PRELOAD this into the test process and every outbound connection
 * attempt (connect(2) and getaddrinfo(3) name resolution) is BLOCKED and
 * logged.  Rationale: tests must not phone home.  A slop contribution that
 * quietly curls the internet during its own test run is doing something it
 * should not be doing — and this guard turns that into a scorecard line
 * with evidence, instead of a silent breach.
 *
 * Build:  cc -shared -fPIC -o libnetspy.so libnetspy.c -ldl
 * Use:    LD_PRELOAD=$PWD/libnetspy.so SIFT_NETGUARD_LOG=/tmp/net.log \
 *             python3 -m pytest
 *
 * What gets logged (one line per blocked attempt):
 *     "connect blocked: 1.2.3.4:443 (caller: python3)"
 *     "dns blocked: example.com (caller: python3)"
 *
 * Loopback (127.x / ::1) and AF_UNIX sockets are allowed so local test
 * servers still work.  Everything else is refused.
 *
 * This is deliberately *zero privilege*: no namespaces, no seccomp, no
 * root — which is exactly why it runs on any contributor/maintainer
 * machine without setup.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

typedef int (*connect_fn)(int, const struct sockaddr *, socklen_t);
typedef int (*getaddrinfo_fn)(const char *, const char *,
			      const struct addrinfo *, struct addrinfo **);

static void log_block(const char *kind, const char *detail)
{
	FILE *f;
	const char *path = getenv("SIFT_NETGUARD_LOG");
	char proc[256] = "?";
	FILE *comm;
	if (!path)
		path = "/tmp/git-sift-netguard.log";

	comm = fopen("/proc/self/comm", "r");
	if (comm) {
		if (fgets(proc, sizeof(proc), comm))
			proc[strcspn(proc, "\n")] = '\0';
		fclose(comm);
	}

	f = fopen(path, "a");
	if (f) {
		fprintf(f, "%s blocked: %s (caller: %s)\n", kind, detail, proc);
		fclose(f);
	}
	/* also warn on stderr so the test author sees it immediately */
	fprintf(stderr, "[git-sift netguard] %s blocked: %s (caller: %s)\n",
		kind, detail, proc);
}

static int sockaddr_is_loopback(const struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)sa;
		return (ntohl(sin->sin_addr.s_addr) >> 24) == 127;
	}
	if (sa->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)sa;
		return IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr);
	}
	return 0;
}

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen)
{
	static connect_fn real_connect = NULL;
	char host[INET6_ADDRSTRLEN] = "?";
	char detail[512];

	if (!real_connect)
		real_connect = (connect_fn)dlsym(RTLD_NEXT, "connect");

	/* unix sockets & loopback are fine */
	if (!addr || addr->sa_family == AF_UNIX || sockaddr_is_loopback(addr))
		return real_connect(sockfd, addr, addrlen);

	if (addr->sa_family == AF_INET) {
		const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
		inet_ntop(AF_INET, &sin->sin_addr, host, sizeof(host));
		snprintf(detail, sizeof(detail), "%s:%d", host, ntohs(sin->sin_port));
	} else if (addr->sa_family == AF_INET6) {
		const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
		inet_ntop(AF_INET6, &sin6->sin6_addr, host, sizeof(host));
		snprintf(detail, sizeof(detail), "[%s]:%d", host, ntohs(sin6->sin6_port));
	} else {
		snprintf(detail, sizeof(detail), "family %d", addr->sa_family);
	}

	log_block("connect", detail);
	errno = EPERM;
	return -1;
}

int getaddrinfo(const char *node, const char *service,
		const struct addrinfo *hints, struct addrinfo **res)
{
	static getaddrinfo_fn real_gai = NULL;

	if (!real_gai)
		real_gai = (getaddrinfo_fn)dlsym(RTLD_NEXT, "getaddrinfo");

	/* allow localhost resolution; block name lookups of anything else */
	if (node && strcmp(node, "localhost") && strcmp(node, "127.0.0.1") &&
	    strcmp(node, "::1")) {
		char detail[512];
		snprintf(detail, sizeof(detail), "%s", node);
		log_block("dns", detail);
		return EAI_NONAME;
	}
	return real_gai(node, service, hints, res);
}
