/*
 * Copyright (c) 2018 LIU Yu
 *
 * This PAM module can set up seccomp syscall filter for a session.
 */

#define _DEFAULT_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>

#include <sys/prctl.h>
#include <linux/seccomp.h>

#define PAM_SM_SESSION

#include <security/pam_modules.h>
#include <security/pam_ext.h>

#include "kafel.h"

typedef struct options_t {
	int debug;
	const char* policy;
} options_t;

static void parse_options(const pam_handle_t *pamh,
		int argc,
		const char **argv, 
		options_t *options)
{
	if (argv == NULL || argv[0] == '\0') {
		return;
	}

	for ( ; argc-- > 0; argv++) {
		if (strcasecmp(*argv, "debug") == 0)
			options->debug = 1;
		else if (strncasecmp(*argv, "policy=", 7) == 0)
			options->policy = *argv + 7;
		else
			pam_syslog(pamh, LOG_ERR, "Unknown option: `%s'", *argv);
	}
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh,
		int flags,
		int argc,
		const char **argv)
{
	FILE* fp = NULL;
	struct sock_fprog prog;
	kafel_ctxt_t ctxt = kafel_ctxt_create();
	options_t options = {0, NULL};

	parse_options(pamh, argc, argv, &options);
	if (!options.policy) {
		return PAM_SUCCESS;
	}

	/* open and compile policy file */
	fp = fopen(options.policy, "r");
	if (!fp) {
		pam_syslog(pamh, LOG_ERR, "Could not open policy %s: %s",
				options.policy,
				strerror(errno));
		return PAM_SESSION_ERR;
	}

	kafel_set_input_file(ctxt, fp);

	if (kafel_compile(ctxt, &prog)) {
		pam_syslog(pamh, LOG_ERR, "Could not compile policy: %s",
				kafel_error_msg(ctxt));
		kafel_ctxt_destroy(&ctxt);
		fclose(fp);
		return PAM_SESSION_ERR;
	}
	kafel_ctxt_destroy(&ctxt);
	fclose(fp);

	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
	if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0)) {
		pam_syslog(pamh, LOG_ERR, "Could not load policy: %s",
				strerror(errno));
		return PAM_SESSION_ERR;
	}

	free(prog.filter);

	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh,
		int flags,
		int argc,
		const char **argv)
{
	return PAM_SUCCESS;
}

