/**
 * basexdbc.h : communicate with BaseX database server
 *
 * Copyright (c) 2005-22, Alexander Holupirek <alex@holupirek.de>, BSD license
 */

#include "sys/types.h"

#ifdef __cplusplus
extern "C" {
#endif
/* Connect to BaseX server and open session. Returns socket file descriptor. */
int basex_connect(const char *host, const char *port);

/* Authenticate for this session (passing socket desc, db user, and passwd). */
int basex_authenticate(int sfd, const char *user, const char *passwd);

/*  Send database command to server.
 *  Expect result and info to be filled (must be free(3)'ed afterwards).
 *
 *  int | result | info  |
 * -----+--------+-------|
 *  -1  |  NULL  | NULL  | general error (i/o and the like)
 *   0  | result | info  | database command has been processed successfully
 *  >0  |  NULL  | error | database command processing failed
 *
 * BaseX commands: https://docs.basex.org/wiki/Commands
 */
int basex_execute(int sfd, const char *command, char **result, char **info);

/* Close session with descriptor sfd. */
void basex_close(int sfd);

int	basex_query(int const, char const * const, char ** const, char * const, char ** const);
int	basex_query_results(int const, char const * const);
int	basex_query_more(int const, char * const, char ** const, size_t * const, char * const, char ** const);
int	basex_query_execute(int const, char const * const, char **const, char * const, char **const);
int	basex_query_close(int const, char const * const, char * const, char ** const);
int	basex_query_bind(int const, char const * const, char const * const, char const * const, char const * const, char * const, char ** const);
int	basex_query_context(int const, char const * const, char const * const, char const * const, char * const, char ** const);

#ifdef __cplusplus
}
#endif
