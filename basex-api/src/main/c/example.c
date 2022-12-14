/* Copyright (c) 2005-22, Alexander Holupirek <alex@holupirek.de>, BSD license */
#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/queue.h>

#include "basexdbc.h"
/* once libbasexdbc.so is installed in /usr/include/basex/ use:
#include "basex/basexdbc.h"
*/

#define DBHOST   "localhost"
#define DBPORT   "1984"
#define DBUSER   "admin"
#define DBPASSWD "admin"

/*
 * Example to demonstrate communication with running BaseX database server.
 *
 * $ cc -L. -lbasexdbc example.c -o example
 */
int
main(int argc, char *argv[])
{
	char const *host = DBHOST;
	char const *port = DBPORT;
	char const *user = DBUSER;
	char const *password = DBPASSWD;
	char const *query = NULL;
	char const *command = NULL;
	char const *context = NULL;
	struct binding {
		char const *name, *value;
		LIST_ENTRY(binding) bindings;
	};
	LIST_HEAD(bindings_head, binding);
	struct bindings_head bindings_head;
	LIST_INIT(&bindings_head);
	while (1) {
		int ch = getopt(argc, argv, "h:p:b:i:U:P:q:c:");
		switch (ch) {
			case 'h':
				host = optarg;
				continue;
				;;
			case 'p':
				port = optarg;
				continue;
				;;
			case 'U':
				user = optarg;
				continue;
				;;
			case 'P':
				password = optarg;
				continue;
				;;
			case 'q':
				query = optarg;
				continue;
				;;
			case 'c':
				command = optarg;
				continue;
				;;
			case 'i':
				context = optarg;
				continue;
				;;
			case 'b':
				{
					size_t const len = strlen(optarg);
					if (len < 3) {
						warnx("\"%s\" does't look like a binding", optarg);
						exit(1);
					}
					struct binding b;
					b.name = optarg;
					unsigned i;
					for (i = 0; i < len; ++i) 
						if ('=' == optarg[i]) {
							optarg[i] = '\0';
							b.value = optarg + i + 1;
							break;
						}
					if (i == len) {
						warnx("no = in binding? (\"%s\")", optarg);
						exit(1);
					}
					LIST_INSERT_HEAD(&bindings_head, &b, bindings);
				}
				continue;
				;;
			case -1:
				break;
				;;
			default:
				exit(1);
		}
		break;
	}
	int sfd, rc;

	/* Connect to server and receive socket descriptor for this session. */
	sfd = basex_connect(host, port);
	if (sfd == -1) {
		warnx("Can not connect to BaseX server.");
		return 0;
	}

	/* We are connected, let's authenticate for this session. */
	rc = basex_authenticate(sfd, user, password);
	if (rc == -1) {
		warnx("Access to DB denied.");
		goto out;
	}

	if (NULL != command) {
		/* Send command in default mode and receive the result string. */
		char *result;
		char *info;
		rc = basex_execute(sfd, command, &result, &info);
		if (rc == -1) { // general (i/o or the like) error
			warnx("An error occurred during execution of '%s'.", command);
			goto free_and_out;		
		}
		if (rc == 1) { // database error while processing command
			warnx("Processing of '%s' failed.", command);
		}

		/* print command, result and info/error */
		printf("command: '%s'\n", command);
		printf("result : '%s'\n", result);
		printf("%s : '%s'\n", (rc == 1) ? "error" : "info", info);

		free_and_out:
			free(result);
			free(info);
	}

	if (NULL != query) {
		char *qid = NULL, code = 0, *message = NULL;
		int rc = basex_query(sfd, query, &qid, &code, &message);
		if (-1 == rc) {
			warnx("error preparing query \"%s\"", query);
			goto out;
		}
		if (0 == code) {
			struct binding *b;
			LIST_FOREACH(b, &bindings_head, bindings) {
				rc = basex_query_bind(sfd, qid, b->name, b->value, "", &code, &message);
				if (-1 == rc) {
					warnx("error binding \"%s\"=\"%s\"", b->name, b->value);
					goto out;
				}
				else {
					if (0 != code) {
						warnx("server returned code %d ((binding \"%s\"=\"%s\")", code, b->name, b->value);
						if (NULL != message) {
							warnx("server message: \"%s\"", message);
							free(message);
						}
						goto query_end;
					}
				}
			};
			if (NULL != context) {
				rc = basex_query_context(sfd, qid, context, "", &code, &message);
				if (-1 == rc) {
					warnx("error binding context");
					goto query_end;
				}
				if (0 != code) {
					warnx("server returned code %d (binding context \"%s\")", code, context);
					if (NULL != message) {
						warnx("server message: %s", message);
						free(message);
					}
					goto query_end;
				}
			}
		}
		else {
			warnx("server returned code %d", (int)code);
			if (NULL != message) {
				warnx("server message: \"%s\"", message);
				free(message);
				goto query_end;
			}
		}
		rc = basex_query_results(sfd, qid);
		if (-1 == rc) {
			warnx("error requesting query results");
			goto query_end;
		}
		while (1) {
			size_t size = 0;
			char type = 0;
			char *value = NULL;
			rc = basex_query_more(sfd, &type, &value, &size, &code, &message);
			if (-1 == rc) {
				warnx("error fetching query result");
				goto query_end;
			}
			if (0 == type) {
				if (0 != code) {
					warnx("server returned code %d while fetching query result", code);
					if (NULL != message) {
						warnx("server message: %s", message);
						free(message);
					}
				}
				break;
			}
			fprintf(stderr, "type: 0x%02x\n", type);
			printf("%s\n", value);
			free(value);
		}
		query_end:
			if (NULL != qid) {
				code = 0;
				message = NULL;
				rc = basex_query_close(sfd, qid, &code, &message);
				if (-1 == rc) {
					warnx("error closing query");
					goto out;
				}
				else {
					if (0 != code) {
						warnx("server returned code %d", code);
						if (NULL != message) {
							warnx("server message: \"%s\"", message);
							free(message);
						}
							goto out;
					}
				}
			}
	}
out:
	basex_close(sfd);
	return 0;
}
