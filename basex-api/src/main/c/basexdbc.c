/**
 * basexdbc.c : communicate with BaseX database server
 * Works with BaseX 7.x and with BaseX 8.0 and later
 *
 * Copyright (c) 2005-22, Alexander Holupirek <alex@holupirek.de>, BSD license
 *
 * Significant Changes:
 * 11 Dec 2016 - Craig Phillips <github.com/smallfriex> - to support newer authentication
 *
 */
#include <assert.h>
#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/uio.h>

#include "basexdbc.h"
#include "md5.h"
#include "readstring.h"

static int send_db(int sfd, const char *buf, size_t buf_len);
static int basex_status(int sfd);

/**
 * Connect to host on port using stream sockets.
 *
 * @param host string representing host to connect to
 * @param port string representing port on host to connect to
 * @return socket file descriptor or -1 in case of failure
 */
int
basex_connect(const char *host, const char *port)
{
	struct addrinfo hints;
	struct addrinfo *result = NULL, *rp;
	int sfd, rc;

	if (host == NULL || port == NULL) {
#if DEBUG
		warnx("Missing hostname '%s' / port '%s'.", host, port);
#endif
		return -1;
	}

	/* Obtain address(es) matching host/port */
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family   = AF_UNSPEC;       /* Allows IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM;     /* TCP socket */
	hints.ai_flags    = AI_NUMERICSERV;

	rc = getaddrinfo(host, port, &hints, &result);
	if (rc != 0) {
#if DEBUG
		warnx("getaddrinfo: %s", gai_strerror(rc));
#endif
		return -1;
	}

	/* getaddrinfo() returns a list of address structures.
	 * Try each address until we successfully connect(2).
	 * If socket(2) (or connect(2)) fails, we (close the
	 * socket and) try the next address. */
	for (rp = result; rp != NULL; rp = rp->ai_next) {
		sfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
		if (sfd == -1)
			continue; /* On error, try next address */

		if (connect(sfd, rp->ai_addr, rp->ai_addrlen) != -1)
			break;	/* Success */
		
		close(sfd); /* Connect failed: close socket, try next address */
	}

	if (rp == NULL) {	/* No address succeeded */
		warnx("Can not connect to BaseX server.");
		warnx("Hostname '%s', port %s.", host, port);
		return -1;
	}

	freeaddrinfo(result);	/* No longer needed */

	return sfd; /* This file descriptor is ready for I/O. */
}

/**
 * Authenticate against BaseX server connected on sfd using user and passwd.
 *
 * Authentication as defined by BaseX transfer protocol (BaseX 7.0 ff.):
 * https://github.com/BaseXdb/basex-api/blob/master/etc/readme.txt
 * {...} = string; \n = single byte
 *
 *   1. Client connects to server socket (basex_connect)
 *   2. Server sends timestamp: {timestamp} \0
 *   3. Client sends username and hash:
 *      {username} \0 {md5(md5(password) + timestamp)} \0
 *   4. Server sends \0 (success) or \1 (error)
 *
 * @param sfd socket file descriptor successfully connected to BaseX server
 * @param user string with database username
 * @param passwd string with password for database username
 * @return 0 in case of success, -1 in case of failure
 */
int
basex_authenticate(int sfd, const char *user, const char *passwd)
{
	char ts[BUFSIZ]; /* timestamp returned by basex. */
	char *md5_pwd;   /* md5'ed passwd */
	int ts_len, rc, i;

	/* Right after the first connect BaseX returns a nul-terminated
         * timestamp string. */
	memset(ts, 0, BUFSIZ);
	rc = read(sfd, &ts, BUFSIZ);
	if (rc == -1) {
		warnx("Reading timestamp failed.");
		return -1;
	}
	ts_len = strlen(ts);

#if DEBUG
	warnx("timestamp       : %s (%d)", ts, strlen(ts));
#endif

	/* BaseX Server expects an authentification sequence:
           {username}\0{md5(md5(user:realm:password) + timestamp)}\0 */
 	/* legacy - 
        /* {username}\0{md5(md5(password) + timestamp)}\0 */
        

	/* Send {username}\0 */
	int user_len = strlen(user) + 1;
	rc = write(sfd, user, user_len);
	if (rc == -1 || rc != user_len) {
		warnx("Sending username failed. %d != %d", rc, user_len);
		return -1;
	}
        
        char* p = strchr(ts,':');
        char* t;
        if (!p) {
            /* legacy login */
            t = ts;
            /* Compute md5 for passwd. */
            md5_pwd = md5(passwd);
            if (md5_pwd == NULL) {
                    warnx("md5 computation for password failed.");
                    return -1;
            }  
        }
        else {
            /* v8.0+ login */
            t = p + 1;
            /* Compute md5 for codeword. */
            int user_len = strlen(user);
            int pass_len = strlen(passwd);
            int realm_len = p - ts;
            char codewd[user_len + realm_len + pass_len + 3];
            strncpy(codewd, user, user_len);
            codewd[user_len] = ':';
            strncpy(codewd + user_len + 1, ts, realm_len);
            codewd[user_len + 1 + realm_len] = ':';
            strncpy(codewd + user_len + 1 + realm_len + 1, passwd, pass_len);
            codewd[user_len + 1 + realm_len + 1 + pass_len] = '\0';
            md5_pwd = md5(codewd);
            if (md5_pwd == NULL) {
                    warnx("md5 computation for password failed.");
                    return -1;
            }
            ts_len = ts_len - realm_len -1;
        }
        int md5_pwd_len = strlen(md5_pwd);
        
#if DEBUG
	warnx("md5(pwd)        : %s (%d)", md5_pwd, md5_pwd_len);
#endif
	
	/* Concat md5'ed codewd string and timestamp/nonce string. */
	int pwdts_len = md5_pwd_len + ts_len + 1;
	char pwdts[pwdts_len];
	memset(pwdts, 0, sizeof(pwdts));
	for (i = 0; i < md5_pwd_len; i++)
		pwdts[i] = md5_pwd[i];
	int j = md5_pwd_len;
	for (i = 0; i < ts_len; i++,j++)
		pwdts[j] = t[i];
	pwdts[pwdts_len - 1] = '\0';
#if DEBUG
	warnx("md5(pwd)+ts     : %s (%d)", pwdts, strlen(pwdts));
#endif

	/* Compute md5 for md5'ed codeword + timestamp */
	char *md5_pwdts = md5(pwdts);
	if (md5_pwdts == NULL) {
		warnx("md5 computation for password + timestamp failed.");
		return -1;
	}
	int md5_pwdts_len = strlen(md5_pwdts);
#if DEBUG
	warnx("md5(md5(pwd)+ts): %s (%d)", md5_pwdts, md5_pwdts_len);
#endif

	/* Send md5'ed(md5'ed codeword + timestamp) to basex. */
	rc = send_db(sfd, md5_pwdts, md5_pwdts_len + 1);  // also send '\0'
	if (rc == -1) {
		warnx("Sending credentials failed.");
		return -1;
	}

	free(md5_pwd);
	free(md5_pwdts);

	/* Retrieve authentification status. */
	rc = basex_status(sfd);
	if (rc == -1) {
		warnx("Reading authentification status failed.");
		return -1;
	}
	if (rc != 0) {
		warnx("Authentification failed");
		return -1;
	}

#if DEBUG
	warnx("Authentification succeeded.");
#endif
	return 0;
}

/**
 * Read status single byte from socket.
 */
int
basex_status(int sfd)
{
	char c;
	int b = read(sfd, &c, 1);	
	if (b == -1) {
		warnx("Can not retrieve status code.");
		return -1;
	}
	return c;
}

/**
 * Executes a command and returns a result string and an info/error string.
 *
 * A database command is sent to BaseX server connected on sfd.
 * The result is a \0 terminated, dynamically allocated string, which is placed
 * at the given result address or NULL.  The same holds for the processing
 * information stored at info.
 *
 * In either case it is the responsibility of the caller to free(3) those
 * strings.
 *
 * The returned int is 0 if the command could be processed successfully, in that
 * case the result contains the result string of the command and info holds
 * the processing information.
 * If a value >0 is returned, the command could not be processed successfully,
 * result contains NULL and info contains the database error message.
 * If -1 is interned, an error occurred, result and info are set to NULL.
 *
 *  int | result* | info* |
 * -----+---------+-------|
 *  -1  |  NULL   | NULL  |
 *   0  | result  | info  |
 *  >0  |  NULL   | error |
 *
 *  * strings shall be free(3)'ed by caller
 *
 * BaseX C/S protocol:
 *
 * client sends: {command} \0
 * server sends: {result}  \0 {info}  \0 \0
 *            or           \0 {error} \0 \1
 *
 * @param sfd socket file descriptor connected to BaseX server
 * @param command to be processed by BaseX server
 * @param result address at which result from BaseX server is placed
 * @param info address at which info/error message from BaseX server is placed
 * @return int 0 for success (result and info contain strings sent from BaseX)
 * -1 in case of failure (result and info are set to NULL), >0 an error occurred
 * while processing the command (result contains NULL, info contains error
 * message)
 */
int
basex_execute(int sfd, const char *command, char **result, char **info)
{
	int rc;

	/* Send {command}\0 to server. */
	rc = send_db(sfd, command, strlen(command) + 1);
	if (rc == -1) {
		warnx("Can not send command '%s' to server.", command);	
		goto err;
	}

	/* --- Receive from server:  {result} \0 {info}  \0 \0
	 *                                    \0 {error} \0 \1 */
	/* Receive {result} \0 */
	rc = readstring(sfd, result);
	if (rc == -1) {
		warnx("Can not retrieve result for command '%s' from server.", command);
		goto err;
	}
#if DEBUG
	warnx("[execute] result: '%s'\n", *result);
#endif

	/* Receive {info/error} \0 .*/
	rc = readstring(sfd, info);
	if (rc == -1) {
		warnx("Can not retrieve info for command '%s' from server.", *info);
		goto err;
	}
#if DEBUG
	warnx("[execute] info/error: '%s'\n", *info);
#endif

	/* Receive terminating \0 for success or \1 for error .*/
	rc = basex_status(sfd);
#if DEBUG
	warnx("[execute] status: '%d'\n", rc);
#endif
	if (rc == -1) {
		warnx("Can not retrieve status.");
		goto err;
	}
	if (rc == 1) {
		warnx("BaseX error message : %s", *info);
		free(*result);
		*result = NULL;
	}

	assert(rc == 0 || rc == 1);
	return rc;

err:
	*result = NULL;
	*info = NULL;
	return -1;
}

/**
 * Quits database session and closes stream connection to database server.
 *
 * @param socket file descriptor for database session.
 */
void
basex_close(int sfd)
{
	/* Send {exit}\0 to server. */
	int rc = send_db(sfd, "exit", 4 + 1);
	if (rc != 0)
		warnx("Can not send 'exit' command to server.");
		
	/* Close socket. */
	rc = shutdown(sfd, SHUT_RDWR);
	if (rc == -1)
		warn("Can not properly shutdown socket.");
}

/**
 * Writes buffer buf of buf_len to socket sfd.
 *
 * @param socket file descriptor for database session.
 * @param buf to be sent to server
 * @param buf_len # of bytes in buf
 * @return 0 if all data has successfully been written to server,
 *        -1 in case of failure.
 */
static int
send_db(int sfd, const char *buf, size_t buf_len)
{
	ssize_t ret;

	while (buf_len != 0 && (ret = write(sfd, buf, buf_len)) != 0) {
		if (ret == -1) {
			if (errno == EINTR)
				continue;
			warn("Can not write to server");
			return -1;
		}
#if DEBUG
		int i;
		warnx("write: \n");
		for (i = 0; i < ret; i++)
			warnx("[write] %3d : 0x%08x %4d %c", i, buf[i], buf[i], buf[i]);
#endif /* DEBUG */
		buf_len -= ret;
		buf += ret;
	}
	return 0;
}

#ifndef BASEX_BLK_READ_SIZE
#define BASEX_BLK_READ_SIZE 100
#endif

#ifndef BASEX_BLK_READ_SIZE_INCR
#define BASEX_BLK_READ_SIZE_INCR 10
#endif

#ifndef BASEX_BLK_READ_SIZE_MUL
#define BASEX_BLK_READ_SIZE_MUL 2
#endif

static ssize_t
basex_read_server_response(int const sfd, char * const code, char ** const message)
{
	char c;
	ssize_t rc = read(sfd, &c, sizeof c);
	if (-1 == rc) {
		perror("read");
		return -1;
	}
	if (0 == c)
	    return 0;
	size_t size = BASEX_BLK_READ_SIZE;
	size_t incr = BASEX_BLK_READ_SIZE_INCR;
	char *msg = malloc(size);
	if (NULL == msg)
		goto error;
	char *p = msg;
	while (1) {
		if (p - msg > size) {
			size += incr;
			char * const newmsg = realloc(msg, size);
			if (NULL == newmsg)
				goto error;
			off_t const offs = p - msg;
			msg = newmsg;
			p = msg + offs;
			incr *= BASEX_BLK_READ_SIZE_MUL;
		}
		rc = read(sfd, p, sizeof *p);
		if (-1 == rc) {
			perror("read");
			goto error;
		}
		if (0 == rc) {
			warnx("EOF");
			goto error;
		}
		if ('\0' == *p)
			break;
		++p;
	}

	*code = c;
	*message = msg;
	return p - msg;
	
	error:
	if (NULL != msg)
		free(msg);
	return -1;
}

static ssize_t
basex_read_block(int const sfd, char ** const block)
{
	size_t size = BASEX_BLK_READ_SIZE;
	size_t incr = BASEX_BLK_READ_SIZE_INCR;
	char *buf = malloc(size);
	if (NULL == buf)
		return -1;
	int esc = 0;
	char *p = buf;
	while (1) {
		if (p - buf > size) {
			size += incr;
			char * const newbuf = realloc(buf, size);
			if (NULL == newbuf)
				goto error;
			off_t const offs = p - buf;
			buf = newbuf;
			p = newbuf + offs;
			incr *= BASEX_BLK_READ_SIZE_MUL;
 		}
		ssize_t const rc = read(sfd, p, sizeof *p);
		if (-1 == rc) {
			perror("read");
			goto error;
		}
		if (0 == rc) {
			warnx("EOF");
			goto error;
		}
		if (!esc && '\xff' == *p) {
			esc = 1;
			continue;
		}
		if (esc) {
			++p;
			esc = 0;
			continue;
		}
		if ('\0' == *p)
			break;
		++p;
	}

	*block = buf;
	return p - buf;

	error:
		if (NULL != buf)
			free(buf);
		return -1;
}

int
basex_query(int const sfd, char const * const query, char ** const qid, char * const code, char ** const server_message)
{
	char const command = '\x00';
	struct iovec const message[] = {
		{
			.iov_base = (void *)&command,
			.iov_len = sizeof command
		},
		{
			.iov_base = (void *)query,
			.iov_len = strlen(query) + 1
		}
	};
	ssize_t rc = writev(sfd, message, sizeof message / sizeof *message);
	if (-1 == rc) {
		perror("writev");
		return -1;
	}
	size_t len = 0;
	for (unsigned i = 0; i < sizeof message / sizeof *message; ++i)
		len += message[i].iov_len;
	if (rc != len) {
		warnx("writev: expected %lu, wrote %ld", len, rc);
		return -1;
	}
	char *id = NULL;
	rc = basex_read_block(sfd, &id);
	if (-1 == rc)
		return -1;
	rc = basex_read_server_response(sfd, code, server_message);
	if (-1 == rc)
		goto error;
	*qid = id;
	return 0;
	error:
		if (NULL != id)
			free(id);
		return -1;
}

int
basex_query_results(int const sfd, char const * const qid)
{
	char const command = '\x04';
	struct iovec const message[] = {
		{
			.iov_base = (void *)&command,
			.iov_len = sizeof command
		},
		{
			.iov_base = (void *)qid,
			.iov_len = strlen(qid) + 1
		}
	};
	ssize_t rc = writev(sfd, message, sizeof message / sizeof *message);
	if (-1 == rc) {
		perror("writev");
		return -1;
	}
	size_t len = 0;
	for (unsigned i = 0; i < sizeof message / sizeof *message; ++i)
		len += message[i].iov_len;
	if (rc != len) {
		warnx("writev: expected %lu, wrote %ld", len, rc);
		return -1;
	}
	return 0;
}

/* returns result type (0 if there are no more results) */
int
basex_query_more(int const sfd, char * const type, char ** const block, size_t * const size, char * const code, char ** const server_message)
{
	char typebuf;
	ssize_t rc = read(sfd, &typebuf, sizeof typebuf);
	if (-1 == rc) {
		perror("read");
		return -1;
	}
	if (0 == rc) {
		warnx("EOF");
		return -1;
	}
	*type = typebuf;
	/* 0 means end of data */
	if ('\x00' == typebuf) {
		rc = basex_read_server_response(sfd, code, server_message);
		if (-1 == rc)
			goto error;
		return 0;
	}
	char *buf = NULL;
	size_t value_size = 0;
	value_size = basex_read_block(sfd, &buf);
	if (-1 == value_size)
		return -1;

	*size = value_size;
	*block = buf;
	return value_size;
	error:
		if (NULL != buf)
			free(buf);
		return -1;
}

int
basex_query_execute(int const sdf, char const * const qid, char ** const result, char * const code, char ** const server_message)
{
}

int
basex_query_close(int const sfd, char const * const qid, char * const code, char ** const server_message)
{
	char const command = '\x02';
	struct iovec const message[] = {
		{
			.iov_base = (void *)&command,
			.iov_len = sizeof command
		},
		{
			.iov_base = (void *)qid,
			.iov_len = strlen(qid) + 1
		}
	};
	ssize_t rc = writev(sfd, message, sizeof message / sizeof *message);
	if (-1 == rc) {
		perror("writev");
		return -1;
	}
	size_t len = 0;
	for (unsigned i = 0; i < sizeof message / sizeof *message; ++i)
		len += message[i].iov_len;
	if (rc != len) {
		warnx("writev: expected %lu, wrote %ld", len, rc);
		return -1;
	}
	/* read zero byte that seems to do not mean much (doing this only for protocol synchronisation) */
	char dummy_code;
	rc = read(sfd, &dummy_code, sizeof dummy_code);
	if (-1 == rc) {
		perror("read");
		return -1;
	}
	if (0 == rc) {
		warnx("EOF");
		return -1;
	}
	assert('\x00' == dummy_code);
	return basex_read_server_response(sfd, code, server_message);
}

static ssize_t
basex_write_block(int const sfd, char const * const block, size_t const size)
{}

int
basex_query_bind(int const sfd, char const * const qid, char const * const name, char const * const value, char const * const type, char * const code, char ** const server_message)
{
	char const command = '\x03';
	struct iovec const message[] = {
		{
			.iov_base = (void *)&command,
			.iov_len = sizeof command
		},
		{
			.iov_base = (void *)qid,
			.iov_len = strlen(qid) + 1
		},
		{
			.iov_base = (void *)name,
			.iov_len = strlen(name) + 1
		},
		{
			.iov_base = (void *)value,
			.iov_len = strlen(value) + 1
		},
		{
			.iov_base = (void *)type,
			.iov_len = strlen(type) + 1
		}
	};
	ssize_t rc = writev(sfd, message, sizeof message / sizeof *message);
	if (-1 == rc) {
		perror("writev");
		return -1;
	}
	size_t len = 0;
	for (unsigned i = 0; i < sizeof message / sizeof *message; ++i)
		len += message[i].iov_len;
	if (rc != len) {
		warnx("writev: expected %lu, wrote %ld", len, rc);
		return -1;
	}
	/* read zero byte that seems to do not mean much (doing this only for protocol synchronisation) */
	/* close and context also end with this kind of server response */
	char dummy_code;
	rc = read(sfd, &dummy_code, sizeof dummy_code);
	if (-1 == rc) {
		perror("read");
		return -1;
	}
	if (0 == rc) {
		warnx("EOF");
		return -1;
	}
	assert('\x00' == dummy_code);
	return basex_read_server_response(sfd, code, server_message);
}
/* TODO implement binding sequences */

int
basex_query_context(int const sfd, char const * const qid, char const * const value, char const * const type, char * const code, char ** const server_message)
{
	char const command = '\x0e';
	struct iovec const message[] = {
		{
			.iov_base = (void *)&command,
			.iov_len = sizeof command
		},
		{
			.iov_base = (void *)qid,
			.iov_len = strlen(qid) + 1
		},
		{
			.iov_base = (void *)value,
			.iov_len = strlen(value) + 1
		},
		{
			.iov_base = (void *)type,
			.iov_len = strlen(type) +1
		}
	};
	ssize_t rc = writev(sfd, message, sizeof message / sizeof *message);
	if (-1 == rc) {
		perror("writev");
		return -1;
	}
	size_t len = 0;
	for (unsigned i = 0; i < sizeof message / sizeof *message; ++i)
		len += message[i].iov_len;
	if (rc != len) {
		warnx("writev: expected %lu, wrote %ld", len, rc);
		return -1;
	}
	/* read zero byte that seems to do not mean much (doing this only for protocol synchronisation) */
	char dummy_code;
	rc = read(sfd, &dummy_code, sizeof dummy_code);
	if (-1 == rc) {
		perror("read");
		return -1;
	}
	if (0 == rc) {
		warnx("EOF");
		return -1;
	}
	assert('\x00' == dummy_code);
	return basex_read_server_response(sfd, code, server_message);
}
