#include <criterion/criterion.h>
#include <criterion/logging.h>

#include "ticker.h"

/*
 * These tests are very basic "blackbox" tests designed to mostly exercise
 * startup and shutdown of the program.
 */

Test(basecode_suite, startup_quit_test) {
    char *cmd = "echo quit | timeout -s KILL 5s bin/ticker";
    int return_code = WEXITSTATUS(system(cmd));

    cr_assert_eq(return_code, EXIT_SUCCESS,
                 "Program exited with %d instead of EXIT_SUCCESS",
		 return_code);
}

Test(basecode_suite, startup_EOF_test) {
    char *cmd = "cat /dev/null | timeout -s KILL 5s bin/ticker";
    int return_code = WEXITSTATUS(system(cmd));

    cr_assert_eq(return_code, EXIT_SUCCESS,
                 "Program exited with %d instead of EXIT_SUCCESS",
		 return_code);
}

Test(basecode_suite, startup_watchers_test) {
    char *cmd = "(echo watchers; echo quit) | timeout -s KILL 5s bin/ticker > test_output/startup_watchers.out";
    char *cmp = "cmp test_output/startup_watchers.out tests/rsrc/startup_watchers.out";

    int return_code = WEXITSTATUS(system(cmd));
    cr_assert_eq(return_code, EXIT_SUCCESS,
                 "Program exited with %d instead of EXIT_SUCCESS",
		 return_code);
    return_code = WEXITSTATUS(system(cmp));
    cr_assert_eq(return_code, EXIT_SUCCESS,
                 "Program output did not match reference output.");
}


////////////////////////////////// HELPER //////////////////////////////////////////////////////
#include <criterion/criterion.h>
#include <criterion/logging.h>

#include "__helper.h"

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>

#include "debug.h"

void assert_proper_exit_status(int err, int status) {
    cr_assert_eq(err, 0, "The test driver returned an error (%d)\n", err);
    cr_assert_eq(status, 0, "The program did not exit normally (status = 0x%x)\n", status);
}

// Set a symlink to point to the data file to be used for a test.
void link_to_test_data(char *file, char *lnk) {
    unlink(lnk);
    if(symlink(file, lnk) < 0)
	cr_assert_fail("Unable to point symlink (%s) at test data file (%s)\n", lnk, file);
}

//////////////////////////////////////// DRIVER ////////////////////////////////////////////////////
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <wait.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "event.h"
#include "driver.h"
#include "debug.h"

#define TICKER_PROMPT "ticker> "
#define TICKER_ERROR "???"
#define CONN_MSG "Websocket connected, you can send text messages of maximum 256 characters."

/*
 * Maximum size of buffer for command to be sent.
 */
#define SEND_MAX 200

char *event_type_names[] = {
	[NO_EVENT]	 "NONE",
	[ANY_EVENT]	 "ANY",
	[EOF_EVENT]	 "EOF",
	[PROMPT_EVENT]	 "PROMPT",
	[ERROR_EVENT]	 "ERROR",
	[TRACE_EVENT]	 "TRACE",
	[WATCHER_EVENT]	 "WATCHER",
	[SHOW_EVENT]	 "SHOW",
	[EOS_EVENT]	 "EOS",
	[OTHER_EVENT]    "OTHER"
};

static int run_target(char *prog, char *av[], FILE **cmd_str, FILE **reply_str);
static EVENT *read_response(FILE *f, struct timeval *timeout);
static int time_diff_usec(struct timeval *then, struct timeval *now);
static TRACE *parse_trace(char *str);
static WATCHER_DATA *parse_watcher_line(char *txt);
static SHOW_DATA *parse_show_line(char *txt);
static void *parse_error_line(char *txt);
static int handle_trace_event(EVENT *ep);
static int handle_watcher_event(EVENT *ep);
static int handle_show_event(EVENT *ep);

int run_test(char *name, char *target, char *av[], COMMAND *script, int *statusp) {
    fprintf(stderr, "Running test %s on target %s\n", name, target);
    signal(SIGPIPE, SIG_IGN);  // Avoid embarrassing death
    FILE *cmd_str = NULL, *reply_str = NULL;
    EVENT *ep = NULL;

    int pid = run_target(target, av, &cmd_str, &reply_str);
    if(pid == -1)
	return -1;

    // Main loop:
    COMMAND *scrp = script;
    while(scrp->send || scrp->expect || (scrp->delay.tv_sec || scrp->delay.tv_usec)) {
	// Possibly delay before sending next command.
	if(scrp->delay.tv_sec || scrp->delay.tv_usec) {
	    fprintf(stderr, "Delay (%ld, %ld)\n", scrp->delay.tv_sec, scrp->delay.tv_usec);
	    struct timespec ts = {.tv_sec = scrp->delay.tv_sec, .tv_nsec = scrp->delay.tv_usec * 1000};
	    struct timespec rem = ts;
	    int err = 0;
	    do {
		ts = rem;
		err = nanosleep(&ts, &rem);
	    } while(err == -1 && (rem.tv_sec || rem.tv_nsec));
	}
	if(scrp->send) {
	    // Send next command to child process.
	    fprintf(stderr, ">>> %s", scrp->send);
	    fprintf(cmd_str, "%s", scrp->send);
	    fflush(cmd_str);
	}
	if(scrp->expect) {
	    fprintf(stderr, "                   [expect %s]\n", event_type_names[scrp->expect]);
	    if(scrp->expect == EOF_EVENT) {
		fclose(cmd_str);
		cmd_str = NULL;
		int err = waitpid(pid, statusp, 0);
		if(err == pid) {
		    debug("Target process terminated with status 0x%x", *statusp);
		    pid = 0;
		} else {
		    perror("waitpid");
		}
	    }
	    // Check for any leftover events on the connection.
	    if(scrp->expect == EOF_EVENT) {
	        int skip = scrp->modifiers & EXPECT_SKIP_OTHER;
		while((ep = read_response(reply_str, &scrp->timeout)) != NULL) {
		    fprintf(stderr, "Response read when expecting EOF: '%s'%s\n", ep->raw_data,
			    skip ? " -- skipping" : "");
		    free_event(ep);
		    ep = NULL;
		    if(skip)
		      continue;
		    else
		      goto abort_test;
		}
		break;
	    }
	    // Read response and check whether it matches what is expected.
	    while(1) {
		// Don't read another response if we are already holding one as a result
		// of a terminated EXPECT_REPEAT.
		while(!ep) {
		    ep = read_response(reply_str, &scrp->timeout);
		    if(ep == NULL)
			break;
		    // Special handling for OTHER_EVENT with empty lines.
		    // Ignore these, because student code is producing them and
		    // they tend to complicate the test scripts.
		    if(ep->type == OTHER_EVENT && *ep->raw_data == '\n' && *(ep->raw_data+1) == '\0') {
			fprintf(stderr, "Ignoring OTHER_EVENT with blank line\n");
			free_event(ep);
			ep = NULL;
			continue;
		    }
		   // Uggh! Special handling for TRACE_EVENT with JSON string "END OF STREAM".
		   // These are converted to an EOS_EVENT that can be matched in the test script.
		   // Otherwise, there isn't a good way to determine when to end a script
		   // that reads a long data stream.
		   if(ep->type == TRACE_EVENT) {
		       if(strstr(ep->raw_data, "\"END OF STREAM\"")) {
			   fprintf(stderr, "End of stream is indicated\n");
			   ep->type = EOS_EVENT;
		       }
		       break;
		   }
		}
		if(ep == NULL) {
		    // Seeing EOF before the end of the script is an error.
		    if(scrp->expect != EOF_EVENT) {
			fprintf(stderr, "Unexpected EOF event\n");
			goto abort_test;
		    } else {
			fprintf(stderr, "Test driver error: EOF event should already have been handled\n");
			abort();
		    }
		}
		int matched = (scrp->expect == ANY_EVENT || scrp->expect == ep->type);

		// If event matched expected, check pre-transition assertion, if any.
		if(matched && scrp->before)
		    scrp->before(ep, NULL, scrp->args);
#if 0
		// Perform transition regardless of whether event matched or not.
		if(track_event(ep) == -1) {
		    fprintf(stderr, "Event tracker returned an error\n");
		    goto abort_test;
		}
#endif
		// Special handling for trace events.
		if(ep->type == TRACE_EVENT) {
		    if(handle_trace_event(ep))
			goto abort_test;
		}

		// Special handling for watcher events.
		if(ep->type == WATCHER_EVENT) {
		    if(handle_watcher_event(ep))
			goto abort_test;
		}

		// Special handling for show events.
		if(ep->type == SHOW_EVENT) {
		    if(handle_show_event(ep))
			goto abort_test;
		}

		// If event matched expected, check post-transition assertion, if any.
		if(matched && scrp->after) {
		    scrp->after(ep, NULL, scrp->args);
		}

		if(matched) {
		    // If event matched expected, then advance test script, unless EXPECT_REPEAT
		    // modifier is present.
		    int repeat = scrp->modifiers & EXPECT_REPEAT;
		    struct timeval zero = {0};
		    int usec_limit = time_diff_usec(&zero, &scrp->timeout);
		    fprintf(stderr, "Event type matched expected type %s ", event_type_names[scrp->expect]);
		    if(usec_limit)
			fprintf(stderr, "(%d usec, limit %d)", ep->usec, usec_limit);
		    fprintf(stderr, "%s\n", repeat ? " -- not advancing" : "");
		    if(!repeat)
			break;
		} else if(scrp->modifiers & EXPECT_SKIP_OTHER) {
		    // If event did not match expected, but EXPECT_SKIP_OTHER modifier is present
		    // then read another event without advancing the script.
		    fprintf(stderr, "Event type (%s) does not match expected (%s) -- skipping\n",
			    event_type_names[ep->type], event_type_names[scrp->expect]);
		} else if(scrp->modifiers & EXPECT_REPEAT) {
		    // If event did not match expected, but EXPECT_REPEAT modifier is present
		    // then advance the script without reading another event.
		    fprintf(stderr, "Event type (%s) does not match expected repeat (%s) -- advancing\n",
			    event_type_names[ep->type], event_type_names[scrp->expect]);
		    goto advance;
#if 0
		} else if(ep->type == CHANGE_EVENT) {
		    // If event did not match expected, but event is a state change event,
		    // then read another event without advancing the script.
#endif
		} else {
		    // Otherwise, failure to match is an error.
		    fprintf(stderr, "Event type (%s) did not match expected type %s\n",
			    event_type_names[ep->type], event_type_names[scrp->expect]);
		    goto abort_test;
		}
		if(ep) {
		    free_event(ep);
		    ep = NULL;
		}
	    }
	    if(ep) {
		free_event(ep);
		ep = NULL;
	    }
	}
	advance:
	debug("Advance test script");
	scrp++;
    }
    // Normal end of test script.
    // Wait for child and get exit status.
    if(cmd_str)
	fclose(cmd_str);
    if(reply_str)
	fclose(reply_str);
    if(pid && waitpid(-1, statusp, 0) < 0) {
	perror("waitpid");
	return -1;
    }
    fprintf(stderr, "End of test %s\n", name);
    return 0;

 abort_test:
    fprintf(stderr, "Aborting test %s\n", name);
    if(pid) {
	killpg(pid, SIGKILL);
	killpg(pid, SIGCONT);
    }
    return -1;
}

static int run_target(char *prog, char *av[], FILE **cmdp, FILE **replyp) {
    FILE *cmdstr, *replystr;
    int cmd_pipe[2];
    int reply_pipe[2];
    int pid;

    if(pipe(cmd_pipe) == -1) {
	perror("pipe(cmd)");
	exit(1);
    }
    if(pipe(reply_pipe) == -1) {
	perror("pipe(reply)");
	exit(1);
    }
    if((pid = fork()) == 0) {
        struct rlimit rl;
	rl.rlim_cur = rl.rlim_max = 60;  // 60 seconds CPU maximum
	setrlimit(RLIMIT_CPU, &rl);
	rl.rlim_cur = rl.rlim_max = 10000;  // 10000 processes maximum
	setrlimit(RLIMIT_NPROC, &rl);
	// Create a new process group so that we can nuke wayward children when
	// we are done.
	setpgid(0, 0);
        signal(SIGPIPE, SIG_DFL);

	dup2(cmd_pipe[0], 0);
	dup2(reply_pipe[1], 1);
	dup2(reply_pipe[1], 2);  // For now, send stdout/stderr to the same place
	close(cmd_pipe[0]); close(cmd_pipe[1]);
	close(reply_pipe[0]); close(reply_pipe[1]);
	if(execvp(av[0], av) == -1) {
	    perror("exec");
	    exit(1);
	}
    }
    close(cmd_pipe[0]);
    close(reply_pipe[1]);
    if((cmdstr = fdopen(cmd_pipe[1], "w")) == NULL) {
	perror("fdopen(cmd)");
	exit(1);
    }
    if((replystr = fdopen(reply_pipe[0], "r")) == NULL) {
	perror("fdopen(reply)");
	exit(1);
    }
    *cmdp = cmdstr;
    *replyp = replystr;
    return pid;
}

static struct timeval current_timeout;

static void alarm_handler(int sig) {
    struct timeval now;
    gettimeofday(&now, NULL);
    fprintf(stderr, "%ld.%06ld: Driver: timeout (%ld, %ld)\n",
	    now.tv_sec, now.tv_usec, current_timeout.tv_sec, current_timeout.tv_usec);
}

static EVENT *read_response(FILE *f, struct timeval *timeout) {
    int c;
    char *rsp = NULL;
    size_t rsize = 0;
    struct timeval then;

    debug("Read response");
    gettimeofday(&then, NULL);
    struct itimerval itv = {0};
    struct sigaction sa = {0}, oa;
    sa.sa_handler = alarm_handler;
    // No SA_RESTART
    itv.it_value = *timeout;
    current_timeout = *timeout;
    sigaction(SIGALRM, &sa, &oa);
    setitimer(ITIMER_REAL, &itv, NULL);
    memset(&itv, 0, sizeof(itv));

    FILE *rspf = open_memstream(&rsp, &rsize);
    while((c = fgetc(f)) != EOF) {
	//fprintf(stderr, "'%c'", c);
	fputc(c, rspf);
	fflush(rspf);
	if(c == '\n' || strstr(rsp, TICKER_PROMPT))
	    break;
    }
    if(c == EOF) {
	if(errno == EINTR)
	    fprintf(stderr, "Timeout reading response from child\n");
	// I don't think errno is otherwise useful here.
	//else
	//    perror("Error reading response");
	fclose(rspf);
	free(rsp);
	return NULL;
    }
    fclose(rspf);

    setitimer(ITIMER_REAL, &itv, NULL);  // Cancel timer
    sigaction(SIGALRM, &oa, NULL);

    // Create and fill in an event.
    EVENT *ep = malloc(sizeof(*ep));
    memset(ep, 0, sizeof(*ep));
    TRACE *tp = NULL;
    WATCHER_DATA *wdp = NULL;
    SHOW_DATA *sdp = NULL;
    ep->type = NO_EVENT;
    ep->trace = NULL;
    ep->wdata = NULL;
    ep->sdata = NULL;
    gettimeofday(&ep->timestamp, NULL);
    ep->usec = time_diff_usec(&then, &ep->timestamp);
    ep->raw_data = rsp;
    rsp = NULL;

    if(!strcmp(ep->raw_data, TICKER_PROMPT))
	ep->type = PROMPT_EVENT;
    else if(parse_error_line(ep->raw_data))
	ep->type = ERROR_EVENT;
    else if((wdp = parse_watcher_line(ep->raw_data)) != NULL) {
	ep->type = WATCHER_EVENT;
	ep->wdata = wdp;
    } else if((sdp = parse_show_line(ep->raw_data)) != NULL) {
	ep->type = SHOW_EVENT;
	ep->sdata = sdp;
    } else if((tp = parse_trace(ep->raw_data)) != NULL) {
	ep->type = TRACE_EVENT;
	ep->trace = tp;
    } else {
	ep->type = OTHER_EVENT;
    }

    show_event(stderr, ep);
    return ep;
}

void show_event(FILE *f, EVENT *ep) {
    fprintf(f, "%ld.%06ld: Driver <~~ [%-8s] '%s'\n",
	    ep->timestamp.tv_sec, ep->timestamp.tv_usec,
	    event_type_names[ep->type], ep->raw_data);
}

void free_event(EVENT *ep) {
    if(ep->raw_data)
	free(ep->raw_data);
    if(ep->trace) {
	if(ep->trace->name)
	    free(ep->trace->name);
	if(ep->trace->json)
	    argo_free_value(ep->trace->json);
	free(ep->trace);
    }
    if(ep->wdata) {
	if(ep->wdata->type)
	    free(ep->wdata->type);
	if(ep->wdata->args1)
	    free(ep->wdata->args1);
	if(ep->wdata->args2)
	    free(ep->wdata->args2);
    }
    free(ep);
}

static TRACE *parse_trace(char *str) {
    TRACE t = {0}, *tp;
    int n = sscanf(str, "[%ld.%ld][%m[^]] ][%d][%d]",
		   &t.time.tv_sec, &t.time.tv_usec, &t.name, &t.fd, &t.serial);
    if(n == 5) {
	t.data = strstr(str, ": ") + 2;
	tp = malloc(sizeof(*tp));
	*tp = t;
	return tp;
    } else {
	//fprintf(stderr, "sscanf returns %d\n", n);
	return NULL;
    }
}

static int time_increases(struct timeval *tv1, struct timeval *tv2) {
    return (tv1->tv_sec < tv2->tv_sec ||
	    (tv1->tv_sec == tv2->tv_sec && tv1->tv_usec < tv2->tv_usec));
}

static int time_diff_usec(struct timeval *then, struct timeval *now) {
    int usec = (now->tv_sec - then->tv_sec) * 1000;
    if(usec >= 0) {
	usec += (now->tv_usec - then->tv_usec);
    } else {
	usec -= (now->tv_usec - then->tv_usec);
    }
    return usec;
}

static ARGO_VALUE *parse_uwsc_message(char *txt) {
    ARGO_VALUE *vp = NULL;
    char *pfx = "Server message: '";
    char *bp = strstr(txt, pfx);
    if(bp) {  // Try to parse JSON
	// Note: uwsc puts some junk before the prefix,
	// so it is not necessarily the case that bp == txt.
	size_t pfxsize = strlen(pfx);
	size_t size = strlen(bp + pfxsize);
	FILE *f = fmemopen(bp + strlen(pfx), size, "r");
	vp = argo_read_value(f);
    }
    return vp;
}

static SHOW_DATA *parse_show_line(char *txt) {
    double value;
    int n;
    char *tp = strchr(txt, '\t');
    if(!tp)
	return NULL;
    *tp = '\0';
    tp++;
    n = sscanf(tp, "%lf", &value);
    if(n == 1) {
	SHOW_DATA *sdata = malloc(sizeof(*sdata));
	sdata->name = strdup(txt);
	sdata->value = value;
	return sdata;
    }
    return NULL;
}

static WATCHER_DATA *parse_watcher_line(char *txt) {
    int wid;
    char *wtype, *args1 = NULL, *args2 = NULL;
    pid_t pid;
    int rfd, wfd;
    int n;

    n = sscanf(txt, "%d\t%m[^(](%d,%d,%d) %m[^[][%m[^]]",
	       &wid, &wtype, &pid, &rfd, &wfd, &args1, &args2);
    if(n >= 5) {
	WATCHER_DATA *wdata = malloc(sizeof(*wdata));
	wdata->id = wid;
	wdata->type = wtype;
	wdata->pid = pid;
	wdata->rfd = rfd;
	wdata->wfd = wfd;
	wdata->args1 = args1;
	wdata->args2 = args2;
	// Because of the parsing, args1 could end with a single space,
	// so delete it.
	if(wdata->args1) {
	    int len = strlen(wdata->args1);
	    if(args1[len-1] == ' ')
		args1[len-1] = '\0';
	}
	return wdata;
    } else {
	return NULL;
    }
}

static void *parse_error_line(char *txt) {
    char *cp = strstr(txt, TICKER_ERROR);
    size_t len = sizeof(TICKER_ERROR);
    if(cp && *(cp+len-1) == '\n' && *(cp+len) == '\0') {
	return "";
    } else {
	return NULL;
    }
}

#define DEADLINE 20000  //20 msec

static int handle_trace_event(EVENT *ep) {
    TRACE *tp = ep->trace;
    fprintf(stderr, "TRACE EVENT:");
    fprintf(stderr, "\t[%lu.%06lu]", tp->time.tv_sec, tp->time.tv_usec);
    fprintf(stderr, "[%-10s][%2d][%5d]: ", tp->name, tp->fd, tp->serial);
    fprintf(stderr, "%s", tp->data);
    fprintf(stderr, "\n");

    // Check the declared timestamp for validity (must be no later than the event timestamp)
    // and promptness (must not be much earlier than the event timestamp).
    if(!time_increases(&tp->time, &ep->timestamp)) {
	fprintf(stderr, "Timestamp in trace (%ld.%06ld) "
		"is greater than time of this event (%ld.%06ld)\n",
		tp->time.tv_sec, tp->time.tv_usec, ep->timestamp.tv_sec, ep->timestamp.tv_usec);
	return 1;
    }
    // We can now subtract without worrying about signs.
    struct timeval deadline = tp->time;
    deadline.tv_usec += DEADLINE;
    while(deadline.tv_usec >= 1000000) {
	deadline.tv_sec++;
	deadline.tv_usec -= 1000000;
    }
    if(time_increases(&deadline, &ep->timestamp)) {
	fprintf(stderr, "Trace event did not arrive promptly (deadline = %ld.%06ld, actual = %ld.%06ld)\n",
		deadline.tv_sec, deadline.tv_usec, ep->timestamp.tv_sec, ep->timestamp.tv_usec);
	return 1;
    }

    // Check if the message body appears to be from uwsc and parse the JSON.
    tp->json = parse_uwsc_message(tp->data);
    return 0;
}

static int handle_watcher_event(EVENT *ep) {
    WATCHER_DATA *wdp = ep->wdata;
    if(!strcmp(wdp->type, "CLI")) {
	if(wdp->pid != -1) {
	    fprintf(stderr, "PID in watcher event is -1, but watcher is not CLI\n");
	    return 1;
	}
    } else {
	// Check that the process with the specified PID actually exists.
	struct stat statbuf;
	char x[] = "/proc/XXXXXXXXX/status";
	sprintf(x, "/proc/%d/status", wdp->pid);
	if(stat(x, &statbuf) < 0) {
	    fprintf(stderr, "PID (%d) in watcher event refers to a nonexistent process\n", wdp->pid);
	    return 1;
	}
    }
    return 0;
}

static int handle_show_event(EVENT *ep) {
    SHOW_DATA *sdp = ep->sdata;
    fprintf(stderr, "handle show event: name=%s, value=%f\n",
	    sdp->name, sdp->value);
    return 0;
}


//////////////////////////////////////// TRACKER TESTS ///////////////////////////////////////////
#include <criterion/criterion.h>
#include <criterion/logging.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/time.h>

#include "ticker.h"
#include "__helper.h"
#include "event.h"
#include "driver.h"

#define QUOTE1(x) #x
#define QUOTE(x) QUOTE1(x)
#define SCRIPT1(x) x##_script
#define SCRIPT(x) SCRIPT1(x)

#define TEST_DATA_SYMLINK "LINK_TO_TEST_DATA"
#define TICKER_EXECUTABLE "bin/ticker"
#define IGNORED_CHANNEL "IGNORED_CHANNEL"

/*
 * Finalization function to try to ensure no stray processes are left over
 * after a test finishes.
 */
static void killall() {
  system("killall -q -s KILL bin/ticker");
  system("killall -q -s KILL uwsc");
}

/*
 * Tests of ticker using event tracker.
 */

#define SUITE basic

/*
 * Start target, read prompt, check for EOF.
 */
#define TEST_NAME start_eof
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 5)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Start target, send empty input line, check for error message and prompt, check for EOF.
 */
#define TEST_NAME start_empty_eof
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "\n",              ERROR_EVENT,       0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 5)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Start target, read prompt, issue quit, check for EOF.
 */
#define TEST_NAME start_quit_eof
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 5)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Start target, read prompt, issue "trace 0", then "untrace 0", check for trace output, then EOF.
 */
#define TEST_NAME start_trace_untrace
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "trace 0\n",       PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "untrace 0\n",     TRACE_EVENT,       0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 5)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Test that an error results from an attempt to trace a nonexistent watcher.
 */
#define TEST_NAME trace_nonexistent
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "trace 1\n",       ERROR_EVENT,       0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 5)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Start target, read prompt, issue "watchers", then EOF.
 * For this test, we don't check anything about the target's response
 * to the the "watchers" command except that a single WATCHER_EVENT is
 * received.
 */
#define TEST_NAME start_watchers
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "watchers\n",      WATCHER_EVENT,     0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 5)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Test that an error is issued when an attempt is made to stop a nonexistent watcher.
 */
#define TEST_NAME stop_nonexistent
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "stop 1\n",        ERROR_EVENT,       0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 5)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Test that an error is issued when an attempt is made to stop the CLI watcher.
 */
#define TEST_NAME stop_CLI
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "stop 0\n",        ERROR_EVENT,       0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 5)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Test that an error is issued when an attempt is made to show the value
 * of an undefined store variable.
 */
#define TEST_NAME show_nonexistent
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "show xyzzy\n",    ERROR_EVENT,       0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 5)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Test that an error is issued when a "start" command is attempted without any argument.
 */
#define TEST_NAME start_no_arg
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "start\n",         ERROR_EVENT,       0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 5)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Test that an error is issued when a "stop" command is attempted without any argument.
 */
#define TEST_NAME stop_no_arg
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "stop\n",          ERROR_EVENT,       0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 5)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Test that an error is issued when a "show" command is attempted without any argument.
 */
#define TEST_NAME show_no_arg
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "show\n",          ERROR_EVENT,       0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 5)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Test that an error is issued when a "trace" command is attempted without any argument.
 */
#define TEST_NAME trace_no_arg
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "trace\n",         ERROR_EVENT,       0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 5)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Test that an error is issued when an "untrace" command is attempted without any argument.
 */
#define TEST_NAME untrace_no_arg
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "untrace\n",       ERROR_EVENT,       0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 5)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

#undef SUITE

#define SUITE watcher

/*
 * Start a test watcher and check that no error is reported.
 */
#define TEST_NAME start_watcher
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "start tester "IGNORED_CHANNEL"\n",
		                        PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
//    {  ZERO_SEC,     NULL,              EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL},
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 10)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    link_to_test_data("tests/rsrc/"QUOTE(TEST_NAME)".in", TEST_DATA_SYMLINK);
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Start a test watcher with a data file that has a long delay, wait one second, and try
 * to stop it.  This should succeed because the test watcher should not terminate until
 * after its long delay.
 */
#define TEST_NAME start_wait_stop_watcher_long_delay
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "start tester "IGNORED_CHANNEL"\n",
		                        PROMPT_EVENT,      EXPECT_SKIP_OTHER, HND_MSEC,          NULL,                   NULL },
    {  ONE_SEC,      "stop 1\n",        PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
//    {  ZERO_SEC,     NULL,              EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL},
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 10)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    link_to_test_data("tests/rsrc/"QUOTE(TEST_NAME)".in", TEST_DATA_SYMLINK);
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Start a test watcher with a data file that has a long delay, wait one second,
 * and issue "watchers" command.  We should receive two "watchers lines", one for
 * the CLI and one for the new watcher.  The driver will check whether the process
 * indicated for the new watcher actually exists.
 */
#define TEST_NAME start_wait_watchers_long_delay

static void assert_watcher_data(EVENT *ep, int *env, void *args) {
    if(!strcmp(ep->wdata->type, "CLI")) {
	cr_assert_eq(ep->wdata->id, 0, "Watcher id (%d) for CLI watcher is not 0\n",
		     ep->wdata->id);
    } else if(!strcmp(ep->wdata->type, "tester")) {
	char *exp_arg = NULL;
	cr_assert_eq(ep->wdata->id, 1, "Watcher id (%d) for 'tester' watcher is not 1\n",
		     ep->wdata->id);
	exp_arg = "util/tester "TEST_DATA_SYMLINK;
	cr_assert_eq(strcmp(ep->wdata->args1, exp_arg), 0,
		     "Watcher args (%s) are not the expected (%s)\n",
		     ep->wdata->args1, exp_arg);
	exp_arg = "IGNORED_CHANNEL";
	cr_assert_eq(strcmp(ep->wdata->args2, exp_arg), 0,
		     "Watcher extra_arg (%s) are not the expected (%s)\n",
		     ep->wdata->args2, exp_arg);
    } else {
	cr_assert_fail("Watcher type (%s) is not one of the expected types (CLI) or (tester)\n",
		       ep->wdata->type);
    }
}

static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "start tester "IGNORED_CHANNEL"\n",
		                        PROMPT_EVENT,      EXPECT_SKIP_OTHER, HND_MSEC,          NULL,                   NULL },
    {  ONE_SEC,      "watchers\n",      WATCHER_EVENT,     0,                 ONE_MSEC,          NULL,                   assert_watcher_data },
    {  ZERO_SEC,     NULL,              WATCHER_EVENT,     0,                 ONE_MSEC,          NULL,                   assert_watcher_data },
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 10)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    link_to_test_data("tests/rsrc/"QUOTE(TEST_NAME)".in", TEST_DATA_SYMLINK);
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Start a test watcher for which no data file exists, wait one second, and try to stop it.
 * This should result in an error, because the test watcher should terminate immediately,
 * which means that it should already have been removed from the watchers table at the
 * time the stop command is issued.
 */
#define TEST_NAME start_wait_stop_watcher_no_file
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "start tester "IGNORED_CHANNEL"\n",
		                        PROMPT_EVENT,      EXPECT_SKIP_OTHER, HND_MSEC,          NULL,                   NULL },
    {  ONE_SEC,      "stop 1\n",        ERROR_EVENT,       EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 10)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    link_to_test_data("tests/rsrc/"QUOTE(TEST_NAME)".in", TEST_DATA_SYMLINK);
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Start a test watcher with data file that has a long delay, immediately turn on tracing,
 * and check that the "subscribe" messages are received.
 *
 * TODO: Almost nobody seemed to produce trace printout for messages that did not start
 * "Server message".  So this test does not provide much information..
 */
#define TEST_NAME start_watcher_trace_subscribe
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "start tester "IGNORED_CHANNEL"\n",
		                        PROMPT_EVENT,      EXPECT_SKIP_OTHER, HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "trace 1\n",       PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 10)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    link_to_test_data("tests/rsrc/"QUOTE(TEST_NAME)".in", TEST_DATA_SYMLINK);
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Start a test watcher, turn on tracing, and wait for a few events.
 */
#define TEST_NAME receive_some_tracing
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "start tester "IGNORED_CHANNEL"\n",
		                        PROMPT_EVENT,      EXPECT_SKIP_OTHER, HND_MSEC,          NULL,                   NULL },
    // Delay for the "subscribed messages" to be received, then turn on tracing
    {  HND_MSEC,     "trace 1\n",       PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    // Wait for a few trace events, then terminate the test
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     "untrace 1\n",     PROMPT_EVENT,      EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 10)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    link_to_test_data("tests/rsrc/"QUOTE(TEST_NAME)".in", TEST_DATA_SYMLINK);
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

#undef SUITE

#define SUITE network

/*
 * Start a bitstamp watcher looking at live_orders_btcusd, turn on tracing, and wait for a few events.
 */
#define TEST_NAME bitstamp_live_orders
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "start bitstamp.net live_orders_btcusd\n",
		                        PROMPT_EVENT,      EXPECT_SKIP_OTHER, HND_MSEC,          NULL,                   NULL },
    // Delay for the "subscribed messages" to be received, then turn on tracing
    {  ONE_SEC,      "trace 1\n",       PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    // Wait for a few trace events, then terminate the test
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     "untrace 1\n",     PROMPT_EVENT,      EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 10)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    link_to_test_data("tests/rsrc/"QUOTE(TEST_NAME)".in", TEST_DATA_SYMLINK);
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Start multiple bitstamp watcher looking at live_orders_btcxxx, turn on tracing, and wait for some events.
 */
#define TEST_NAME bitstamp_multi_live_orders
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "start bitstamp.net live_orders_btcusd\n",
		                        PROMPT_EVENT,      EXPECT_SKIP_OTHER, HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "start bitstamp.net live_orders_btcgbp\n",
		                        PROMPT_EVENT,      EXPECT_SKIP_OTHER, HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "start bitstamp.net live_orders_btceur\n",
		                        PROMPT_EVENT,      EXPECT_SKIP_OTHER, HND_MSEC,          NULL,                   NULL },
    // Delay for the "subscribed messages" to be received, then turn on tracing
    // Skip trace messages that arrive while we are still turning on tracing
    {  ONE_SEC,      "trace 1\n",       PROMPT_EVENT,      EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "trace 2\n",       PROMPT_EVENT,      EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "trace 3\n",       PROMPT_EVENT,      EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    // Wait for some trace events, then terminate the test
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     "untrace 1\n",     PROMPT_EVENT,      EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "untrace 2\n",     PROMPT_EVENT,      EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "untrace 3\n",     PROMPT_EVENT,      EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 10)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    link_to_test_data("tests/rsrc/"QUOTE(TEST_NAME)".in", TEST_DATA_SYMLINK);
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

#undef SUITE

#define SUITE store

/*
 * Start a test watcher, turn on tracing, and read several btcusd events.
 * Once the events have been read, issue show commands to check the results.
 */
#define TEST_NAME receive_btcusd_tracing_short

static void assert_btcusd_price_27660(EVENT *ep, int *env, void *args) {
    char *exp_key = "tester:live_trades_btcusd:price";
    double exp_value = 27660.0;
    cr_assert_eq(strcmp(ep->sdata->name, exp_key), 0,
		 "Variable shown (%s) is not the expected (%s)\n",
		 ep->sdata->name, exp_key);
    cr_assert_eq(ep->sdata->value, exp_value,
		 "Value shown (%lf) is not the expected (%lf)\n",
		 ep->sdata->value, exp_value);
}

static void assert_btcusd_volume_533740(EVENT *ep, int *env, void *args) {
    char *exp_key = "tester:live_trades_btcusd:volume";
    double exp_value = 0.533740;
    cr_assert_eq(strcmp(ep->sdata->name, exp_key), 0,
		 "Variable shown (%s) is not the expected (%s)\n",
		 ep->sdata->name, exp_key);
    cr_assert_eq(ep->sdata->value, exp_value,
		 "Value shown (%lf) is not the expected (%lf)\n",
		 ep->sdata->value, exp_value);
}

static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "start tester "IGNORED_CHANNEL"\n",
		                        PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    // Delay for the "subscribed messages" to be received, then turn on tracing
    {  HND_MSEC,     "trace 1\n",       PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    // Read trace events until EOF
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     "show tester:live_trades_btcusd:price\n",
                                        SHOW_EVENT,        0,                 ONE_MSEC,          NULL,                   assert_btcusd_price_27660 },
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "show tester:live_trades_btcusd:volume\n",
                                        SHOW_EVENT,        0,                 ONE_MSEC,          NULL,                   assert_btcusd_volume_533740 },
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 10)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    link_to_test_data("tests/rsrc/"QUOTE(TEST_NAME)".in", TEST_DATA_SYMLINK);
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Start a test watcher, turn on tracing, and read all events until END OF STREAM.
 * This one doesn't check for any processing -- it just checks for possible hanging.
 */
#define TEST_NAME receive_btcusd_tracing_long
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "start tester "IGNORED_CHANNEL"\n",
		                        PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    // Delay for the "subscribed messages" to be received, then turn on tracing
    {  HND_MSEC,     "trace 1\n",       PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    // Read trace events
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       EXPECT_REPEAT,     ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              EOS_EVENT,         0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 10)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    link_to_test_data("tests/rsrc/"QUOTE(TEST_NAME)".in", TEST_DATA_SYMLINK);
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

/*
 * Start a test watcher, turn on tracing, and read all events until END OF STREAM.
 * Then check that the store variables have the proper values.
 */
#define TEST_NAME receive_btcusd_tracing_long_show

static void assert_btcusd_volume_1355760(EVENT *ep, int *env, void *args) {
    char *exp_key = "tester:live_trades_btcusd:volume";
    double exp_value = 1.355760;
    cr_assert_eq(strcmp(ep->sdata->name, exp_key), 0,
		 "Variable shown (%s) is not the expected (%s)\n",
		 ep->sdata->name, exp_key);
    cr_assert_eq(ep->sdata->value, exp_value,
		 "Value shown (%lf) is not the expected (%lf)\n",
		 ep->sdata->value, exp_value);
}

static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "start tester "IGNORED_CHANNEL"\n",
		                        PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    // Delay for the "subscribed messages" to be received, then turn on tracing
    {  HND_MSEC,     "trace 1\n",       PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    // Read trace events
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       EXPECT_REPEAT,     ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              EOS_EVENT,         0,                 ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     "show tester:live_trades_btcusd:price\n",
                                        SHOW_EVENT,        0,                 ONE_MSEC,          NULL,                   assert_btcusd_price_27660 },
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "show tester:live_trades_btcusd:volume\n",
                                        SHOW_EVENT,        0,                 ONE_MSEC,          NULL,                   assert_btcusd_volume_1355760 },
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "quit\n",          EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 10)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    link_to_test_data("tests/rsrc/"QUOTE(TEST_NAME)".in", TEST_DATA_SYMLINK);
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

#undef SUITE

#if 0

#define SUITE tracker_suite

/*
 * Start a bitstamp watcher and turn on tracing.
 */
#define TEST_NAME trace_bitstamp_test
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "start bitstamp.net live_trades_btcusd\n",
                                        PROMPT_EVENT,      0,                 TEN_SEC,           NULL,                   NULL },
 // {  ZERO_SEC,     NULL,              CONN_EVENT,        0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "watchers\n",      PROMPT_EVENT,      EXPECT_SKIP_OTHER, HND_MSEC,          NULL,                   NULL },
    // Wait for the "subscribed messages" to be received before turning on tracing
    {  ONE_SEC,      "trace 1\n",       PROMPT_EVENT,      EXPECT_SKIP_OTHER, HND_MSEC,          NULL,                   NULL },
    // Wait for a few trace events, then terminate the test
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       EXPECT_SKIP_OTHER, ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       EXPECT_SKIP_OTHER, ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     "untrace 1\n",     PROMPT_EVENT,      EXPECT_SKIP_OTHER, ZERO_SEC,          NULL,                   NULL },
//    {  ZERO_SEC,     NULL,              EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_SEC,           NULL,                   NULL},
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 10)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME

#if 0   // Test commented until "grader.local" is available in tree (and not in /bin).
/*
 * Start a grader watcher and turn on tracing.
*/
#define TEST_NAME trace_grader_test
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "start grader.local /opt/cse320_hw4_rsrc/btc_usd_1.data",
                                        PROMPT_EVENT,      0,                 TEN_SEC,           NULL,                   NULL },
    {  ZERO_SEC,     "watchers\n",
                                        PROMPT_EVENT,      EXPECT_SKIP_OTHER, HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "trace 1\n",
                                        PROMPT_EVENT,      EXPECT_SKIP_OTHER, HND_MSEC,          NULL,                   NULL },
    // Hang skipping further non-prompt events
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      EXPECT_SKIP_OTHER, ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 10)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}
#undef TEST_NAME
#endif

/*
 * Start a test watcher and turn on tracing.
 */
#define TEST_NAME test_watcher_test
static COMMAND SCRIPT(TEST_NAME)[] = {
    // delay,	     send,              expect,            modifiers,         timeout,           before,                 after
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     "start tester "IGNORED_CHANNEL"\n",
		                        PROMPT_EVENT,      0,                 TEN_SEC,           NULL,                   NULL },
    {  ZERO_SEC,     "watchers\n",      WATCHER_EVENT,     0,                 HND_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              WATCHER_EVENT,     EXPECT_REPEAT,     ONE_MSEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              PROMPT_EVENT,      EXPECT_SKIP_OTHER, ONE_MSEC,          NULL,                   NULL },
    // Wait for the "subscribed messages" to be received before turning on tracing
    {  ONE_SEC,      "trace 1\n",       PROMPT_EVENT,      EXPECT_SKIP_OTHER, HND_MSEC,          NULL,                   NULL },
    // Wait for a few trace events, then terminate the test
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       EXPECT_SKIP_OTHER, ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     NULL,              TRACE_EVENT,       EXPECT_SKIP_OTHER, ZERO_SEC,          NULL,                   NULL },
    {  ZERO_SEC,     "untrace 1\n",     PROMPT_EVENT,      EXPECT_SKIP_OTHER, ZERO_SEC,          NULL,                   NULL },
//    {  ZERO_SEC,     NULL,              EOF_EVENT,         EXPECT_SKIP_OTHER, ONE_SEC,           NULL,                   NULL}
    {  ZERO_SEC,     NULL,              0,                 0,                 ZERO_SEC,          NULL,                   NULL }
};

Test(SUITE, TEST_NAME, .fini = killall, .timeout = 10)
{
    int err, status;
    char *name = QUOTE(SUITE)"/"QUOTE(TEST_NAME);
    char *argv[] = {TICKER_EXECUTABLE, NULL};
    link_to_test_data("tests/rsrc/"QUOTE(TEST_NAME)".in", TEST_DATA_SYMLINK);
    err = run_test(name, argv[0], argv, SCRIPT(TEST_NAME), &status);
    assert_proper_exit_status(err, status);
}

#endif

