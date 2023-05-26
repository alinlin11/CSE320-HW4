# CSE320-HW4
Homework 4 Web Watcher - CSE 320 - Spring 2023

Professor Eugene Stark

Due Date: Friday 4/14/2023 @ 11:59pm


Introduction
The goal of this assignment is to become familiar with low-level Unix/POSIX system
calls related to processes, signal handling, files, and I/O redirection.
You will implement a "web watcher" program, called ticker, which manages a
collection of "watcher" processes that monitor real-time data feeds from a
cryptocurrency exchange.

Takeaways
After completing this assignment, you should:

Understand process execution: forking, executing, and reaping.
Understand signal handling and asynchronous I/O.
Understand the use of "dup" to perform I/O redirection.
Have gained experience with C libraries and system calls.
Have enhanced your C programming abilities.


Getting Started
The following package needs to be installed: libmicrohttpd-dev
Installation can be done using the apt package manager; e.g.:

$ sudo apt update
$ sudo apt install libmicrohttpd-dev


Fetch and merge the base code for hw4 as described in hw1.
You can find it at this link: https://gitlab02.cs.stonybrook.edu/cse320/hw4
Once you have merged the basecode, you will need to install the uwsc
command and associated libraries.  These have been provided in the form
of a "tarball" as util/uwsc.tgz.  If you are using the standard VM environment
for the course, you can install this by executing the following command:

sudo tar xvfz util/uwsc.tgz -C /


If you are using some environment other than the standard VM, you will need
to figure out what needs to be done for your particular setup.
Here is the structure of the base code:
.
├── .gitignore
├── .gitlab-ci.yml
└── hw4
    ├── demo
    │   └── ticker
    ├── include
    │   ├── bitstamp.h
    │   ├── cli.h
    │   ├── debug.h
    │   └── ticker.h
    ├── lib
    │   ├── argo.h
    │   ├── argo.o
    │   ├── store.h
    │   └── store.o
    ├── Makefile
    ├── src
    │   ├── bitstamp.c
    │   ├── cli.c
    │   ├── main.c
    │   ├── ticker.c
    │   └── watchers.c
    ├── test_output
    │   ├── .git-keep
    │   └── startup_watchers.out
    ├── tests
    │   ├── hw4_tests.c
    │   └── rsrc
    │       └── startup_watchers.out
    └── util
        └── uwsc.tgz

The include and src directories contain header and source files, as usual.
The lib directory contains headers and binaries for some library code that
has been provided for you.
The demo directory contains an executable demonstration version of the program.
The tests directory contains some very basic tests.
All of these are discussed in more detail below.
If you run make, the code should compile correctly, resulting in two
executables bin/ticker and bin/ticker_test.
The executable bin/ticker is the main one.
If you run this program, it will just abort, because only stubs for the
required functions have been provided -- you have to write them!
The executable bin/ticker_tests runs only some very basic tests, which cover
some easily overlooked cases that come up during startup and termination of
the program.  Most of the functionality is not exercised at all by these tests.

Hints and Tips


Due to the fact that the kind of program you will write in this assignment
will most likely be unfamiliar to you and you will need to use a number of
new system calls to do it, it is almost certainly not a good idea for you
to just set about writing the whole program at one go and trying to make it work.
Instead, you should develop the program in an incremental fashion, experimenting
with each of the system calls (ideally in the context of simple test programs)
to develop an understanding of how they work.  Then you can put the pieces together.


We strongly recommend that you check the return codes of all system calls
and library functions.  This will help you catch errors.


You should use the debug macro provided to you in the base code.
That way, when your program is compiled without -DDEBUG, all of your debugging
output will vanish, preventing you from losing points due to superfluous output.
Your program should only produce output that has been specified in this document,
and you should pay close attention to whether the output should be directed
to the standard output or to the standard error output.


Put to good use the tools that have been introduced in previous assignments.
In particular, use valgrind to check for serious memory access errors,
and gdb for normal debugging.


BEAT UP YOUR OWN CODE! Exercise your code thoroughly with various numbers of
processes, problem mix, and timing situations, to make sure that no sequence of
events can occur that can crash the program.


Your code should NEVER crash, and we will deduct points every time your
program crashes during grading.  Especially make sure that you have avoided
race conditions involving process termination and reaping that might result
in "flaky" behavior.  If you notice odd behavior you don't understand:
INVESTIGATE.



🤓 When writing your program, try to comment as much as possible and stay
consistent with code formatting.  Keep your code organized, and don't be afraid
to introduce new source files if/when appropriate.


Reading Man Pages
This assignment will involve the use of many system calls and library functions
that you probably haven't used before.
As such, it is imperative that you become comfortable looking up function
specifications using the man command.
The man command stands for "manual" and takes the name of a function or command
(programs) as an argument.
For example, if I didn't know how the fork(2) system call worked, I would type
man fork into my terminal.
This would bring up the manual for the fork(2) system call.

🤓 Navigating through a man page once it is open can be weird if you're not
familiar with these types of applications.
To scroll up and down, you simply use the up arrow key and down arrow key
or j and k, respectively.
To exit the page, simply type q.
That having been said, long man pages may look like a wall of text.
So it's useful to be able to search through a page.
This can be done by typing the / key, followed by your search phrase,
and then hitting enter.
Note that man pages are displayed with a program known as less.
For more information about navigating the man pages with less,
run man less in your terminal.

Now, you may have noticed the 2 in fork(2).
This indicates the section in which the man page for fork(2) resides.
Here is a list of the man page sections and what they are for.



Section
Contents




1
User Commands (Programs)


2
System Calls


3
C Library Functions


4
Devices and Special Files


5
File Formats and Conventions


6
Games, et al


7
Miscellanea


8
System Administration Tools and Daemons



From the table above, we can see that fork(2) belongs to the system call section
of the man pages.
This is important because there are functions like printf which have multiple
entries in different sections of the man pages.
If you type man printf into your terminal, the man program will start looking
for that name starting from section 1.
If it can't find it, it'll go to section 2, then section 3 and so on.
However, there is actually a Bash user command called printf, so instead of getting
the man page for the printf(3) function which is located in stdio.h,
we get the man page for the Bash user command printf(1).
If you specifically wanted the function from section 3 of the man pages,
you would enter man 3 printf into your terminal.

😱 Remember this: man pages are your bread and butter.
Without them, you will have a very difficult time with this assignment.


Development and Test Strategy
You will probably find it the most efficient approach to this assignment to write and
test your code incrementally, a little bit at a time, to develop your understanding and
verify that things are working as expected.
You will probably it overwhelmingly difficult to debug your code if you try to write
a lot of it first without trying it out little by little.
Putting some effort into creating useful, understandable, debugging trace output will
also be very helpful.

The killall Command
In the course of debugging this program, you will almost certainly end up in
situations where there are a number of "leftover" watcher processes that have survived
beyond a particular test run of the program.  If you allow these processes to
accumulate, it can cause confusion, as well as consume resources on your computer.
The ps(1) (process status) command can be used to determine if there are any
such processes around; e.g.

$ ps alx | grep uwsc


If there are a lot of them, it can be tedious to kill them all using the kill command.
The killall command can be used to kill all processes running a program with a
particular name; e.g.

$ killall uwsc


It might be necessary to use the additional option -s KILL to send these processes
a SIGKILL, which they cannot catch or ignore, as opposed to the SIGTERM, which is
sent by default.

The strace Command
An extremely useful (but rather advanced) feature that Linux provides for debugging
is the strace(1) command.  When a program is run via strace, you can get an
extremely detailed trace of all of the operating system calls made by the main process
of this program, as well as child processes.  This can be useful when all else fails
in trying to understand what a program is doing, however the down side is that
to understand the voluminous output produced by strace requires a fair amount of
technical knowledge about Linux system calls.  You might want to give it a try, though.

Ticker


Description of Behavior
The ticker program manages a collection of concurrently executing "watcher" processes
that monitor real-time data feeds from the Web.  As the watcher processes are notified
of events from their data feed, they report these events to the ticker process,
which extracts desired information from these events and accumulates it into a
"data store".  For concreteness, and due to the existence of free, publicly available
real-time data feeds, we will focus on monitoring data from a cryptocurrency exchange.
In particular, Bitstamp (www.bitstamp.net)
provides data feeds pertaining to buying and
selling of cryptocurrencies on their exchange.  These data feeds are
available via a "Websocket" interface.  Websockets provide a means of bidirectional
interaction with Web server, which is currently increasing in popularity.
A Websocket connection is obtained by "upgrading" an ordinary HTTP or HTTPS connection
to a web server.  Fortunately, for the purposes of this assignment you do not need
to understand how this happens, or to know very much about Websockets or even ordinary
HTTP or HTTPS connections to Web servers.  This is because we will use a stand-alone
client program called uwsc (Ulfius WebSocket Client), running in a child process,
to actually make the Websocket connections.  For this assignment, I have made a
custom-compiled version of the uwsc program that is available on GitHub
(github.com).
The custom compilation was done in order to get the most recent version
(which seems to fix some issues that I experienced with the older version standardly
available on Mint/Ubuntu), and to avoid the use of an unnecessary library (yder)
that was problematic to compile and which is not needed for what we are doing.
You can run the uwsc program from the Linux command line to make a Websocket
connection to a server.  For example, if you run:

$ uwsc wss://ws.bitstamp.net


you should see:

Websocket connected, you can send text messages of maximum 256 characters.
To exit uwsc, type !q<enter>
> 


The > is the command prompt from uwsc.  In order to cause the bitstamp server
to send some data, you need to subscribe to a "channel".  This is done by sending
a command (encoded in JSON) to the server.  For example:

> { "event": "bts:subscribe", "data": { "channel": "live_orders_btcusd" } }


You should then see "events" being reported (also encoded in JSON):

Send '{ "event": "bts:subscribe", "data": { "channel": "live_orders_btcusd" } }'
Server message: '{"event":"bts:subscription_succeeded","channel":"live_orders_btcusd","data":{}}'
Server message: '{"data":{"id":1599036464488448,"id_str":"1599036464488448","order_type":1,"datetime":"1679224736","microtimestamp":"1679224736496000","amount":0.22771886,"amount_str":"0.22771886","price":27106,"price_str":"27106"},"channel":"live_orders_btcusd","event":"order_created"}'
Server message: '{"data":{"id":1599036464488448,"id_str":"1599036464488448","order_type":1,"datetime":"1679224737","microtimestamp":"1679224736513000","amount":0.22771886,"amount_str":"0.22771886","price":27106,"price_str":"27106"},"channel":"live_orders_btcusd","event":"order_deleted"}'
Server message: '{"data":{"id":1599036464660480,"id_str":"1599036464660480","order_type":1,"datetime":"1679224737","microtimestamp":"1679224736537000","amount":0.00168139,"amount_str":"0.00168139","price":27174,"price_str":"27174"},"channel":"live_orders_btcusd","event":"order_created"}'
Server message: '{"data":{"id":1599036464726016,"id_str":"1599036464726016","order_type":1,"datetime":"1679224737","microtimestamp":"1679224736553000","amount":0.22771886,"amount_str":"0.22771886","price":27106,"price_str":"27106"},"channel":"live_orders_btcusd","event":"order_created"}'
...


The actual JSON responses from the server appear in between the single quotes (')
in the above.  The Send '...' and Server message: '...' wrappers are generated by
uwsc; they will need to be removed by the program you write.
A line of the form Send '...' is used by uwsc to report JSON that is sent to
the server, whereas a line of the form Server message: '...' reports a JSON
response sent by the server.  This wrapper text is annoying for our purposes,
and although it seemed like uwsc provides an option -i ("non-interactive")
that avoids them, I was not able to figure out how it was intended to work.
So, we will just have to suffer with the wrappers.
Hopefully you have encountered JSON ("Javascript Object Notation") before.
If not, a summary of it can be found at
www.json.org.
JSON is a notation for representing structured data, which has an extremely simple
syntax, and which (to my mind, at least) has some significant advantages over other
notations, such as XML, that are used for similar purposes.
JSON has become increasingly popular in recent years.
You will not have to write a parser for JSON: I have supplied with the basecode
a library containing a JSON parser (called argo) which was the subject of an
assignment I gave in this course a few semesters ago.
It will only be necessary for you to understand how to extract desired information
from the data structure returned by the parser; more on this below.
The live_orders_btcusd channel used above to illustrate the use of uwsc is
(from our point of view) a fairly high-rate data feed that produces on average
multiple events per second.  A feed like this will provide a good test of the
asynchronous signal-handling capabilities of your ticker program, but for development
purposes a lower-rate feed will be more useful.
Good examples are live_trades_btcusd and live_trades_btcgbp.
Your ticker program will use the events provided by the various live_trades_xxx
channels to accumulate information about cryptocurrency trades.
Besides Bitstamp, another site that provides a free real-time data feed via
Websockets is "blockchain.com"
www.blockchain.com.
This site, to which uwsc is also able to connect, provides real-time data about
updates to the Bitcoin blockchain.
Although it also uses JSON as the language for bidirectional communication between
the client and server, the format of the commands and responses is different
from Bitstamp's, so somewhat different "driver" code would be required to make
use of a feed from this site.
The architecture of the ticker program is designed to be general enough to support
multiple sites with different communication requirements, but you are only required
to implement support for the Bitstamp site in this assignment.
When ticker is launched, it presents a command-line interface:

$ bin/ticker
ticker> 


The command-line interface provides commands to start and stop watchers,
display a table of currently active watchers, enable or disable tracing
of events arriving from individual watchers, to show the data value
currently associated with a specified "key" in the data store, and to
perform a graceful shutdown of the main process and any executing watcher
processes.
So that waiting for the user to enter a command does not hinder the ability of
ticker to monitor external data feeds in real time, input from the command line
is treated just as if it were an additional data feed on which data can arrive
asynchronously.  In the context of the ticker architecture, this is done by
providing a CLI driver that understands how to interact with the user,
in addition to drivers that understand how to interact with a Websocket connection.
Here is an example of the use of the ticker command-line interface:

$ bin/ticker
ticker> watchers
0	CLI(-1,0,1)


There is initially just one "watcher" of type CLI (command-line interface),
which is not running in a separate process (the process ID is indicated as -1),
which is reading from standard input (file descriptor 0) and writing to standard
output (file descriptor 1).

ticker> start bitstamp.net live_trades_btcusd
ticker> watchers
0	CLI(-1,0,1)
1	bitstamp.net(404756,3,6) uwsc wss://ws.bitstamp.net [live_trades_btcusd]


Now there is an additional watcher, of type bitstamp.net,
which is running in process 404756, from which we can read data on file descriptor 3,
to which we can write data on file descriptor 6, and subscribed to channel live_trades_btcusd.

ticker> start bitstamp.net live_trades_btcgbp
ticker> watchers
0	CLI(-1,0,1)
1	bitstamp.net(404756,3,6) uwsc wss://ws.bitstamp.net [live_trades_btcusd]
2	bitstamp.net(404765,4,8) uwsc wss://ws.bitstamp.net [live_trades_btcgbp]


Now there is an additional watcher, of type bitstamp.net,
which is running in process 404765, with read file descriptor 4,
write file descriptor 8, and subscribed to channel live_trades_btcgbp.

ticker> trace 1
ticker> [1679233551.535374][bitstamp.net][ 3][   35]: Server message: '{"data":{"id":277351788,"timestamp":"1679233551","amount":0.00082,"amount_str":"0.00082000","price":27256,"price_str":"27256","type":0,"microtimestamp":"1679233551474000","buy_order_id":1599072570642432,"sell_order_id":1599072570363904},"channel":"live_trades_btcusd","event":"trade"}'

[1679233556.626918][bitstamp.net][ 3][   36]: Server message: '{"data":{"id":277351790,"timestamp":"1679233556","amount":0.002,"amount_str":"0.00200000","price":27253,"price_str":"27253","type":0,"microtimestamp":"1679233556564000","buy_order_id":1599072591491072,"sell_order_id":1599072580296705},"channel":"live_trades_btcusd","event":"trade"}'



Here we turned on tracing for "watcher #1".
While tracing was on, two events arrived.
At the beginning of each tracing line is shown:


a timestamp (e.g. [1679233551.535374]), giving seconds and microseconds since the "Unix epoch"
of midnight, January 1, 1970, UTC.


the type [bitstamp.net] of the watcher.


the file descriptor (*e.g. [ 3]) which ticker is using to read from this particular watcher.


the serial number (e.g. [   35]) of the message received from this particular watcher;
that is, this is the 35th message received from this watcher since it was started.


Following the initial information is the line of data that was read from the watcher
shown verbatim.

untrace 1


Tracing is turned off for watcher #1.

ticker> stop 1


Watcher #1 is terminated.

ticker> watchers
0	CLI(-1,0,1)
2	bitstamp.net(401983,7,10) uwsc wss://ws.bitstamp.net [live_trades_btcgbp]


Now only the CLI and watcher #2 are left.  Watcher ID 1 is free
to be used for a new watcher.

ticker> show bitstamp.net:live_trades_btcusd:price
bitstamp.net:live_trades_btcusd:price	27256.000000


We request the last trade price for this currency pair (Bitcoin and USD),
and are told that it is USD $27256 per 1 BTC.

ticker> show bitstamp.net:live_trades_btcusd:volume
bitstamp.net:live_trades_btcusd:volume	5.063207


We request the total volume of trades for this currency pair,
and are told that a total of 5.063207 BTC have been traded since we started
watching.

ticker> quit
ticker> $ 


We ask to quit the program.  The watcher processes are killed, the main
process waits for them to terminate, and then the main process itself
exits.

Implementation Details
The ticker program makes extensive use of processes, signals, and handlers
to create and manage the watchers.  A number of system calls are involved in
this, most of which have been discussed at least briefly in lecture.
When a bitstamp.net watcher is started, the main ticker process
uses the fork() system call to create a child process for it.  So that the
main process can communicate with the child, two pipes are created: one that
redirects output from the main process to the standard input of the child process,
and one that redirects the standard output of the child process to the main process.
Creation of the pipe and setting up the redirection uses the
pipe(), dup2(), and close() system calls.
Once the child process has started, it uses the execvp() system call to
execute the uwsc program with argument wss://ws.bitstamp.net.
The main process then outputs a JSON-encoded command

{ "event": "bts:subscribe", "data": { "channel": "live_trades_btcusd" } }


as a single line of text over the pipe to the child process, which reads
this line from its standard input and forwards it over the Websocket connection
to the server.  The uwsc program that the child process prints an
acknowledgement

Send '{ "event": "bts:subscribe", "data": { "channel": "live_orders_btcusd" } }'


to its standard output and it is sent over the pipe to the main ticker process.
Later, the Web server sends the JSON

{"event":"bts:subscription_succeeded","channel":"live_orders_btcusd","data":{}}


to indicate that subscription to the channel was successful, and the uwsc program
wraps this in some additional text and outputs the following over the pipe to
the main ticker process:

Server message: '{"event":"bts:subscription_succeeded","channel":"live_orders_btcusd","data":{}}'


In the meantime, while the above is going on, the CLI watcher in the main process
concurrently outputs a new prompt for the user on its standard output,
which is printed on the terminal:

ticker>  


Note that the CLI watcher and the bitstamp.net watchers run concurrently and
asynchronously, so, for example, if tracing is enabled (see below),
the order in which the new CLI prompt appears relative to any tracing output
that is printed will be timing-dependent.
The main ticker process maintains a table of watchers that it manages.
The index of a watcher in the table serves as a "watcher ID" that is used to
name the watcher in various operations (e.g. stop or trace).
The CLI watcher always has watcher ID 0.  When a new watcher is created,
it is allocated the least unused watcher ID (i.e. it is allocated the
watcher table slot with the least index that is not already in use).
The watcher table maintains all relevant information about each watcher.
Exactly what all this information is something that you will have to work out,
but at least each entry of the watcher table will contain the process ID of
the watcher process, as well as the file descriptors that the main process
uses to communicate with the watcher process.
The main ticker process relies on the receipt of a SIGCHLD signal to
inform it that a watcher process has terminated.  As part of its initialization,
the main process will therefore need to set up a handler for SIGCHLD signals.
When such a signal is received, the main process will use the waitpid()
system call to determine which watcher processes have terminated, and to obtain
their process ID's so that it can be arranged to close file descriptors
and free slots in the watcher table, as well as to free any other memory or
resources that were associated with the watchers that have terminated.
Setting up the signal handlers should be done with the sigaction() system call.
It will be useful to set the SA_SIGINFO flag when the handler is set up.
This enables additional information (structure siginfo_t) to be passed to the handler,
including a code (field si_code) that provides additional information about the
reason for the signal and a field si_fd that indicates the file descriptor
that originated the signal (this is not used for SIGCHLD, but it is used
for the SIGIO signal which you will also need to handle).
For full information, you will have to read the man page for sigaction()
in section 2 of the Linux manual.
Because there can be multiple concurrently executing watchers,
each of which will be sending event information asynchronously to the main
main process, it is not possible for the main process to use "normal"
(synchronous, blocking) I/O to read this event information.
The default behavior of the Unix I/O read() system call is that it will
block (or suspend) the calling process if there is currently no data
to be read.  This is clearly not desirable for the ticker program because,
for example, if the main ticker process were to block awaiting input, say,
from the user, then it would be unable to process any event information
arriving over the network until the user enters a command.
Similarly, the main process cannot commit to reading from the pipe connected
to any particular watcher process, because it is not known when (if ever)
additional input will be available from that process.
In order to work around the limitations of normal synchronous, blocking I/O,
the ticker program will perform I/O in an asynchronous and non-blocking
fashion.  The "non-blocking" part means that when an attempt is made to read
input from a watcher, if no input is available then the read() system call
will return immediately (with an error return and errno set to EWOULDBLOCK),
as opposed to waiting for an indefinite period for input to become available.
The "asynchronous" part means that the ticker program will use signals and
handlers in order to become informed about when input from a watcher has
become available.  Although the desired functionality could be achieved using
only non-blocking I/O, without the associated use of asynchronous I/O
notification via signals it would be necessary for the main ticker process
to waste CPU time running continuously in a "polling loop" checking for input
from each watcher over and over again.  This waste of CPU time is highly
undesirable and your program should not work that way (expect that there will
be grading tests to check for this!).
The ticker program will enable asynchronous I/O notification by arranging
for a SIGIO signal to be sent when a file descriptor becomes
ready for input.  It will install a handler for SIGIO in order to arrange
for input to be read from file descriptors that have become ready.
Installation of the SIGIO handler should be done using sigaction(),
similarly to the way the SIGCHLD handler is installed.
To enable asynchronous I/O notification on a file descriptor,
three things need to be done:
(1) Asynchronous I/O notification needs to be set on the file descriptor,
using the fcntl() system call with command F_SETFL and argument
O_ASYNC;
(2) The fcntl() system call has to be used on that file descriptor with
command F_SETOWN to identity the process to which I/O notifications for
that file descriptor should be sent;
(3) The fcntl() system call has to be used
on that file descriptor with command F_SETSIG to designate
SIGIO as the signal to be sent as the asynchronous I/O notification.
This third step is necessary for the SA_SIGINFO flag set on the signal handler
to cause the si_fd field of the siginfo_t structure to be populated
with the file descriptor that originated the SIGIO.
Note that fcntl() system call is also what is used to set non-blocking I/O
on a file descriptor; this is done using command F_SETFL with argument
O_NONBLOCK.
Once the signal handlers have been installed and the appropriate modes
set on the file descriptors, the normal operation of the ticker program
is to execute in a "main loop" in which there is a call to sigsuspend().
The sigsuspend() system call temporarily unmasks signals that it is
desired to receive, and then suspends execution of the calling process until
one such signal has in fact been received.  This suspension of execution is
what avoids the continuous consumption of CPU cycles in polling file
descriptors to determine if they are ready for I/O.  Once a signal has
been received, the sigsuspend() system call returns and then the body
of the main loop performs any actions (such as reading from file descriptors
or handling termination of child processes) that are required.
Input is read from file descriptors until an error return with errno
set to EWOULDBLOCK is observed, at which point it is known
that all the available input has been consumed.  Once all input has been
consumed and processed, control returns to sigsuspend() and execution is
suspended again until the next signal is received.

Watcher Types
Ticker has been designed using an architecture that makes it possible to
use the same mechanism for performing asynchronous, non-blocking I/O for
user input as is used for watcher processes.  In addition, the architecture
makes it to support "drivers" for multiple kinds of network data feeds,
though for this assignment you only need to worry about access to Bitstamp
using the uwsc Websocket client.
The way ticker supports multiple "drivers" is using the notion of a
watcher type.  The header file ticker.h defines type
struct watcher_type as follows:

typedef struct watcher_type {
    char *name;
    char **argv;
    struct watcher *(*start)(struct watcher_type *type, char *args[]);
    int (*stop)(WATCHER *wp);
    int (*send)(WATCHER *wp, void *msg);
    int (*recv)(WATCHER *wp, char *txt);
    int (*trace)(WATCHER *wp, int enable);
} WATCHER_TYPE;


Each instance of the watcher_type structure defines something roughly
analogous to what a "class" would be used for in an object-oriented language.
The field name is a "class variable" that gives the name of the watcher type.
The field argv provides the name of an executable (in argv[0]) and additional
arguments to pass to that executable via execvp().
The remaining fields are pointers to "methods".
There is a start method, which is in essence a constructor for initializing
an instance of the watcher type.
The stop method is used to terminate a previously constructed instance.
The send method is used to output a command or other information to the watcher
instance.
The recv method is used to input asynchronous data from the watcher and act on it.
Finally the trace method is used to enable or disable tracing of asynchronous
messages received from the watcher instance.
The file watchers.c contains an entry for each of the watcher types that are
configured into ticker.  In the basecode, there are only two such watcher types:
CLI and bitstamp.net, and these are the ones you are responsible for implementing.
However, you should not assume that these are the only watcher types that might exist.
During grading, we will likely add one or more additional watcher types to test
aspects of the operation of the rest of your program.
The is no predetermined fixed size for the watcher type table.  Instead, the end
of the table is signalled by an entry whose fields are all set to 0.
To create an instance of a particular watcher type (e.g. in response to a CLI
start command) the watcher type has to first be looked up by name in the
watcher_types table.
Then, the start method of the watcher type has to be invoked, passing
as a parameter a pointer to the watcher type itself as the type argument,
and possibly passing a pointer to an additional vector of arguments as args
(any such arguments are above and beyond the fixed arguments given in the
argv field of the watcher type).
For example, the bitstamp.net watcher type will expect args[0] to contain a string
that specifies the name of a channel (e.g. live_trades_btcusd) to connect to,
once uwsc has been started and the Websocket connection has been made.
The CLI watcher type does not expect any additional arguments, and NULL
may be passed.
Once a watcher instance has been started using start, the other methods
may be used to operate on the instance.  Each method requires that a pointer
of type WATCHER * (aka struct watcher *) be passed; this corresponds to the
implicit parameter this in object-oriented languages.  The actual format of
struct watcher is unspecified; it is up to you to define it.  For the command-line
interface, you must also implement some way for a WATCHER to be looked up by
its index in the table of watcher instances.  How this is done depends on how
you choose to represent this table.
The msg argument to send can be a pointer to any type of value or even NULL,
depending on the needs of a particular watcher type.  For example, for the CLI
watcher type this will be a prompt to be shown to the user.  For the bitstamp.net
watcher type this could be a textual or other representation of a JSON command
to be sent to the server.
The txt argument to recv is a line of text received from the watcher instance.
For example, for the CLI watcher type this will be a command line typed by the user.
For the bitstamp.net watcher type this will be a line of text received from
the watcher process running uwsc.
The enable argument to trace is a boolean value that determines whether
tracing is to be enabled (nonzero) or disabled (zero).
You are required to manipulate watcher instances only by calling the specific
methods provided by the watcher type.  In particular, you may not introduce
any other functions that "do things to" watcher instances.  This is because
during grading we might decide to track calls to watcher methods to get some
idea of what your program is doing.
However, the interface between the watcher methods and the rest of ticker
is not specified, so within the implementation of the specified watcher methods
you may assume that you have have arbitrary access to any other part of the state
of ticker.

The Data Store
For accumulating event information provided by watchers, I have provided a
binary implementation of a rudimentary "data store", which implements a simple
key/value mapping.  The interface of the data store is given in store.h.
The store_put() function is used to introduce a new key/value mapping
in the store, or to delete or replace the value already associated with a
given key.
The store_get() function is used to retrieve a value previously associated
with a key.  The value returned by store_get() is a heap-allocated value,
which it is the caller's responsibility to free using store_free_value()
when it is no longer required.
Exactly what you should put in the store is specified elsewhere in this document.
The general idea is that you will be accumulating information, such as last
trade prices, trade volume, and so on, and these will be associated in the store
with keys of a specific format.  The grading tests will retrieve the values
associated with these keys at various points, to check whether your program is
functioning properly.

The 'Argo' Parser
Communication between Websocket clients and servers typically uses JSON to
encode represent requests and responses.  Information about JSON syntax
can be found at www.json.org.
So that you can focus on the central issues of this assignment, which are
processes and signal handling, I have provided (in binary form) a JSON parser
for you to use.  This parser, called argo, was written by me in the context
of an assignment given in this course in a previous semester.
The interface of the argo parser is given in the header file argo.h.
For simplicity, I have hidden most of the functions and the details of the
data structure used to represent JSON expressions, and have exposed only the
part that you really need to use for the current assignment.
The code defines a type ARGO_VALUE, which is the data type used to represent
a JSON expression.  The functions provided for creating an ARGO_VALUE object is:


ARGO_VALUE *argo_read_value(FILE *f):
This function parses JSON code read from an input stream and produces an
ARGO_VALUE object that represents the parsed JSON expression.

The following function can be used to convert an ARGO_VALUE object back
to JSON form:


int argo_write_value(ARGO_VALUE *vp, FILE *f, int pretty):
This function unparses an ARGO_VALUE object and emits JSON code
to an output stream, possibly with "pretty-printing" applied to make
the result more human-readable.

Since ARGO_VALUE objects are data structures allocated from the heap,
there needs to be a way to free them:


void argo_free_value(ARGO_VALUE *vp):
This function is used to dispose of an ARGO_VALUE that is no longer
required.

The details of the ARGO_VALUE data structure are not exposed.
However, there are several functions provided for "deconstructing"
an ARGO_VALUE object to determine its structure and extract the
information that it contains.  See the argo.h header file for
more details about these.

What You are to Do
The general requirement for this assignment is to implement the
ticker program within the context of the provided skeleton.
The completed program should provide a function ticker() which
performs initialization and then starts a main loop to manage watchers,
as outlined above.  The main loop should execute until a quit
command has been received and executed by the command-line interface,
as described in more detail below.
The completed program should also provide implementations of the
methods for the two watcher types that are mentioned in the
watcher_types table in the base code; namely the CLI command-line
interface watcher and the
bitstamp.net Bitstamp Websocket watcher.

The CLI Watcher Type
When started, the command-line interface watcher shall print a prompt
for the user to the standard output.  The prompt shall be exactly of
the form ticker>, followed by a single space and without any newline.
After printing the prompt, the command-line interface watcher shall
read a line of of input typed by the user, attempt to interpret it
as a command, and execute it.  Any output required to be produced
as a result of successfully executing the command shall be printed to the
standard output as complete lines of text, followed by a prompt for the
next user command.
Should parsing or execution of a command result in an error,
then ??? shall be printed to the standard output, followed by
a single newline and then a prompt for the next user command.
The structure of a command line is a sequence of "words",
which consist of non-whitespace chararacters, delimited by sequences
of whitespace characters.  The first word is the name of a command
to be executed; the remaining words are arguments to the command.
The following commands and arguments shall be supported:


quit - Terminate the ticker program gracefully, after first
terminating any active watchers and waiting for the associated
child processes to terminate.  Note that simply calling exit()
does not count as "graceful termination" of the ticker program.


watchers - Print a list of the active watchers to the standard output,
one per line, using the exact format shown in the examples above:

0	CLI(-1,0,1)
1	bitstamp.net(404756,3,6) uwsc wss://ws.bitstamp.net [live_trades_btcusd]
2	bitstamp.net(404765,4,8) uwsc wss://ws.bitstamp.net [live_trades_btcgbp]


The first field is the watcher ID, which is the index of the
watcher in the watcher table.  The watchers should be listed in increasing
order of watcher ID, as shown.
Following the watcher ID is a single TAB ('\t') character.
Following that is the name of the watcher type for the watcher, taken directly
from the name field of the WATCHER_TYPE structure that defines
that watcher type.
Following the watcher type name are three numbers enclosed in parentheses
and separated by commas as shown.  The first number is the process ID of the
child process that is executing the watcher, if any, otherwise -1.
The second number is the file descriptor being used by the main ticker process
to read input from the watcher.
The third number is the file descriptor being used by the main ticker process
to write output to the watcher.
Following the parenthesized numbers is a single space (' ') character.
After the space comes the sequence of arguments from the argv[] vector,
taken directly from the WATCHER_TYPE structure and separated from
each other by a single space character.
Finally, there is a single space, followed by the sequence of strings
from the args[] additional arguments vector that was provided when the
watcher instance was created.  These strings are also separated by a single
space character, and the whole seqence is enclosed in square brackets:
('[' and ']').


start - This command takes at least one argument, which is the name of
a watcher type for which an instance is to be started.  There may be
additional arguments, which are provided as the args[] argument to
the start method for the watcher type.  The effect of this command is
to start an instance of the specified watcher type.  The new watcher
shall be assigned the least watcher ID that is not already in use.


stop - This command takes a single argument, which is the watcher ID
of a watcher to be stopped.  The specified watcher is marked as "terminated",
and any associated child process is sent a SIGTERM signal to request it to
terminate.  The watcher will remain in the watcher table until it has been
verified that the child process has actually terminated, at which point
its watcher ID will become available for use by a subsequently started
watcher instance.
Note: an attempt to stop the CLI watcher instance shall be an error.


trace - This command takes a single argument, which is the watcher number
of a watcher instance to be traced.  The effect of the command is to enable
tracing for that watcher.  Tracing a watcher means that each line of input received
from that watcher is printed to the standard error output, in exactly
the format shown in the examples above:

[1679233551.535374][bitstamp.net][ 3][   35]: Server message: '{"data":{"id":277351788,"timestamp":"1679233551","amount":0.00082,"amount_str":"0.00082000","price":27256,"price_str":"27256","type":0,"microtimestamp":"1679233551474000","buy_order_id":1599072570642432,"sell_order_id":1599072570363904},"channel":"live_trades_btcusd","event":"trade"}'



The first item in the output is a timestamp (enclosed in square brackets)
representing the current date and time,
as obtained by calling the function clock_gettime() with the CLOCK_REALTIME
option.  The time is printed in the form seconds.microseconds, where seconds
is the value of the tv_sec field of the struct timespec returned from
clock_gettime() and microseconds is the value of the tv_nsec field of
the struct timespec field, divided by 1000.  The microseconds field should
be exactly six spaces in width, the value should be right-justified within the
field and it should be padded on the left with leading zeros in case the value
would otherwise not have six digits.
The second item (also enclosed in square brackets) is the name of the watcher
type for the particular watcher instance that is producing the trace output.
The third item (also enclosed in square brackets) is the file descriptor
being used by the ticker program to read input from the particular watcher
instance that is producing the trace output.
The fourth item (also enclosed in square brackets) is the serial number of
the line of input for which the trace output is being generated.  The first
line of input received by a watcher instance after being started shall have
serial number 1, the second line shall have serial number 2, and so on.
Following the preceding items shall be a single colon (':') character,
followed by a single space.  The remainder of the line shall consist of the
line of data input from the watcher, exactly as it was received by the
main ticker process.


untrace - This command takes a single argument, which is the watcher number
of a watcher instance to be untraced.  The effect of the command is to disable
tracing for that watcher instance.


show - This command takes a single argument, which is a key to be looked up
in the data store.  If the store currently contains a value associated with
that key, then the value is displayed in a single line printed to standard output,
in the following format:

 bitstamp.net:live_trades_btcusd:price	27256.000000


The first field of the output is the key.  This is followed by a TAB
character ('\t') and then the value associated with the key.
If the store does not contain any value associated with the specified key,
it shall be an error.



The bitstamp.net Watcher Type
For the bitstamp.net watcher type, you are to provide implementations for
each of the watcher methods.  When started (using the start() method),
the watcher shall create a child process to run the uwsc program to manage
the Websocket connection to the server.  The recv method shall examine each
line of txt it is passed, to determine whether it has the form
Server message: '...'.  If so, then an attempt shall be made to interpret the
text occurring between the single quotes as JSON code.  If parsing of this code
is successful, then the result shall be examined to determine if it is a
JSON "object" having a field named event with value trade.
If so, then the value of the price and amount fields shall be extracted
and used to update the data store in the following way.
The value of the key bitstamp.net:live_trades_XXXYYY:price shall be updated
to the value of the price field in the received event.
Here XXXYYY is the 6-character string (such as btcusd) that represents the
currency pair being watched.
The value of the key bitstamp.net:live_trades_XXXYYY:volume shall be updated
to be the sum of its previous value (or 0.0 if this is the first update)
and the value of the amount field in the received event.

Suggested Plan of Attack
To have the greatest likelihood of being able to submit something that
has at least some testable correct functionality, it is suggested that you
attack this assignment in an incremental fashion, as described below.
Start with a small skeleton of the core portion of the ticker program.
This will consist of an initialization section and a basic main loop
that uses sigsuspend() to suspend execution while waiting for a signal.
Determine that this works properly; for example, by installing a handler
for SIGINT and verifying that the handler is actually invoked when CTRL-c
is typed at the terminal or the kill -INT is used to send the SIGINT
signal from the command line at another terminal.
Install a handler for SIGCHLD and then work with fork() and execvp()
until you can reliably create child processes that run another program
(such as uwsc), you can terminate these processes
(e.g. by using kill() system call or the kill shell command),
and you can detect their termination via the receipt of the SIGCHLD signal
and reap them using waitpid().
Install a handler for SIGIO and then set asynchronous I/O
on the standard input.  Demonstrate that entering a line of input on the
terminal causes a SIGIO signal to be received and the handler to be invoked.
Set non-blocking I/O on the standard input and modify the way you read
the standard input so that it stops trying to read once an error is returned
with errno set to EWOULDBLOCK.
There is an additional level of complication here, because it is not
guaranteed that an entire line of input will be available each time you
receive SIGIO.
In order to work around this, you will need to arrange to buffer partial
lines of input, so that a partial line can be read until all the currently
available input has been consumed, and then the rest of the line can be read later,
when a subsequent receipt of SIGIO has indicated that more input is
available.
Although you could use a fixed-size buffer to hold a partially accumulated
input line, this requires making an a priori decision about the maximum
length of an input line.  A better approach would be to allow the input buffer
to grow dynamically as it is filled.  You can code such a mechanism yourself
by directly calling realloc() to increase the size of the input buffer as needed.
Alternatively, you might wish to consider using the somewhat more convenient
open_memstream() library function, which handles the reallocation automatically
and which provides a FILE * pointer with which you can use normal standard I/O
output functions such as fprintf().
A related function that you might find useful is fmemopen(), which is used
to wrap an in-memory buffer in a FILE object.  This will make it possible to
use standard I/O input functions such as fgetc() or fgets() on in-memory data.
At this point, you will have enough mechanism and understanding available that
you can complete the coding of the CLI watcher type; at least up to the point
of being able to use asynchronous, non-blocking I/O to read lines of input from
the terminal, parsing them as commands, and dispatching to stub functions to
"execute" the commands.  Since you have already understood how to create and
manage child processes, you should be able to implement at least part of the
functionality of commands such as start, stop, and quit.
To implement the full functionality of these commands, you will have to make
some decisions about the data structures you are going to use to manage the
collection of watcher processes.
You should now be able to go on and arrange for pipes and the I/O redirection
of the child processes.  File descriptors used for input by the main ticker
process will have to be configured for asynchronous, non-blocking I/O,
just as was used for user input.
Finally, you will be in a position to complete the "driver" code for the
Bitstamp watcher.

Demonstration Program
I have found that students seem to understand better what they are to do
and have fewer questions about it, when I provide some kind of executable
demonstration version of the program that I am asking them to implement.
For this reason, I have included with the base code an executable binary
of the demonstration program (demo/ticker) that I wrote while developing
this assignment.
You might find it helpful to run this program and compare its behavior
with the specifications in this document.  I do not guarantee that it
is bug-free, or that its behavior exactly conforms to what is specified
here.  In case of any discrepancy, the written specifications in this
document shall take precedence over any behavior exhibited by the
demonstration program.
Please note that the demonstration program is provided only for you to
execute as an aid to your understanding of what I am asking you to do.
It is not intended that you should attempt to deconstruct the binary
or reverse-engineer source code from it.  In the end, you are to write
your own code for this assignment.
Any evidence that source code you submit for this assignment has been
reverse-engineered from the binary demonstration version I have provided
will be considered as evidence of Academic Dishonesty and will result in
charged being filed against you.

Hand-in instructions
As usual, make sure your homework compiles before submitting.
Test it carefully to be sure that doesn't crash or exhibit "flaky" behavior
due to race conditions.
Use valgrind to check for memory errors and leaks.
Besides --leak-check=full, you might also want to look into the
valgrind --trace-children and related options.
Submit your work using git submit as usual.
This homework's tag is: hw4.
