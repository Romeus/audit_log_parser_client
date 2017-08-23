Implement a simple Audit D log parser, using the AuditD API to fetch, process and forward AuditD messages to an HTTP/2 API interface.
The implementation should be able to fetch events from AuditD, parse the event into a JSON object, and pass the log to a network host for processing.
The interface should be non-blocking to the system, and forward any log information to the collection interface in a very performant manner.
Any included libraries should reference reasoning behind the specific selection, and assumptions for the API side should be noted.

Mandatory:

- The implementation should be built in C, and leverage compatibility of early AuditD API features
- The program should restart if there is a failure

Optional:

- The program should be hidden from the system process list
- The program should protect itself from being stopped by a standard user.

Testing:

To test, we should be able to use a simple netcat session, listening on port 8888

===================================================================

Prerequisites

I tested that project on centos 7.0.

$ uname -r
> 3.10.0-514.6.2.el7.x86_64


Before you compile it you need to install the following libraries:

$ sudo yum install json-c jsonc-devel json-c-doc audit libcurl-devel

If your linux distributive doesn't include libcur and nghttp libraries that support http2 version you should install them from third-party repositories or build it from source.

For example on cent os you should follow those instructions:

http://mor-pah.net/2017/06/21/installing-curl-with-http2-support-on-centos-7-self-contained/

After the libraries is built you should do the following:

$ echo '/usr/local/lib' > /etc/ld.so.conf.d/custom-libs.conf

Then switch to the branch 'custom-lib' of that repository before do the next step.


===================================================================

Installation

Clone that project to a folder, go there and type:

$ make

The build result is a binary executable:

audit_log_parser_client

if you want to rebuild the project you should do:

$ make clean

$ make

===================================================================

How to test it

There is a slightly modified simple http server obtained from here:
https://gist.github.com/huyng/814831

All you need to do is make it executable using (you should do it once,
after the repository was cloned:

$ chown +x reflect.py

Then you should run it in a first terminal tab:

$ ./reflect.py

In a second tab run the client:

$ sudo ./audit_log_parser_client

Go to the first tab and see all the audit records that were received
by the server
