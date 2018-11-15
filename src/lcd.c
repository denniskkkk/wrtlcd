#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <stdlib.h>
#include <assert.h>
#include <fcntl.h>
#include <termios.h>
#include <signal.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <regex.h>
#include <sys/time.h>
#include <fnmatch.h>
#include <dirent.h>
#include <pthread.h>
#include <sys/fcntl.h>
#include <sys/file.h>
#include <stdlib.h>
#include <ftdi.h>
#include <math.h>
#include <event2/event_struct.h>
#include <event2/event-config.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#include <event2/event.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#include <sys/queue.h>

#include "lglcd.h"
#include "gfont.h"

//#define DEBUG

unsigned char buf[65536];
unsigned char buf1[65536];

unsigned char rbuf[65536];
unsigned char rbuf1[65536];

typedef void (*t_sighup_handler)(void);
static t_sighup_handler user_sighup_handler = NULL;
static int got_sighup = 0;
int pid;
int daemonized = 0;

unsigned int delay = 50; // scanning delay time in msec 50 msec

struct ftdi_context ftdic, ftdic1;
struct ftdi_context ftdic_b, ftdic1_b;

unsigned long errcount = 0L;

char uri_root[1024];

// global threads
pthread_t thread[15];

// PRA port thread
pthread_mutex_t pra_mutex;
pthread_cond_t pra_cond;
pthread_attr_t pra_attr;

// PRB thread attr
pthread_attr_t prb_attr;

// PRC thread attr
pthread_attr_t prc_attr;

// ProcCom1 thread attr
pthread_attr_t com1_attr;

// ProcCom2 thread attr
pthread_attr_t com2_attr;

// Server thread attr
pthread_attr_t setupServer_attr;

// ProcKey thread attr
pthread_attr_t key_attr;

// procB thread
pthread_mutex_t procb_mutex;
pthread_cond_t procb_cond;
pthread_attr_t procb_attr;

// lcd lock
pthread_mutex_t lcdprint_mutex;
pthread_mutex_t lcdprintw_mutex;

// message queue mutex all qm0-7
pthread_mutex_t qm[8];

// message log mutex for all qm0-7
pthread_mutex_t qlog[8];

#define digitregex  "[^0-9]"

#define TRUE 1
#define FALSE 0

int checktext(const char *find_text, const char *regex_text) {
	regex_t r;
	const char * p;
	const int n_matches = 10;
	regmatch_t m[n_matches];
	p = find_text;

	int status = regcomp(&r, regex_text, REG_EXTENDED | REG_NEWLINE);
	int nomatch = regexec(&r, p, n_matches, m, 0);
	if (nomatch) {
		regfree(&r);
		return TRUE; // no non number in text
	} else {
		regfree(&r);
		return FALSE; // some non number in text
	}
}

static void send_document_cb(struct evhttp_request *req, void *arg) {
	if (req == NULL
	)
		return;
	struct evbuffer *evb = NULL;
	const char *uri = evhttp_request_get_uri(req);
	struct evhttp_uri *decoded = NULL;
	struct evhttp_uri *euri;
	const char *path;
	char *decoded_path;
	struct timeval vt;
	time_t stime;
	struct tm stm;
	struct evkeyvalq keys;
	const char *c1, *c2, *c3, *c4;
	int n1 = 0, n2 = 0, n3 = 0, n4 = 0;
	char str[128];
	// get system time
	gettimeofday(&vt, NULL);
	time(&stime);
	stm = *localtime(&stime);

	decoded = evhttp_uri_parse(uri);

	if (!decoded || decoded == NULL) {
		printf("BADREQUEST URI\n");
		evhttp_send_error(req, HTTP_BADREQUEST, REG_ICASE);
		return;
	}

	path = evhttp_uri_get_path(decoded);
	if (path == NULL) {
		goto err;
	}
	if (!path) {
		goto err;
	}
	decoded_path = evhttp_uridecode(path, 0, NULL);
	// printf("decoded path = %s\n", decoded_path);
	if (decoded_path == NULL) {
		return;
	}
	if (strstr(decoded_path, "..")) {
		goto err;
	}
	if (checktext(decoded_path, "/7705/")) { // initial command id
		goto err;
	}
	// create reply message----------------
	evb = evbuffer_new();
	evbuffer_add_printf(evb, "~~~~~~\n");
	evbuffer_add_printf(evb, "timestamp=%lu\n",
			vt.tv_sec * 1000000 + vt.tv_usec);
	evbuffer_add_printf(evb, "datetime=%02d-%02d-%04d %02d:%02d:%02d\n",
			stm.tm_mday, stm.tm_mon + 1, stm.tm_year + 1900, stm.tm_hour,
			stm.tm_min, stm.tm_sec);
	// parse parameter in uri_root
	int q = evhttp_parse_query(uri, &keys);
	//printf("parse query %s\n", uri);
	if (q == 0 && keys.tqh_first != NULL && keys.tqh_last != NULL) {
		if (strstr(decoded_path, "/7705/WRITE")) { // command write
			evbuffer_add_printf(evb, "writecommand\n");
			c1 = evhttp_find_header(&keys, "control01");
			if (c1 != NULL) {
				evbuffer_add_printf(evb, "c1=0X%04x\n",
						(checktext(c1, digitregex)) ? n1 = atol(c1) : -1);
					}
			c2 = evhttp_find_header(&keys, "control02");
			if (c2 != NULL) {
				evbuffer_add_printf(evb, "c2=0X%04x\n",
						(checktext(c2, digitregex)) ? n2 = atol(c2) : -1);
					}
			c3 = evhttp_find_header(&keys, "control03");
			if (c3 != NULL) {
				evbuffer_add_printf(evb, "c3=0X%04x\n",
						(checktext(c3, digitregex)) ? n3 = atol(c3) : -1);
					}
			c4 = evhttp_find_header(&keys, "control04");
			if (c4 != NULL) {
				evbuffer_add_printf(evb, "c4=0X%04x\n",
						(checktext(c4, digitregex)) ? n4 = atol(c4) : -1);
					}
			// lcd display
			sprintf(str, "%04X,%04X,%04X,%04X\0", n1, n2, n3, n4);
			//printf ("%s", str);
			pthread_mutex_lock(&lcdprint_mutex);
			printLine(0, 7, 0, str, 1); // print time
			pthread_mutex_unlock(&lcdprint_mutex);
				}
			}
	if (strstr(decoded_path, "/7705/READ")) { // command read
		evbuffer_add_printf(evb, "readcommand\n");
		evbuffer_add_printf(evb, "n1=0x0000\n");
		evbuffer_add_printf(evb, "n2=0x0001\n");
		evbuffer_add_printf(evb, "n3=0x0002\n");
		evbuffer_add_printf(evb, "n4=0x0003\n");
	}
	if (strstr(decoded_path, "/7705/RESET")) { // command reset
		evbuffer_add_printf(evb, "resetcommand\n");
	}
	if (strstr(decoded_path, "/7705/RELOAD")) { // command reload
		evbuffer_add_printf(evb, "reloadcommand\n");
	}
	if (strstr(decoded_path, "/7705/INITSYS")) { // command init system
		evbuffer_add_printf(evb, "initsyscommand\n");
	}
	// serial port command
	if (strstr(decoded_path, "/7705/TXPORT0")) { // command to port 0
		evbuffer_add_printf(evb, "port0command\n");
		c1 = evhttp_find_header(&keys, "message");
		if (c1 != NULL) {
			            int st = addMessage (c1,strlen(c1),0);
			            evbuffer_add_printf(evb, "message=%s\n",c1);
			            if (st >= 0) {
			            	 evbuffer_add_printf(evb, "size=%d\n",st);
			            } else {
			            	 evbuffer_add_printf(evb, "bufferfull\n");
			            }
						}
	}
	if (strstr(decoded_path, "/7705/TXPORT1")) { // command to port 1
		evbuffer_add_printf(evb, "port1command\n");
	}
	if (strstr(decoded_path, "/7705/TXPORT2")) { // command to port 2
		evbuffer_add_printf(evb, "port2command\n");
	}
	if (strstr(decoded_path, "/7705/TXPORT3")) { // command to port 3
		evbuffer_add_printf(evb, "port3command\n");
	}
	if (strstr(decoded_path, "/7705/TXPORT4")) { // command to port 4
		evbuffer_add_printf(evb, "port4command\n");
	}
	if (strstr(decoded_path, "/7705/TXPORT5")) { // command to port 5
		evbuffer_add_printf(evb, "port5command\n");
	}
	if (strstr(decoded_path, "/7705/TXPORT6")) { // command to port 6
		evbuffer_add_printf(evb, "port6command\n");
	}
	if (strstr(decoded_path, "/7705/TXPORT7")) { // command to port 7
		evbuffer_add_printf(evb, "port7command\n");
	}
	// get serial port status
	if (strstr(decoded_path, "/7705/RXPORT0")) { // status from port 0
		evbuffer_add_printf(evb, "port0status\n");
	}
	if (strstr(decoded_path, "/7705/RXPORT1")) { // status from port 1
		evbuffer_add_printf(evb, "port1status\n");
	}
	if (strstr(decoded_path, "/7705/RXPORT2")) { // status from port 2
		evbuffer_add_printf(evb, "port2status\n");
	}
	if (strstr(decoded_path, "/7705/RXPORT3")) { // status from port 3
		evbuffer_add_printf(evb, "port3status\n");
	}
	if (strstr(decoded_path, "/7705/RXPORT4")) { // status from port 4
		evbuffer_add_printf(evb, "port4status\n");
	}
	if (strstr(decoded_path, "/7705/RXPORT5")) { // status from port 5
		evbuffer_add_printf(evb, "port5status\n");
	}
	if (strstr(decoded_path, "/7705/RXPORT6")) { // status from port 6
		evbuffer_add_printf(evb, "port6status\n");
	}
	if (strstr(decoded_path, "/7705/RXPORT7")) { // status from port 7
		evbuffer_add_printf(evb, "port7status\n");
	}
	evbuffer_add_printf(evb, "commandend\n");
	evhttp_add_header(evhttp_request_get_output_headers(req), "Content-Type",
			"text/text");
	evhttp_send_reply(req, 200, "OK", evb);
	//---------------
	goto done;
	err:
	    //evbuffer_add_printf (evb, "error\n");
	    evhttp_send_error(req, 404, "ERRORcommand\n");
	done: if (decoded)
		evhttp_uri_free(decoded);
	if (decoded_path)
		free(decoded_path);
	if (evb)
		evbuffer_free(evb);
}

int startServer() {
	struct event_base *base;
	struct evhttp *http;
	struct evhttp_bound_socket *handle;

	unsigned short port = 9000;

	base = event_base_new();
	if (!base) {
		fprintf(stderr, "error base\n");
		return 1;
	}

	/* Create a new evhttp object to handle requests. */
	http = evhttp_new(base);
	if (!http) {
		fprintf(stderr, "error evhttp\n");
		return 1;
	}

	//evhttp_set_allowed_method (http, EVHTTP_REQ_GET | EVHTTP_REQ_POST | EVHTTP_REQ_DELETE);

	evhttp_set_gencb(http, send_document_cb, "/");

	/* Now we tell the evhttp what port to listen on */
	handle = evhttp_bind_socket_with_handle(http, "0.0.0.0", port);
	if (!handle) {
		fprintf(stderr, "error port %d\n", (int) port);
		return 1;
	}
	/*-----------------
	 {
	 struct sockaddr_storage ss;
	 evutil_socket_t fd;
	 ev_socklen_t socklen = sizeof(ss);
	 char addrbuf[128];
	 void *inaddr;
	 const char *addr;
	 int got_port = -1;
	 fd = evhttp_bound_socket_get_fd(handle);
	 memset(&ss, 0, sizeof(ss));
	 if (getsockname(fd, (struct sockaddr *) &ss, &socklen)) {
	 perror("getsockname() failed");
	 return 1;
	 }
	 if (ss.ss_family == AF_INET) {
	 got_port = ntohs(((struct sockaddr_in*) &ss)->sin_port);
	 inaddr = &((struct sockaddr_in*) &ss)->sin_addr;
	 } else if (ss.ss_family == AF_INET6) {
	 got_port = ntohs(((struct sockaddr_in6*) &ss)->sin6_port);
	 inaddr = &((struct sockaddr_in6*) &ss)->sin6_addr;
	 } else {
	 fprintf(stderr, "Weird address family %d\n", ss.ss_family);
	 return 1;
	 }
	 addr = evutil_inet_ntop(ss.ss_family, inaddr, addrbuf, sizeof(addrbuf));
	 if (addr) {
	 printf("Listening on %s:%d\n", addr, got_port);
	 evutil_snprintf(uri_root, sizeof(uri_root), "http://%s:%d", addr,
	 got_port);
	 } else {
	 fprintf(stderr, "ntop failed\n");
	 return 1;
	 }
	 } */
	//---------------------
	event_base_dispatch(base);
	return 0;
}

void *setupServer() {
	printf ("server\n");
	startServer();
}

struct timeval lasttime;
static void timeout_cb(evutil_socket_t fd, short event, void *arg) {
	struct timeval newtime, difference;
	struct event *timeout = arg;
	double elapsed;
	char strb[128];

	evutil_gettimeofday(&newtime, NULL);
	evutil_timersub(&newtime, &lasttime, &difference);
	elapsed = difference.tv_sec + (difference.tv_usec / 1.0e6);
	sprintf(strb, "E2:%.5fsec\0", elapsed);
	//printf("%s\n", strb);
	//
	pthread_mutex_lock(&lcdprint_mutex);
	printLineW(0, 3, 0, strb, 1); // print time
	pthread_mutex_unlock(&lcdprint_mutex);
	//
	lasttime = newtime;
	//
	struct timeval tv;
	evutil_timerclear(&tv);
	tv.tv_sec = 0;
	tv.tv_usec = 5000; // 5 msec
	event_add(timeout, &tv);

}

// event 1
struct timeval lasttime1;
static void timeout_cb1(evutil_socket_t fd, short event, void *arg) {
	struct timeval newtime, difference;
	struct event *timeout = arg;
	double elapsed;
	char strb[128];

	evutil_gettimeofday(&newtime, NULL);
	evutil_timersub(&newtime, &lasttime1, &difference);
	elapsed = difference.tv_sec + (difference.tv_usec / 1.0e6);
	sprintf(strb, "E3:%.5fsec\0", elapsed);
	//printf("%s\n", strb);
	//
	pthread_mutex_lock(&lcdprint_mutex);
	printLineW(0, 4, 0, strb, 1); // print time
	pthread_mutex_unlock(&lcdprint_mutex);
	//
	lasttime1 = newtime;
	//
	struct timeval tv;
	evutil_timerclear(&tv);
	tv.tv_sec = 0;
	tv.tv_usec = 20000; // 20 msec
	event_add(timeout, &tv);

}

// event 2
struct timeval lasttime2;
static void timeout_cb2(evutil_socket_t fd, short event, void *arg) {
	struct timeval newtime, difference;
	struct event *timeout = arg;
	double elapsed;
	char strb[128];

	evutil_gettimeofday(&newtime, NULL);
	evutil_timersub(&newtime, &lasttime2, &difference);
	elapsed = difference.tv_sec + (difference.tv_usec / 1.0e6);
	sprintf(strb, "E4:%.5fsec\0", elapsed);
	//printf("%s\n", strb);
	//
	pthread_mutex_lock(&lcdprint_mutex);
	printLineW(0, 5, 0, strb, 1); // print time
	pthread_mutex_unlock(&lcdprint_mutex);
	//
	lasttime2 = newtime;
	//
	struct timeval tv;
	evutil_timerclear(&tv);
	tv.tv_sec = 0;
	tv.tv_usec = 100000; // 70 msec
	event_add(timeout, &tv);

}

void *testPRA() {
	struct event timeout;
	struct timeval tv;
	struct event_base *base;
	int flags;
	//wait start signal
	//pthread_cond_wait (&pra_cond, &pra_mutex);
	flags = EV_PERSIST;
	/* Initalize the event library */
	base = event_base_new();
	/* Initalize one event */
	event_assign(&timeout, base, -1, flags, timeout_cb, (void*) &timeout);
	evutil_timerclear(&tv);
	tv.tv_sec = 0;
	tv.tv_usec = 100000; // 100msec
	event_add(&timeout, &tv);
	evutil_gettimeofday(&lasttime, NULL);
	event_base_dispatch(base);
}

void *testPRB() {
	struct event timeout;
	struct timeval tv;
	struct event_base *base;
	int flags;
	flags = EV_PERSIST;
	/* Initalize the event library */
	base = event_base_new();
	/* Initalize one event */
	event_assign(&timeout, base, -1, flags, timeout_cb1, (void*) &timeout);
	evutil_timerclear(&tv);
	tv.tv_sec = 0;
	tv.tv_usec = 100000; // 100msec
	event_add(&timeout, &tv);
	evutil_gettimeofday(&lasttime1, NULL);
	event_base_dispatch(base);
}

void *testPRC() {
	struct event timeout;
	struct timeval tv;
	struct event_base *base;
	int flags;
	flags = EV_PERSIST;
	/* Initalize the event library */
	base = event_base_new();
	/* Initalize one event */
	event_assign(&timeout, base, -1, flags, timeout_cb2, (void*) &timeout);
	evutil_timerclear(&tv);
	tv.tv_sec = 0;
	tv.tv_usec = 100000; // 100msec
	event_add(&timeout, &tv);
	evutil_gettimeofday(&lasttime2, NULL);
	event_base_dispatch(base);
}

void *procB() {
	struct timeval tv, tv1, tv2;
	int retval;
	double timemsec;
	char strb[128];
	// wait start signal
	//pthread_cond_wait (&procb_cond, &procb_mutex);
	while (1) {
		gettimeofday(&tv1, NULL);
		tv.tv_sec = 0;
		tv.tv_usec = 50000; // 50.000 usec
		retval = select(1, NULL, NULL, NULL, &tv);
		if (retval == -1) {
			perror("timer error!!!");
		} else if (retval) {
		} else {
			gettimeofday(&tv2, NULL);
			timemsec = ((tv2.tv_sec - tv1.tv_sec) * 1000000
					+ (tv2.tv_usec - tv1.tv_usec));
			sprintf(strb, "E1:%.2fus\0", timemsec);
			//printf("%s\n", strb);
			pthread_mutex_lock(&lcdprint_mutex);
			printLineW(0, 2, 0, strb, 1); // print time
			pthread_mutex_unlock(&lcdprint_mutex);
		}

	}
}

void *procKey() {
	struct timeval tv, tv1, tv2;
	int retval;
	double timemsec;
	char strb[128];
	while (1) {
		gettimeofday(&tv1, NULL);
		tv.tv_sec = 0;
		tv.tv_usec = 100000; // 100.000 usec
		retval = select(1, NULL, NULL, NULL, &tv);
		if (retval == -1) {
			perror("timer error!!!");
		} else if (retval) {
		} else {
			gettimeofday(&tv2, NULL);
			timemsec = ((tv2.tv_sec - tv1.tv_sec) * 1000000
					+ (tv2.tv_usec - tv1.tv_usec));
			sprintf(strb, "Key:%.2fus\0", timemsec);
			//printf("%s\n", strb);
			pthread_mutex_lock(&lcdprint_mutex);
			printLineW(0, 6, 0, strb, 1); // print time
			pthread_mutex_unlock(&lcdprint_mutex);
		}

	}
}

void printhex(unsigned char *tmp2, unsigned int readed) {
	unsigned int z;
	if (readed > 0) {
		printf("readed %d, ", readed);
		for (z = 0; z < readed; z++) {
			printf(":%02X:", tmp2[z]);
		}
		printf("\n");
	}
}
// message structure
struct tailq_entry {
	int id;          // message id
	char data[128];  // message information
	char reply[128]; // reply message
	int size;        // message size in bytes
	int flag;        // 0 = disable, 1 = enable
	int port;        // port number 0-7
	TAILQ_ENTRY(tailq_entry) entries;
};
TAILQ_HEAD (qhead, tailq_entry) mhead;   // head pointer, name = qhead
// init message queue for use
void initMessage (int port) {
	pthread_mutex_lock(&qm[0]);
	TAILQ_INIT ( &mhead);
	pthread_mutex_unlock(&qm[0]);
}

// add message to command process queue, return are reply id
int addMessage (char *message , int size, int port) {
	// queue struct
	struct tailq_entry *item;
	int msgsize = 0;
	pthread_mutex_lock (&qm[port]);
	TAILQ_FOREACH (item , &mhead, entries) {
		if (item == NULL) {
			break;
		}
		msgsize ++;
		if (msgsize > 128 ) {  // max queue size = 128
			msgsize = -1;
			goto status;
		}
	}
	//
	item = malloc(sizeof(*item));
//	printf ("add message to port %d queue message, %s\n", port, message);
	if (item == NULL) {
		perror ("create queue message fails");
		//exit (EXIT_FAILURE);
	}
	sprintf (item->data,"%s", message);
	item->size = size;
	// insert a new item to queue tail
	TAILQ_INSERT_TAIL (&mhead, item, entries);
status:
	pthread_mutex_unlock (&qm[port]);
	return msgsize;
}

int sizeMessage (int port) {
	int size =0;
	struct tailq_entry *item;
	pthread_mutex_lock(&qm[port]);
	TAILQ_FOREACH (item, &mhead, entries) {
		if (item == NULL) {
			break;
		}
		size ++;
	}
	pthread_mutex_unlock(&qm[port]);
	return size;
}

// get message from queue. If empty return -1 otherwise size of message
int getMessage (char *message, int port) {
	// queue struct
	struct tailq_entry *item;
	struct tailq_entry *item_tmp;
	int status;
	pthread_mutex_lock(&qm[port]);
	if (!TAILQ_EMPTY (&mhead)) {
		item_tmp = TAILQ_FIRST (&mhead);
		if (item_tmp == NULL) {
			perror ("error reading queued message");
			return -1;
		}
		strncpy (message, item_tmp->data, item_tmp->size);
		// complete remove messsage from queue
	    TAILQ_REMOVE (&mhead, item_tmp, entries);
		// release memory
		free (item_tmp);
		status = item_tmp->size;  // return size of message in char
	} else {
		// empty queue return
		status = -1;
	}
	pthread_mutex_unlock(&qm[port]);
    return status;
}
// serial server 1
void *procCom1() {
	char strb[128];
	unsigned int size = 0;
	unsigned int flag;
	unsigned int f, i;
	unsigned int readed = 0;
	unsigned int count = 0;
	unsigned int timeout = 0;
	unsigned int z = 0;
	unsigned long tsend = 0L;
	unsigned long trecv = 0L;
	unsigned int sended = 0;
	unsigned char tmp[32];
	unsigned char tmp2[4096];
	struct ftdi_context ftdic;
	// queue struct
	struct tailq_entry *item;
	struct tailq_entry *item_tmp;
	int msgsize;
	//

	printf("com1\n");
	// init message queue
	initMessage(0);
	if (ftdi_init(&ftdic) < 0) {
		fprintf(stderr, "ftdi init failed \n");
		return;
	}
	ftdi_set_interface(&ftdic, INTERFACE_A);
	f = ftdi_usb_open_string(&ftdic, "i:0x9403:0x9011:0");
	if (f < 0 && f != -5) {
		fprintf(stderr, "unable to open ftdi device: %d (%s)\n", f,
				ftdi_get_error_string(&ftdic));
		exit(-1);
	}
	ftdi_usb_reset(&ftdic);
	ftdi_usb_purge_rx_buffer(&ftdic);
	ftdi_usb_purge_tx_buffer(&ftdic);
	//ftdi_setflowctrl(&ftdic, SIO_RTS_CTS_HS);
	ftdi_setflowctrl(&ftdic, SIO_DISABLE_FLOW_CTRL);
	ftdi_set_latency_timer(&ftdic, 16);
	//ftdi_read_data_set_chunksize(&ftdic, 4096);
	ftdi_set_baudrate(&ftdic, 9600); // 1200, latency = 16ms, 9600 = 16ms
	ftdi_set_line_property(&ftdic, BITS_8, STOP_BIT_1, NONE);
	printf("read buffer chunksize %d bytes\n", ftdic.readbuffer_chunksize);
	printf("write buffer chunksize %d bytes\n", ftdic.writebuffer_chunksize);
	printf("baudrate %d baud\n", ftdic.baudrate);
	//printf("async usb buffer size %d bytes\n", ftdic.async_usb_buffer_size);
	//printf("eeprom size %d bytes\n", ftdic.eeprom_size);
	printf("max packet size %d bytes\n", ftdic.max_packet_size);
	printf("usb read timeout %d ms\n", ftdic.usb_read_timeout);
	printf("usb write timsout %d ms\n", ftdic.usb_write_timeout);
	printf("usb in endpoint %d\n", ftdic.in_ep);
	printf("usb out endpoint %d\n", ftdic.out_ep);
	while (1) {
		//printf("write data \n");
		ftdi_read_data(&ftdic, tmp2, 4096);
		// send data to serial interface
		if (sizeMessage (0) < 1 ) {
			// filling test loop data
			for (size = 0; size < sizeof(tmp); size++) {
				tmp[size] = size & 0xff;
			}
			msgsize = size;
		} else {
			// get message data from uri
			msgsize = getMessage (tmp, 0);
		}
		    sended = ftdi_write_data(&ftdic, tmp, msgsize);
		// receive reply
		tsend = tsend + sended;
		// clear receive buffer
		for (z = 0; z < sizeof(tmp2); z++) {
			tmp2[z] = 0x00;
		}
		readed = 0;
		count = 0;
		timeout = 0;
		do {
			readed = ftdi_read_data(&ftdic, tmp2, sizeof(tmp2));
			trecv = trecv + readed;
			if (readed > 0) {
				count = readed + count;
				printhex(tmp2, readed);
			} else {
				//printf("wait data......\n");
				if (timeout < 100) {
					timeout++; // inc timeout count
				} else {
					break;
				}
			}
		} while (readed > 0);
		//printf("______total sended %lu, recived %lu______\n", tsend, trecv);
		/*sprintf(strb, "DT1:%010lu,%010lu\0", tsend, trecv);
		pthread_mutex_lock(&lcdprint_mutex);
		printLine(0, 0, 0, strb, 0); // print time
		pthread_mutex_unlock(&lcdprint_mutex);*/
	}
	ftdi_usb_close(&ftdic);
	ftdi_deinit(&ftdic);
}

void *procCom2() {
	char strb[128];
	unsigned int size = 0;
	unsigned int flag;
	unsigned int f, i;
	unsigned int readed = 0;
	unsigned int count = 0;
	unsigned int timeout = 0;
	unsigned int z = 0;
	unsigned long tsend = 0L;
	unsigned long trecv = 0L;
	unsigned int sended = 0;
	unsigned char tmp[32];
	unsigned char tmp2[4096];
	printf("com2\n");
	struct ftdi_context ftdic;
	for (size = 0; size < sizeof(tmp); size++) {
		tmp[size] = size & 0xff;
	}
	if (ftdi_init(&ftdic) < 0) {
		fprintf(stderr, "ftdi init failed \n");
		return;
	}
	ftdi_set_interface(&ftdic, INTERFACE_B);
	f = ftdi_usb_open_string(&ftdic, "i:0x9403:0x9011:0");
	if (f < 0 && f != -5) {
		fprintf(stderr, "unable to open ftdi device: %d (%s)\n", f,
				ftdi_get_error_string(&ftdic));
		exit(-1);
	}
	ftdi_usb_reset(&ftdic);
	ftdi_usb_purge_rx_buffer(&ftdic);
	ftdi_usb_purge_tx_buffer(&ftdic);
	//ftdi_setflowctrl(&ftdic, SIO_RTS_CTS_HS);
	ftdi_setflowctrl(&ftdic, SIO_DISABLE_FLOW_CTRL);
	ftdi_set_latency_timer(&ftdic, 16);
	//ftdi_read_data_set_chunksize(&ftdic, 4096);
	ftdi_set_baudrate(&ftdic, 9600); // 1200, latency = 16ms, 9600 = 16ms
	ftdi_set_line_property(&ftdic, BITS_8, STOP_BIT_1, NONE);
	while (1) {
		//printf("write data \n");
		ftdi_read_data(&ftdic, tmp2, 4096);
		sended = ftdi_write_data(&ftdic, tmp, sizeof(tmp));
		tsend = tsend + sended;
		//printf("read data\n");
		for (z = 0; z < sizeof(tmp2); z++) {
			tmp2[z] = 0x00;
		}
		readed = 0;
		count = 0;
		timeout = 0;
		do {
			readed = ftdi_read_data(&ftdic, tmp2, sizeof(tmp2));
			trecv = trecv + readed;
			if (readed > 0) {
				count = readed + count;
				//printhex(tmp2, readed);
			} else {
				//printf("wait data......\n");
				if (timeout < 100) {
					timeout++; // inc timeout count
				} else {
					break;
				}
			}
		} while (readed > 0);
		//printf("______total sended %lu, recived %lu______\n", tsend, trecv);
		sprintf(strb, "DX2:%010lu,%010lu\0", tsend, trecv);
		pthread_mutex_lock(&lcdprint_mutex);
		printLine(0, 1, 0, strb, 0); // print time
		pthread_mutex_unlock(&lcdprint_mutex);
	}
	ftdi_usb_close(&ftdic);
	ftdi_deinit(&ftdic);
}

void testLcd() {
	time_t stime;
	struct tm stm;
	struct timeval tv, tv1;
	double timemsec;
	long q = 0;
	int r = 0;
	char str[128];
	char str1[128];
	printf("test LCD start\n");
	while (1) {
		//lcdClear(0);
		//lcdClear(1);
		//usleep(200000);
		//	printf("test text \n");
		time(&stime);
		stm = *localtime(&stime);
		sprintf(str, "DATE:%02d-%02d-%04d %02d:%02d:%02d\0", stm.tm_mday,
				stm.tm_mon + 1, stm.tm_year + 1900, stm.tm_hour, stm.tm_min,
				stm.tm_sec);
		//sprintf(str, "TIME:%02d:%02d:%02d\0", stm.tm_hour, stm.tm_min,
		//		stm.tm_sec);
		pthread_mutex_lock(&lcdprint_mutex);
		printLine(0, 0, 0, str, 1); // print date
		//printLine(0, 1, 0, str, 0); // print time
		//printLine(0, 2, 0, "CH:Transmitted,Received\0", 0); // heading for Tx/Rx data
		pthread_mutex_unlock(&lcdprint_mutex);
		//printf ("time: %s\n", str);
		gettimeofday(&tv, NULL);
		/* for (r = 2; r < 8; r++) {
		 pthread_mutex_lock(&lcdprint_mutex);
		 if (r > 6) {
		 sprintf(str, "%08d,ABCDEfgijkl034,%d\0", q, r);
		 }
		 if (r > 6) {
		 sprintf(str1, "%08d,!@#$%^&{}][><,%d\0", q + 9876000, r);
		 }
		 if ((r % 2) == 0) {
		 if (r > 6) {
		 //	printLine(0, r, 0, str, 0);
		 }
		 if (r > 6) {
		 printLine(0, r, 0, str1, 1);
		 }
		 } else {
		 if (r > 6) {
		 //	printLineW(0, r, 0, str, 0);
		 }
		 if (r > 6) {
		 printLineW(0, r, 0, str1, 1);
		 }
		 }
		 //	lcdClearLine (0,0);
		 //	lcdClearLine (0,1);
		 pthread_mutex_unlock(&lcdprint_mutex);
		 } */
		gettimeofday(&tv1, NULL);
		timemsec = ((tv1.tv_sec - tv.tv_sec) * 1000
				+ (tv1.tv_usec - tv.tv_usec) / 1000);
		pthread_mutex_lock(&lcdprint_mutex);
		sprintf(str1, "RUN:%4.2fms\0", timemsec);
		//printf ("%s\n", str1);
		printLineW(0, 1, 0, str1, 1);
		//sprintf(str1, "CPU:%4.2fms\0", 0);
		//printf ("%s\n", str1);
		//printLineW(0, 0, 0, str1, 1);
		pthread_mutex_unlock(&lcdprint_mutex);
		if (delay > 1) {
			usleep(delay * 1000);
		}
		q++;
	}
	printf("test end \n");
//exit (0);
}

void initPRA() {
	int size = 0;
	int f;
#ifdef DEBUG
	printf("SBR threading......\n");
#endif
	// channel A -------------------------------------
	if (ftdi_init(&ftdic) < 0) {
		fprintf(stderr, "PRA ftdi init failed \n");
		return (EXIT_FAILURE);
	}
	//
	//ftdi_set_interface(&ftdic, INTERFACE_A);
	f = ftdi_usb_open(&ftdic, 0x0403, 0x6014);
	//f = ftdi_usb_open_string(&ftdic, "i:0x9403:0x9014:0");
	if (f < 0 && f != -5) {
		fprintf(stderr, "unable to open ftdi device PRA: %d (%s)\n", f,
				ftdi_get_error_string(&ftdic));
		exit(-1);
	}
	ftdi_usb_reset(&ftdic);
#ifdef DEBUG
	printf("ftdi port PRA open succeeded(channel 1): %d\n", f);
#endif
	ftdi_setflowctrl(&ftdic, SIO_RTS_CTS_HS);

	ftdi_set_latency_timer(&ftdic, 1);

	ftdi_usb_purge_buffers(&ftdic);
#ifdef DEBUG
	printf("SBR enabling bitmode RESET(channel 1)\n");
#endif
	ftdi_set_bitmode(&ftdic, 0xfb, 0x00);
	//ftdi_set_bitmode(&ftdic, 0xFF, BITMODE_BITBANG);
#ifdef DEBUG
	printf("SBR enabling bitmode MPSSE mode(channel 1)\n");
#endif
	ftdi_set_bitmode(&ftdic, 0xfb, BITMODE_MPSSE);

	buf[size++] = 0x8a & 0xff; // disable divid by 5 60Mhz clock, 0x8B= enable
	buf[size++] = 0x97 & 0xff; // turn off adaptive clocking, 0x96=on
	buf[size++] = 0x8d & 0xff; // disable 3 phase, 0x8c=enable

	buf[size++] = 0x86 & 0xff; // set TCLK
	buf[size++] = 0x02 & 0xff; // lo 0x0003=7.5Mhz, 0xffff=457hz
	buf[size++] = 0x00 & 0xff; // hi
#ifdef DEBUG
			printf("PRA buffer size %d\n", size);
#endif
	ftdi_write_data(&ftdic, buf, size);
	size = 0;
	initLCD();

}

void initLCD() {
	int size = 0;
	int f;
	// reset lcd high
	buf[size++] = 0x80 & 0xff; // reset LCD
	buf[size++] = 0xB8 & 0xff; // 1011 1000, reset=1, A0=0, #cs=1
	buf[size++] = 0xfb & 0xff; // 1111 1011 , 1=out 0=in

	buf[size++] = 0x82 & 0xff; // reset LCD
	buf[size++] = 0x00 & 0xff; // 0011 1111 gpioL0-7 = 0
	buf[size++] = 0xff & 0xff; // 1111 1011 , 1=out 0=in
	ftdi_write_data(&ftdic, buf, size);
	size = 0;
	usleep(50000);
	// reset lcd low
	buf[size++] = 0x80 & 0xff; // reset LCD
	buf[size++] = 0x38 & 0xff; // 0011 1000, reset=1, A0=0, #cs=1
	buf[size++] = 0xfb & 0xff; // 1111 1011 , 1=out 0=in
	ftdi_write_data(&ftdic, buf, size);
	size = 0;
	usleep(50000);
	// reset lcd high
	buf[size++] = 0x80 & 0xff; // reset LCD
	buf[size++] = 0xB8 & 0xff; // 1011 1000, reset=1, A0=0, #cs=1
	buf[size++] = 0xfb & 0xff; // 1111 1011 , 1=out 0=in
	ftdi_write_data(&ftdic, buf, size);
	size = 0;
	usleep(50000);
	// setup LCD parameters
	unsigned char init1[4] = { CMD_DISP_SET_BIAS & 0xff, // Set Bias
	CMD_DISP_SCANDIR & 0xff, // ADC to normal
	CMD_DISP_REV | 0x08, // Flip on Y
	CMD_DISP_LINE_ADDR & 0xff }; // line address =0
	write_lcd_cmd(init1, 4, 0);
	write_lcd_cmd(init1, 4, 1);
	usleep(50000);

	unsigned char init2[1] = { CMD_DISP_PWRCTRL | LCD_VCNV }; // send power ctrl
	write_lcd_cmd(init2, 1, 0);
	write_lcd_cmd(init2, 1, 1);
	usleep(50000);

	unsigned char init3[1] = { (init2[0] | LCD_VREG) & 0xff };
	write_lcd_cmd(init3, 1, 0);
	write_lcd_cmd(init3, 1, 1);
	usleep(50000);

	unsigned char init4[1] = { (init3[0] + LCD_VFOL) & 0xff };
	write_lcd_cmd(init4, 1, 0);
	write_lcd_cmd(init4, 1, 1);
	usleep(50000);

	unsigned char init5[4] = { (CMD_DISP_VREG_RES_RATIO | 0x06), // regulator resistor select
	(CMD_DISP_EVOLUME_MODE & 0xff), // send ref volt
	(LCD_EVOLUME_VALUE & 0xff), (CMD_DISP_ON & 0xff) // send display on
			};
	write_lcd_cmd(init5, 4, 0);
	write_lcd_cmd(init5, 4, 1);
	usleep(50000);
	lcdClear(0);
	// disp0
	setPageAddress(0, 0);
	setColumnAddress(0, 0);
	setLineAddress(0, 0);
	// disp1
	lcdClear(1);
	setPageAddress(0, 1);
	setColumnAddress(0, 1);
	setLineAddress(0, 1);
	lcdSetContrast(LCD_EVOLUME_VALUE + 2, 0);
	lcdSetContrast(LCD_EVOLUME_VALUE + 2, 1);
	printf("Init LCD \n");
}

// A0 = 1 write data
void write_lcd_data(unsigned char *data, unsigned char len, unsigned char disp) {
	unsigned int size = 0;
	unsigned int slen = 0;
#ifdef DEBUG
	printf("write data len %d \n", len);
#endif
	buf[size++] = 0x80 & 0xff; // reset=1, A0=1 ,#cs=1
	if (disp == 0) {
		buf[size++] = 0xF0 & 0xff; // 1111 0000, reset=1, A0=1, #cs=0
	} else {
		buf[size++] = 0xD8 & 0xff; // 1101 1000, reset=1, A0=1, #cs1=0
	}
	buf[size++] = 0xfb & 0xff; // 1111 1011 , 1=out 0=in

	buf[size++] = 0x11 & 0xff; // write data
	buf[size++] = (len - 1) & 0xff; //  len -1 = low
	buf[size++] = 0x00; // len high

	for (slen = 0; slen < len; slen++) {
		buf[size++] = *(data + (slen & 0xff)); // write data byte
#ifdef DEBUG
				printf("write data address:%d, data:%02X\n", slen,
						*(data + (slen & 0xff)));
#endif
	}
	//  disable lcd interface
	buf[size++] = 0x80 & 0xff; // reset=1, A0=1,#cs=1
	buf[size++] = 0xB8 & 0xff; // 1011 1000, reset=1, A0=0, #cs=1
	buf[size++] = 0xfb & 0xff; // 1111 1011 , 1=out 0=in
	ftdi_write_data(&ftdic, buf, size);
	size = 0;
}

// A0 = 0 write command
void write_lcd_cmd(unsigned char *cmd, unsigned char len, unsigned char disp) {
	unsigned int size = 0;
	unsigned int slen = 0;
#ifdef DEBUG
	printf("write command len %d \n", len);
#endif
	// enable lcd serial interface
	buf[size++] = 0x80 & 0xff; // reset=1, A0=1,#cs=1
	if (disp == 0) {
		buf[size++] = 0xB0 & 0xff; // 1011 0000, reset=1, A0=0, #cs=0
	} else {
		buf[size++] = 0x98 & 0xff; // 1001 1000, reset=1, A0=0, #cs=0
	}
	buf[size++] = 0xfb & 0xff; // 1111 1011 , 1=out 0=in

	buf[size++] = 0x11 & 0xff; // write data
	buf[size++] = (len - 1) & 0xff; //  len - 1 = low
	buf[size++] = 0x00; // len high

	for (slen = 0; slen < len; slen++) {
		buf[size++] = *(cmd + (slen & 0xff)); // write data byte
#ifdef DEBUG
				printf("write command address:%d, data:%02X\n", slen,
						*(cmd + (slen & 0xff)));
#endif
	}

	buf[size++] = 0x80 & 0xff; // reset=1, A0=1,#cs=1
	buf[size++] = 0xB8 & 0xff; // 1011 1000, reset=1, A0=0, #cs=1
	buf[size++] = 0xfb & 0xff; // 1111 1011 , 1=out 0=in
	ftdi_write_data(&ftdic, buf, size);
	size = 0;

}

void printLine(unsigned char x, unsigned char y, unsigned char inv,
		unsigned char *string, unsigned char disp) {
#ifdef DEBUG
	printf ("printline x=%d, y=%d, inv=%d, string=%s\n", x,y,inv,string);
#endif
	unsigned char m, n;
	unsigned short yy;
	unsigned char lcd_buffer[128];
	setPageAddress(y, disp);
	setColumnAddress(x, disp);
	n = x;
	while (*string != 0) {
		if ((n + 5) > 127) { // if one or more char can be display
			break;
		} else {
			yy = *string; // get asc val
			yy = (yy - 32) * 5;
			for (m = 0; m < 5; m++) {
				lcd_buffer[n] = font5x7[yy + m]; // get charachter map
				if (inv) {
					lcd_buffer[n] = (~lcd_buffer[n]); // inverted bit map
				}
				n++;
			}
			++string; // inc pointer
		}
	}
	write_lcd_data(lcd_buffer, (n), disp);
}

void printLineW(unsigned char x, unsigned char y, unsigned char inv,
		unsigned char *string, unsigned char disp) {
#ifdef DEBUG
	printf ("printline x=%d, y=%d, inv=%d, string=%s\n", x,y,inv,string);
#endif
	unsigned char m, n;
	unsigned short yy;
	unsigned char lcd_buffer[128];
	setPageAddress(y, disp);
	setColumnAddress(x, disp);
	n = x;
	while (*string != 0) {
		if ((n + 8) > 127) { // if one or more char can be display
			break;
		} else {
			yy = *string; // get asc val
			yy = yy * 8;
			for (m = 0; m < 8; m++) {
				lcd_buffer[n] = font8x8[yy + m]; // get charachter map
				if (inv) {
					lcd_buffer[n] = (~lcd_buffer[n]); // inverted bit map
				}
				n++;
			}
			++string; // inc pointer
		}
	}
	write_lcd_data(lcd_buffer, (n), disp);
}

void lcdOn(unsigned char disp) {
#ifdef DEBUG
	printf ("LCD ON command\n");
#endif
	unsigned char cmd_buffer[1] = { CMD_DISP_ON };
	write_lcd_cmd(cmd_buffer, 1, disp);
	usleep(50000);
}

void lcdOff(unsigned char disp) {
#ifdef DEBUG
	printf ("LCD OFF command\n");
#endif
	unsigned char cmd_buffer[1] = { CMD_DISP_OFF };
	write_lcd_cmd(cmd_buffer, 1, disp);
	usleep(50000);
}

void lcdSetContrast(unsigned char contrast, unsigned char disp) {
#ifdef DEBUG
	printf ("LCD contrast %02X\n" , contrast);
#endif
	unsigned char cmd_buffer[2] = { CMD_DISP_EVOLUME_MODE, contrast & 0xff };
	write_lcd_cmd(cmd_buffer, 2, disp);
	usleep(50000);

}

void setPageAddress(unsigned char page, unsigned char disp) {
#ifdef DEBUG
	printf ("LCD set page address %02X\n", page);
#endif
	unsigned char cmd_buffer[1] = { CMD_DISP_PAGE_ADDR | (page & 0x0f) };
	write_lcd_cmd(cmd_buffer, 1, disp);
}

void setColumnAddress(unsigned char column, unsigned char disp) {
#ifdef DEBUG
	printf ("LCD set column Address %02X\n", column);
#endif
	unsigned char cmd_buffer[2] = { CMD_DISP_COLADDR_H | (column >> 4),
			CMD_DISP_COLADDR_L | (column & 0x0f) };
	write_lcd_cmd(cmd_buffer, 2, disp);

}

void setLineAddress(unsigned char line, unsigned char disp) {
#ifdef DEBUG
	printf ("LCD set line Address %02X\n", line);
#endif
	unsigned char cmd_buffer[1] = { CMD_DISP_LINE_ADDR | (line & 0x3f) };
	write_lcd_cmd(cmd_buffer, 1, disp);
}

void lcdClear(unsigned char disp) {
#ifdef DEBUG
	printf ("LCD clear \n");
#endif
	unsigned char lcd_buffer[128];
	unsigned char i;
	for (i = 0; i < 128; i++) {
		lcd_buffer[i] = 0;
	}
	for (i = 0; i < 8; i++) {
		setPageAddress(i, disp);
		setColumnAddress(0, disp);
		setLineAddress(0, disp);
		write_lcd_data(lcd_buffer, 128, disp);
	}
}

void lcdClearLine(unsigned char line, unsigned char disp) {
#ifdef DEBUG
	printf ("LCD clear line %02X\n", line);
#endif
	unsigned char i;
	unsigned char lcd_buffer[128];
	for (i < 0; i < 128; i++) {
		lcd_buffer[i] = 0;
		setPageAddress(line, disp);
		setColumnAddress(0, disp);
		write_lcd_data(lcd_buffer, 128, disp);
	}
}

void make_pidfile(char *pidfile) {
	FILE *fpidfile;
	if (!pidfile)
		return;
	fpidfile = fopen(pidfile, "w");
	if (!fpidfile) {
		syslog(LOG_WARNING, "Error opening pidfile");
		return;
	}
	fprintf(fpidfile, "%d\n", getpid());
	fclose(fpidfile);
}

void set_sighup_handler(t_sighup_handler handler) {
	user_sighup_handler = handler;
	printf("exit daemon\n");
	exit(0);
}

void sighup_handler(int sig) {
	got_sighup = 1;
	printf ("server stop !!!\n");

}

void setup_sighup(void) {
	struct sigaction act;
	int err;

	act.sa_handler = sighup_handler;
	sigemptyset(&act.sa_mask);
	act.sa_flags = SA_RESTART;
	err = sigaction(SIGHUP, &act, NULL);
	if (err) {
		perror("sigaction");
	}

}

/*
 void regsignal() {
 signal(SIGQUIT, signalhandler);
 signal(SIGTERM, signalhandler);
 signal(SIGHUP, signalhandler);
 signal(SIGINT, signalhandler);
 } */

int main(int argc, char **argv) {
	int err;
	int threadgroup;
	int i;
	for (i = 1; i < argc; i++) {
		if ((argv[i][0] != '-') || (strlen(argv[i]) != 2)) {
			fprintf(stderr, "Invalid argument:'%s'\n", argv[i]);
		}
		switch (argv[i][1]) {
		case 'n': // -n normal process
			printf("normal process\n");
			daemonized = 0;
			break;
		case 'd': // -d daemonized
			printf("daemonized\n");
			daemonized = 1;
			break;
		default: // default
			fprintf(stderr, "Invalid option: '%s'\n", argv[i]);
		}
	}
	setup_sighup();
	if (daemonized == 1) {
		openlog("forkdaemon", LOG_PID | LOG_CONS, LOG_DAEMON);
		syslog(LOG_NOTICE, "startup");
		if ((pid = fork()) > 0) {
			exit(0);
		} else if (pid < 0) {
			syslog(LOG_ERR, "Error forking first fork");
			exit(1);
		} else {
			setsid();
			if ((pid = fork()) > 0) {
				exit(0);
			} else if (pid < 0) {
				syslog(LOG_ERR, "Error forking second fork");
				exit(1);
			}
		}
	}
	make_pidfile("forkpid");
	/* int result = setpriority(PRIO_PROCESS, 0, 0);
	 if (result == -1) {
	 #ifdef DEBUG
	 dprintf("cannot change to higher priority\n");
	 #endif
	 } */
	// register signal from OS
	//regsignal();
	// init PRA and PRB....
	initPRA();
	// setup networks
	// set_ip ("eth0", "192.168.1.130" , 24);

	// pra thread init
	pthread_mutex_init(&pra_mutex, NULL);
	pthread_cond_init(&pra_cond, NULL);
	pthread_attr_init(&pra_attr);
	pthread_attr_setdetachstate(&pra_attr, PTHREAD_CREATE_JOINABLE);

	// proc B thread init
	pthread_mutex_init(&procb_mutex, NULL);
	pthread_cond_init(&procb_cond, NULL);
	pthread_attr_init(&procb_attr);
	pthread_attr_setdetachstate(&procb_attr, PTHREAD_CREATE_JOINABLE);

	// lcd lock
	pthread_mutex_init(&lcdprint_mutex, NULL);
	pthread_mutex_init(&lcdprintw_mutex, NULL);

	// init qm locks
	int qi;
	for (qi =0; qi < 8; qi++) {
		pthread_mutex_init (&qm[qi], NULL);
		pthread_mutex_init (&qlog[qi], NULL);
	}

    usleep(50000);
	// create PRA thread
	if ((err = pthread_create(&thread[0], &pra_attr, testPRA, NULL))) {
		// create without attribute
		if (err != EPERM || pthread_create(&thread[0], NULL, testPRA, NULL))
			printf("unable create PRA thread");
		printf("create PRA thread without scheduling\n");
	}
	usleep(50000);
	// create PRB thread
	if ((err = pthread_create(&thread[2], &prb_attr, testPRB, NULL))) {
		// create without attribute
		if (err != EPERM || pthread_create(&thread[2], NULL, testPRC, NULL))
			printf("unable create PRB thread");
		printf("create PRB thread without scheduling\n");
	}
	usleep(50000);
	// create PRC thread
	if ((err = pthread_create(&thread[3], &prc_attr, testPRC, NULL))) {
		// create without attribut
		if (err != EPERM || pthread_create(&thread[3], NULL, testPRC, NULL))
			printf("unable create PRC thread");
		printf("create PRC thread without scheduling\n");
	}
	usleep(50000);
	// create procB thread
	if ((err = pthread_create(&thread[1], &procb_attr, procB, NULL))) {
		// create without attribute
		if (err != EPERM || pthread_create(&thread[1], NULL, procB, NULL))
			printf("unable create procB thread");
		printf("create procB thread without scheduling\n");
	}
	usleep(50000);
	// create procKey thread
	if ((err = pthread_create(&thread[5], &key_attr, procKey, NULL))) {
		// create without attribute
		if (err != EPERM || pthread_create(&thread[5], NULL, procKey, NULL))
			printf("unable create procKey thread");
		printf("create procKey thread without scheduling\n");
	}
	usleep(50000);
	// create procCom1 thread
	if ((err = pthread_create(&thread[6], &com1_attr, procCom1, NULL))) {
		// create without attribute
		if (err != EPERM || pthread_create(&thread[6], NULL, procCom1, NULL))
			printf("unable create procCom1 thread");
		printf("create procCom1 thread without scheduling\n");
	}
	usleep(50000);
	// create procCom2 thread
	if ((err = pthread_create(&thread[7], &com2_attr, procCom2, NULL))) {
		// create without attribute
		if (err != EPERM || pthread_create(&thread[7], NULL, procCom2, NULL))
			printf("unable create procCom2 thread");
		printf("create procCom2 thread without scheduling\n");
	}
	usleep(50000);
	// create server thread
	if ((err = pthread_create(&thread[14], &setupServer_attr, setupServer,
			NULL))) {
		// create without attribute
		if (err != EPERM
				|| pthread_create(&thread[14], NULL, setupServer, NULL))
			printf("unable create procCom8 thread");
		printf("create server thread without scheduling\n");
	}

	usleep(50000);
	// thread group join and wait thread destory
	// pthread_join(thread[0], &threadgroup); // cmd procesing thread join
	//pthread_cond_broadcast(&procb_mutex);
	//pthread_cond_broadcast(&pra_cond);
	// start
	testLcd();

	//destory PRA thread
	printf("destory all threads\n");
	pthread_attr_destroy(&pra_attr);
	pthread_mutex_destroy(&pra_mutex);
	pthread_cond_destroy(&pra_cond);

	// PRB
	pthread_attr_destroy(&prb_attr);

	// PRC
	pthread_attr_destroy(&prc_attr);

	// ProcKey
	pthread_attr_destroy(&key_attr);
	// Com[1-4]Key
	pthread_attr_destroy(&com1_attr);
	pthread_attr_destroy(&com2_attr);

	//destory server
	pthread_attr_destroy(&setupServer_attr);
	//destory procb thread
	pthread_attr_destroy(&procb_attr);
	pthread_mutex_destroy(&procb_mutex);
	pthread_cond_destroy(&procb_cond);

	//lcd mutex
	pthread_mutex_destroy(&lcdprint_mutex);
	pthread_mutex_destroy(&lcdprintw_mutex);
	// destory qm locks
	for (qi =0; qi < 8; qi++) {
		pthread_mutex_destroy (&qm[qi]);
		pthread_mutex_destroy (&qlog[qi]);
	}

	pthread_exit(NULL);
	return 0;
}

