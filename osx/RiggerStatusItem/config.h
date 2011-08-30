/* config.h for OSX */
#define CONFIGFILE "test.conf"
#define KEYDIR "/usr/local"
#define PIDFILE "test.pid"
#define UNBOUND_CONTROL "unbound-control"

#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <unistd.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#define ATTR_FORMAT(x,y,z) /* nil */
#define FD_SET_T 
#define MAXSYSLOGMSGLEN 10240
#define DNS_PORT 53
