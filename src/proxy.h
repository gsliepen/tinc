#ifndef TINC_PROXY_H
#define TINC_PROXY_H

#include "system.h"

#include "net.h"

PACKED(struct socks4_request_t {
	uint8_t version;
	uint8_t command;
	uint16_t dstport;
	struct in_addr dstip;
	char id[];
});

PACKED(struct socks4_response_t {
	uint8_t version;
	uint8_t status;
	uint16_t dstport;
	struct in_addr dstip;
});

typedef struct socks4_request_t socks4_request_t;
typedef struct socks4_response_t socks4_response_t;

PACKED(struct socks5_greet_t {
	uint8_t version;
	uint8_t nmethods;
	uint8_t authmethod;
});

typedef struct socks5_greet_t socks5_greet_t;

PACKED(struct socks5_conn_hdr_t {
	uint8_t version;
	uint8_t command;
	uint8_t reserved;
	uint8_t addr_type;
});

PACKED(struct socks5_ipv4_t {
	struct in_addr addr;
	uint16_t port;
});

PACKED(struct socks5_ipv6_t {
	struct in6_addr addr;
	uint16_t port;
});

typedef struct socks5_conn_hdr_t socks5_conn_hdr_t;
typedef struct socks5_ipv4_t socks5_ipv4_t;
typedef struct socks5_ipv6_t socks5_ipv6_t;

PACKED(struct socks5_conn_req_t {
	socks5_conn_hdr_t header;
	union {
		socks5_ipv4_t ipv4;
		socks5_ipv6_t ipv6;
	} dst;
});

PACKED(struct socks5_server_choice_t {
	uint8_t socks_version;
	uint8_t auth_method;
});

PACKED(struct socks5_auth_status_t {
	uint8_t auth_version;
	uint8_t auth_status;
});

typedef struct socks5_auth_status_t socks5_auth_status_t;

PACKED(struct socks5_conn_resp_t {
	uint8_t socks_version;
	uint8_t conn_status;
	uint8_t reserved;
	uint8_t addr_type;
});

typedef struct socks5_conn_req_t socks5_conn_req_t;
typedef struct socks5_server_choice_t socks5_server_choice_t;
typedef struct socks5_conn_resp_t socks5_conn_resp_t;

PACKED(struct socks5_resp_t {
	socks5_server_choice_t choice;

	union {
		// if choice == password
		struct {
			socks5_auth_status_t status;
			socks5_conn_resp_t resp;
		} pass;

		// if choice == anonymous
		socks5_conn_resp_t anon;
	};
});

typedef struct socks5_resp_t socks5_resp_t;

// Get the length of a connection request to a SOCKS 4 or 5 proxy
extern size_t socks_req_len(proxytype_t type, const sockaddr_t *sa);

// Create a request to connect to a SOCKS 4 or 5 proxy.
// Returns the expected response length, or zero on error.
extern size_t create_socks_req(proxytype_t type, void *req, const sockaddr_t *sa);

// Check that SOCKS server provided a valid response and permitted further requests
extern bool check_socks_resp(proxytype_t type, const void *buf, size_t len);

#endif // TINC_PROXY_H
