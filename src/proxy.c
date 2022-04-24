#include "system.h"

#include "logger.h"
#include "proxy.h"

typedef enum socks5_auth_method_t {
	AUTH_ANONYMOUS = 0,
	AUTH_PASSWORD = 2,
	AUTH_FAILED = 0xFF,
} socks5_auth_method_t;

// SOCKS 4 constants (https://en.wikipedia.org/wiki/SOCKS#SOCKS4)
static const uint8_t SOCKS4_CMD_CONN = 1;
static const uint8_t SOCKS4_REPLY_VERSION = 0;
static const uint8_t SOCKS4_STATUS_OK = 0x5A;
static const uint8_t SOCKS4_VERSION = 4;

// SOCKS 5 constants (https://en.wikipedia.org/wiki/SOCKS#SOCKS5)
typedef enum socks5_addr_type_t {
	SOCKS5_IPV4 = 1,
	SOCKS5_IPV6 = 4,
} socks5_addr_type_t;

static const uint8_t SOCKS5_AUTH_METHOD_NONE = 0;
static const uint8_t SOCKS5_AUTH_METHOD_PASSWORD = 2;
static const uint8_t SOCKS5_AUTH_OK = 0;
static const uint8_t SOCKS5_AUTH_VERSION = 1;
static const uint8_t SOCKS5_COMMAND_CONN = 1;
static const uint8_t SOCKS5_STATUS_OK = 0;
static const uint8_t SOCKS5_VERSION = 5;

static void log_proxy_grant(bool granted) {
	if(granted) {
		logger(DEBUG_CONNECTIONS, LOG_DEBUG, "Proxy request granted");
	} else {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "Proxy request rejected");
	}
}

static void log_short_response(void) {
	logger(DEBUG_CONNECTIONS, LOG_ERR, "Received short response from proxy");
}

static bool check_socks4_resp(const socks4_response_t *resp, size_t len) {
	if(len < sizeof(socks4_response_t)) {
		log_short_response();
		return false;
	}

	if(resp->version != SOCKS4_REPLY_VERSION) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "Bad response from SOCKS4 proxy");
		return false;
	}

	bool granted = resp->status == SOCKS4_STATUS_OK;
	log_proxy_grant(granted);
	return granted;
}

static bool socks5_check_result(const socks5_conn_resp_t *re, size_t len) {
	size_t addrlen;

	switch((socks5_addr_type_t)re->addr_type) {
	case SOCKS5_IPV4:
		addrlen = sizeof(socks5_ipv4_t);
		break;

	case SOCKS5_IPV6:
		addrlen = sizeof(socks5_ipv6_t);
		break;

	default:
		logger(DEBUG_CONNECTIONS, LOG_ERR, "Unsupported address type 0x%x from proxy server", re->addr_type);
		return false;
	}

	if(len < addrlen) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "Received short address from proxy server");
		return false;
	}

	if(re->socks_version != SOCKS5_VERSION) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "Invalid response from proxy server");
		return false;
	}

	bool granted = re->conn_status == SOCKS5_STATUS_OK;
	log_proxy_grant(granted);
	return granted;
}

static bool check_socks5_resp(const socks5_resp_t *resp, size_t len) {
	if(len < sizeof(socks5_server_choice_t)) {
		log_short_response();
		return false;
	}

	len -= sizeof(socks5_server_choice_t);

	if(resp->choice.socks_version != SOCKS5_VERSION) {
		logger(DEBUG_CONNECTIONS, LOG_ERR, "Invalid response from proxy server");
		return false;
	}

	switch((socks5_auth_method_t) resp->choice.auth_method) {
	case AUTH_ANONYMOUS:
		if(len < sizeof(socks5_conn_resp_t)) {
			log_short_response();
			return false;
		} else {
			return socks5_check_result(&resp->anon, len - sizeof(socks5_conn_resp_t));
		}

	case AUTH_PASSWORD: {
		size_t header_len = sizeof(socks5_auth_status_t) + sizeof(socks5_conn_resp_t);

		if(len < header_len) {
			log_short_response();
			return false;
		}

		if(resp->pass.status.auth_version != SOCKS5_AUTH_VERSION) {
			logger(DEBUG_CONNECTIONS, LOG_ERR, "Invalid proxy authentication protocol version");
			return false;
		}

		if(resp->pass.status.auth_status != SOCKS5_AUTH_OK) {
			logger(DEBUG_CONNECTIONS, LOG_ERR, "Proxy authentication failed");
			return false;
		}

		return socks5_check_result(&resp->pass.resp, len - header_len);
	}

	case AUTH_FAILED:
		logger(DEBUG_CONNECTIONS, LOG_ERR, "Proxy request rejected: unsuitable authentication method");
		return false;

	default:
		logger(DEBUG_CONNECTIONS, LOG_ERR, "Unsupported authentication method");
		return false;
	}
}

bool check_socks_resp(proxytype_t type, const void *buf, size_t len) {
	if(type == PROXY_SOCKS4) {
		return check_socks4_resp(buf, len);
	} else if(type == PROXY_SOCKS5) {
		return check_socks5_resp(buf, len);
	} else {
		return false;
	}
}

static size_t create_socks4_req(socks4_request_t *req, const sockaddr_t *sa) {
	if(sa->sa.sa_family != AF_INET) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Cannot connect to an IPv6 host through a SOCKS 4 proxy!");
		return 0;
	}

	req->version = SOCKS4_VERSION;
	req->command = SOCKS4_CMD_CONN;
	req->dstport = sa->in.sin_port;
	req->dstip = sa->in.sin_addr;

	if(proxyuser) {
		strcpy(req->id, proxyuser);
	} else {
		req->id[0] = '\0';
	}

	return sizeof(socks4_response_t);
}

static size_t create_socks5_req(void *buf, const sockaddr_t *sa) {
	uint16_t family = sa->sa.sa_family;

	if(family != AF_INET && family != AF_INET6) {
		logger(DEBUG_ALWAYS, LOG_ERR, "Address family %x not supported for SOCKS 5 proxies!", family);
		return 0;
	}

	socks5_greet_t *req = buf;
	req->version = SOCKS5_VERSION;
	req->nmethods = 1; // only one auth method is supported

	size_t resplen = sizeof(socks5_server_choice_t);
	uint8_t *auth = (uint8_t *)buf + sizeof(socks5_greet_t);

	if(proxyuser && proxypass) {
		req->authmethod = SOCKS5_AUTH_METHOD_PASSWORD;

		// field  | VER | IDLEN |  ID   | PWLEN |   PW  |
		// bytes  |  1  |   1   | 1-255 |   1   | 1-255 |

		// Assign the first field (auth protocol version)
		*auth++ = SOCKS5_AUTH_VERSION;

		size_t userlen = strlen(proxyuser);
		size_t passlen = strlen(proxypass);

		// Assign the username length, and copy the username
		*auth++ = userlen;
		memcpy(auth, proxyuser, userlen);
		auth += userlen;

		// Do the same for password
		*auth++ = passlen;
		memcpy(auth, proxypass, passlen);
		auth += passlen;

		resplen += sizeof(socks5_auth_status_t);
	} else {
		req->authmethod = SOCKS5_AUTH_METHOD_NONE;
	}

	socks5_conn_req_t *conn = (socks5_conn_req_t *) auth;
	conn->header.version = SOCKS5_VERSION;
	conn->header.command = SOCKS5_COMMAND_CONN;
	conn->header.reserved = 0;

	resplen += sizeof(socks5_conn_resp_t);

	if(family == AF_INET) {
		conn->header.addr_type = SOCKS5_IPV4;
		conn->dst.ipv4.addr = sa->in.sin_addr;
		conn->dst.ipv4.port = sa->in.sin_port;
		resplen += sizeof(socks5_ipv4_t);
	} else {
		conn->header.addr_type = SOCKS5_IPV6;
		conn->dst.ipv6.addr = sa->in6.sin6_addr;
		conn->dst.ipv6.port = sa->in6.sin6_port;
		resplen += sizeof(socks5_ipv6_t);
	}

	return resplen;
}

size_t socks_req_len(proxytype_t type, const sockaddr_t *sa) {
	uint16_t family = sa->sa.sa_family;

	if(type == PROXY_SOCKS4) {
		if(family != AF_INET) {
			logger(DEBUG_CONNECTIONS, LOG_ERR, "SOCKS 4 only supports IPv4 addresses");
			return 0;
		}

		size_t userlen_size = 1;
		size_t userlen = proxyuser ? strlen(proxyuser) : 0;
		return sizeof(socks4_request_t) + userlen_size + userlen;
	}

	if(type == PROXY_SOCKS5) {
		if(family != AF_INET && family != AF_INET6) {
			logger(DEBUG_CONNECTIONS, LOG_ERR, "SOCKS 5 only supports IPv4 and IPv6");
			return 0;
		}

		size_t len = sizeof(socks5_greet_t) +
		             sizeof(socks5_conn_hdr_t) +
		             (family == AF_INET
		              ? sizeof(socks5_ipv4_t)
		              : sizeof(socks5_ipv6_t));

		if(proxyuser && proxypass) {
			// version, userlen, user, passlen, pass
			len += 1 + 1 + strlen(proxyuser) + 1 + strlen(proxypass);
		}

		return len;
	}

	logger(DEBUG_CONNECTIONS, LOG_ERR, "Bad proxy type 0x%x", type);
	return 0;
}

size_t create_socks_req(proxytype_t type, void *buf, const sockaddr_t *sa) {
	if(type == PROXY_SOCKS4) {
		return create_socks4_req(buf, sa);
	} else if(type == PROXY_SOCKS5) {
		return create_socks5_req(buf, sa);
	} else {
		abort();
	}
}
