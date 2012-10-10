/*
 *  tunemu - Tun device emulation for Darwin
 *  Copyright (C) 2009 Friedrich Schöller <friedrich.schoeller@gmail.com>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include "tunemu.h"

#include <sys/socket.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <util.h>
#include <pcap.h>
#include <stdarg.h>
#include <errno.h>
#include <stdint.h>
#include <stdint.h>
#include <ctype.h>
#include <fcntl.h>

#define PPPPROTO_CTL 1

#define PPP_IP          0x21
#define PPP_IPV6        0x57

#define SC_LOOP_TRAFFIC 0x00000200

#define PPPIOCNEWUNIT   _IOWR('t', 62, int)
#define PPPIOCSFLAGS    _IOW('t', 89, int)
#define PPPIOCSNPMODE   _IOW('t', 75, struct npioctl)
#define PPPIOCATTCHAN   _IOW('t', 56, int)
#define PPPIOCGCHAN     _IOR('t', 55, int)
#define PPPIOCCONNECT   _IOW('t', 58, int)
#define PPPIOCGUNIT     _IOR('t', 86, int)

struct sockaddr_ppp
{
	u_int8_t ppp_len;
	u_int8_t ppp_family;
	u_int16_t ppp_proto;
	u_int32_t ppp_cookie;
};

enum NPmode
{
	NPMODE_PASS,
    NPMODE_DROP,
    NPMODE_ERROR,
    NPMODE_QUEUE
};

struct npioctl
{
	int protocol;
	enum NPmode mode;
};

#define PPP_KEXT_PATH "/System/Library/Extensions/PPP.kext"

#define ERROR_BUFFER_SIZE 1024

char tunemu_error[ERROR_BUFFER_SIZE];

static int pcap_use_count = 0;
static pcap_t *pcap = NULL;

static int data_buffer_length = 0;
static char *data_buffer = NULL;

static void tun_error(char *format, ...)
{
	va_list vl;
	va_start(vl, format);
	vsnprintf(tunemu_error, ERROR_BUFFER_SIZE, format, vl);
	va_end(vl);
}

static void tun_noerror()
{
	*tunemu_error = 0;
}

static void closeall()
{
    int fd = getdtablesize();
	while (fd--)
		close(fd);

    open("/dev/null", O_RDWR, 0);
    dup(0);
    dup(0);
}

static int ppp_load_kext()
{
	int pid = fork();
	if (pid < 0)
	{
		tun_error("fork for ppp kext: %s", strerror(errno));
		return -1;
	}

	if (pid == 0)
	{
		closeall();
		execle("/sbin/kextload", "kextload", PPP_KEXT_PATH, NULL, NULL);
		exit(1);
	}

	int status;
	while (waitpid(pid, &status, 0) < 0)
	{
		if (errno == EINTR)
			continue;

		tun_error("waitpid for ppp kext: %s", strerror(errno));
		return -1;
	}

	if (WEXITSTATUS(status) != 0)
	{
		tun_error("could not load ppp kext \"%s\"", PPP_KEXT_PATH);
		return -1;
	}

	tun_noerror();
	return 0;
}

static int ppp_new_instance()
{
	// create ppp socket
    int ppp_sockfd = socket(PF_PPP, SOCK_RAW, PPPPROTO_CTL);
    if (ppp_sockfd < 0)
	{
		if (ppp_load_kext() < 0)
			return -1;

		ppp_sockfd = socket(PF_PPP, SOCK_RAW, PPPPROTO_CTL);
		if (ppp_sockfd < 0)
		{
			tun_error("creating ppp socket: %s", strerror(errno));
			return -1;
		}
	}

	// connect to ppp procotol
    struct sockaddr_ppp pppaddr;
    pppaddr.ppp_len = sizeof(struct sockaddr_ppp);
    pppaddr.ppp_family = AF_PPP;
    pppaddr.ppp_proto = PPPPROTO_CTL;
    pppaddr.ppp_cookie = 0;
    if (connect(ppp_sockfd, (struct sockaddr *)&pppaddr, sizeof(struct sockaddr_ppp)) < 0)
	{
		tun_error("connecting ppp socket: %s", strerror(errno));
		close(ppp_sockfd);
		return -1;
    }

	tun_noerror();
	return ppp_sockfd;
}

static int ppp_new_unit(int *unit_number)
{
	int fd = ppp_new_instance();
	if (fd < 0)
		return -1;

	// create ppp unit
	if (ioctl(fd, PPPIOCNEWUNIT, unit_number) < 0)
	{
		tun_error("creating ppp unit: %s", strerror(errno));
		close(fd);
		return -1;
    }

	tun_noerror();
	return fd;
}

static int ppp_setup_unit(int unit_fd)
{
	// send traffic to program
	int flags = SC_LOOP_TRAFFIC;
	if (ioctl(unit_fd, PPPIOCSFLAGS, &flags) < 0)
	{
		tun_error("setting ppp loopback mode: %s", strerror(errno));
		return -1;
    }

	// allow packets
	struct npioctl npi;
	npi.protocol = PPP_IP;
	npi.mode = NPMODE_PASS;
	if (ioctl(unit_fd, PPPIOCSNPMODE, &npi) < 0)
	{
		tun_error("starting ppp unit: %s", strerror(errno));
		return -1;
	}

	tun_noerror();
	return 0;
}

static int open_pcap()
{
	if (pcap != NULL)
	{
		pcap_use_count++;
		return 0;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap = pcap_open_live("lo0", BUFSIZ, 0, 1, errbuf);
	pcap_use_count = 1;

	if (pcap == NULL)
	{
		tun_error("opening pcap: %s", errbuf);
		return -1;
	}

	tun_noerror();
	return 0;
}

static void close_pcap()
{
	if (pcap == NULL)
		return;

	pcap_use_count--;
	if (pcap_use_count == 0)
	{
		pcap_close(pcap);
		pcap = NULL;
	}
}

static void allocate_data_buffer(int size)
{
	if (data_buffer_length < size)
	{
		free(data_buffer);
		data_buffer_length = size;
		data_buffer = malloc(data_buffer_length);
	}
}

static void make_device_name(tunemu_device device, int unit_number)
{
	snprintf(device, sizeof(tunemu_device), "ppp%d", unit_number);
}

static int check_device_name(tunemu_device device)
{
	if (strlen(device) < 4)
		return -1;

	int unit_number = atoi(device + 3);
	if (unit_number < 0 || unit_number > 999)
		return -1;

	tunemu_device compare;
	make_device_name(compare, unit_number);

	if (strcmp(device, compare) != 0)
		return -1;

	return 0;
}

int tunemu_open(tunemu_device device)
{
	int ppp_unit_number = -1;
	if (device[0] != 0)
	{
		if (check_device_name(device) < 0)
		{
			tun_error("invalid device name \"%s\"", device);
			return -1;
		}

		ppp_unit_number = atoi(device + 3);
	}

	int ppp_unit_fd = ppp_new_unit(&ppp_unit_number);
	if (ppp_unit_fd < 0)
		return -1;

	if (ppp_setup_unit(ppp_unit_fd) < 0)
	{
		close(ppp_unit_fd);
		return -1;
	}

	if (open_pcap() < 0)
	{
		close(ppp_unit_fd);
		return -1;
	}

	make_device_name(device, ppp_unit_number);

	return ppp_unit_fd;
}

int tunemu_close(int ppp_sockfd)
{
	int ret = close(ppp_sockfd);

	if (ret == 0)
		close_pcap();

	return ret;
}

int tunemu_read(int ppp_sockfd, char *buffer, int length)
{
	allocate_data_buffer(length + 2);

	length = read(ppp_sockfd, data_buffer, length + 2);
	if (length < 0)
	{
		tun_error("reading packet: %s", strerror(errno));
		return length;
	}
	tun_noerror();

	length -= 2;
	if (length < 0)
		return 0;

	memcpy(buffer, data_buffer + 2, length);

	return length;
}

int tunemu_write(int ppp_sockfd, char *buffer, int length)
{
	allocate_data_buffer(length + 4);

	data_buffer[0] = 0x02;
	data_buffer[1] = 0x00;
	data_buffer[2] = 0x00;
	data_buffer[3] = 0x00;

	memcpy(data_buffer + 4, buffer, length);

	if (pcap == NULL)
	{
		tun_error("pcap not open");
		return -1;
	}

	length = pcap_inject(pcap, data_buffer, length + 4);
	if (length < 0)
	{
		tun_error("injecting packet: %s", pcap_geterr(pcap));
		return length;
	}
	tun_noerror();

	length -= 4;
	if (length < 0)
		return 0;

	return length;
}
