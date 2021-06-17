/*
  hpfeeds.c
  Copyright (C) 2011 The Honeynet Project
  Copyright (C) 2011 Tillmann Werner, tillmann.werner@gmx.de

  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License version 2 as 
  published by the Free Software Foundation.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifdef __linux__ 
    #include <arpa/inet.h>
#elif _WIN32
    #include <winsock2.h>
#else
    //placeholder
#endif
#include <hpfeeds.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "sha1.h"


hpf_msg_t *hpf_msg_new(void) {
	hpf_msg_t *msg;

	msg = (hpf_msg_t*)calloc(1, sizeof(hpf_msg_t));
	msg->hdr.msglen = htonl(sizeof(msg->hdr));

	return msg;
}

void hpf_msg_delete(hpf_msg_t *m) {
	if (m) free(m);

	return;
}

hpf_msg_t *hpf_msg_getmsg(u_char *data) {
	return (hpf_msg_t *) data;
}

uint32_t hpf_msg_getsize(hpf_msg_t *m) {
	return ntohl(m->hdr.msglen);
}

uint32_t hpf_msg_gettype(hpf_msg_t *m) {
	return m->hdr.opcode;
}

hpf_msg_t *hpf_msg_add_chunk(hpf_msg_t **m, const u_char *data, size_t len) {
	hpf_msg_t *msg = *m;
	u_char l;

	if (!m || !data || !len)
		return NULL;

	l = (u_char) (len < 0xff ? len : 0xff);

	*m = msg = (hpf_msg_t*) realloc(msg, ntohl(msg->hdr.msglen) + l + 1);

	if (msg == NULL)
		return NULL;

	((u_char *) msg)[ntohl(msg->hdr.msglen)] = l;
	memcpy(((u_char *) msg) + ntohl(msg->hdr.msglen) + 1, data, l);

	msg->hdr.msglen = htonl(ntohl(msg->hdr.msglen) + 1 + l);

	return msg;
}

hpf_chunk_t *hpf_msg_get_chunk(u_char *data, size_t len) {
	hpf_chunk_t *c;

	if (!data || !len) return NULL;

	c = (hpf_chunk_t *) data;

	// incomplete chunk?
	if (c->len > len + 1) return NULL;

	return c;
}

hpf_msg_t *hpf_msg_add_payload(hpf_msg_t **m, const u_char *data, size_t len) {
	hpf_msg_t *msg = *m;

	if (!m || !data || !len)
		return NULL;

	*m = msg = (hpf_msg_t*) realloc(msg, ntohl(msg->hdr.msglen) + len);

	if (msg == NULL)
		return NULL;

	memcpy(((u_char *) msg) + ntohl(msg->hdr.msglen), data, len);

	msg->hdr.msglen = htonl(ntohl(msg->hdr.msglen) + len);

	return msg;
}

hpf_msg_t *hpf_msg_error(u_char *err, size_t err_size) {
	hpf_msg_t *msg;

	msg = hpf_msg_new();

	if (msg == NULL)
		return NULL;

	msg->hdr.opcode = OP_ERROR;

	hpf_msg_add_payload(&msg, err, err_size);

	return msg;
}

hpf_msg_t *hpf_msg_info(uint32_t nonce, u_char *fbname, size_t fbname_len) {
	hpf_msg_t *msg;

	msg = hpf_msg_new();

	if (msg == NULL)
		return NULL;

	msg->hdr.opcode = OP_INFO;

	hpf_msg_add_chunk(&msg, fbname, fbname_len);

	hpf_msg_add_payload(&msg, (u_char *) &nonce, sizeof(uint32_t));

	return msg;
}

hpf_msg_t *hpf_msg_auth(uint32_t nonce, u_char *ident, size_t ident_len, u_char *secret, size_t secret_len) {
	hpf_msg_t *msg;
	SHA1Context ctx;
	u_char hash[SHA1HashSize];

	msg = hpf_msg_new();

	if (msg == NULL)
		return NULL;	

	msg->hdr.opcode = OP_AUTH;

	SHA1Reset(&ctx);
	SHA1Input(&ctx, (u_char *) &nonce, sizeof(nonce));
	SHA1Input(&ctx, (u_char *) secret, secret_len);
	SHA1Result(&ctx, hash);

	hpf_msg_add_chunk(&msg, ident, ident_len);

	hpf_msg_add_payload(&msg, hash, SHA1HashSize);

	return msg;
}

hpf_msg_t *hpf_msg_publish(u_char *ident, size_t ident_len, u_char *channel, size_t channel_len, u_char *data, size_t data_len) {
	hpf_msg_t *msg;

	msg = hpf_msg_new();

	if (msg == NULL)
		return NULL;

	msg->hdr.opcode = OP_PUBLISH;

	hpf_msg_add_chunk(&msg, ident, ident_len);
	hpf_msg_add_chunk(&msg, channel, channel_len);

	hpf_msg_add_payload(&msg, data, data_len);

	return msg;
}

hpf_msg_t *hpf_msg_subscribe(u_char *ident, size_t ident_len, u_char *channel, size_t channel_len) {
	hpf_msg_t *msg;

	msg = hpf_msg_new();

	if (msg == NULL)
		return NULL;

	msg->hdr.opcode = OP_SUBSCRIBE;

	hpf_msg_add_chunk(&msg, ident, ident_len);

	hpf_msg_add_payload(&msg, channel, channel_len);

	return msg;
}

