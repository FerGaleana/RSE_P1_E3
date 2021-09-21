/*
 * Copyright (c) 2001-2003 Swedish Institute of Computer Science.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT
 * SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 * IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 *
 * This file is part of the lwIP TCP/IP stack.
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */
#include "tcpecho.h"
#include "lwip/opt.h"

#if LWIP_NETCONN

#include "lwip/sys.h"
#include "lwip/api.h"
#include "aes.h"																			// AES128

/* IP address SERVER = 192.168.0.103 */														// SERVER IP
#define serverIP_ADDR0 192																	// IP NET
#define serverIP_ADDR1 168																	// IP NET
#define serverIP_ADDR2 0																	// IP NET
#define serverIP_ADDR3 102																	// IP HOST
#define TOTAL_MSGS		4

struct AES_ctx ctx;

uint8_t key[]     = "aaaaaaaaaaaaaaaa";
uint8_t Tx_msg[TOTAL_MSGS][16] = {{ '-','-','-','-','-','-','-','R','e','q','u','e','s','t','1','\0'},
								{ '-','-','-','-','-','-','-','R','e','q','u','e','s','t','2','\0'},
								{ '-','-','-','-','-','-','-','R','e','q','u','e','s','t','3','\0'},
								{ '-','-','-','-','-','-','-','R','e','q','u','e','s','t','4','\0'}};

/*-----------------------------------------------------------------------------------*/
static void
tcpecho_thread(void *arg)
{
  struct netconn *conn, *newconn;
  err_t err;
  LWIP_UNUSED_ARG(arg);

  ip4_addr_t server_ipaddr;																	// SERVER IP
  IP4_ADDR(&server_ipaddr, serverIP_ADDR0, serverIP_ADDR1, serverIP_ADDR2, serverIP_ADDR3);	// SERVER IP

  struct netbuf *buf;
  void *data;
  u16_t len;
  u8_t msg_counter;

  /* Create a new connection identifier. */
  /* Bind connection to well known port number 7. */
#if LWIP_IPV6
  conn = netconn_new(NETCONN_TCP_IPV6);
  //netconn_bind(conn, IP6_ADDR_ANY, 7);
#else /* LWIP_IPV6 */																		// CLIENT
  conn = netconn_new(NETCONN_TCP);															// socket()
  //netconn_bind(conn, IP_ADDR_ANY, 7);										   				Delete bind()
#endif /* LWIP_IPV6 */
  LWIP_ERROR("tcpecho: invalid conn", (conn != NULL), return;);

  /* Tell connection to go into listening mode. */

  while (1) {
	  //Connect
	  err = netconn_connect(conn, &server_ipaddr, 7);	  	  	  	  	  					// connect()
	  AES_init_ctx(&ctx, key);																// AES128
	  for(msg_counter= 0; msg_counter<TOTAL_MSGS; msg_counter++)
	  {
		  if (err == ERR_OK) {
			  PRINTF("Sent (normal) %u bytes: %s\n", sizeof(Tx_msg[msg_counter]),(char*)Tx_msg[msg_counter]);
			  AES_ECB_encrypt(&ctx, Tx_msg[msg_counter]);						// AES128
			  err = netconn_write(conn, (void*)Tx_msg[msg_counter], sizeof(Tx_msg[msg_counter]), NETCONN_COPY);			// write()
			  PRINTF("Sent (enc) %u bytes: %.2x \n", sizeof(Tx_msg[msg_counter]), (uint8_t*)Tx_msg[msg_counter]);

			  while((err = netconn_recv(conn, &buf)) == ERR_OK){
			  do {
				  netbuf_data(buf, &data, &len);											// read()
				  PRINTF("Received (enc) %u bytes: %.2x \n",len,(uint8_t*)data);
				  AES_ECB_decrypt(&ctx, data);				// AES128
				  PRINTF("Received (normal) %u bytes: %s \n", len, (char*)data);
			  } while (netbuf_next(buf) >= 0);
			  netbuf_delete(buf);
		  }
	  }
	  }
	  /* Process the new connection. */

	  /* Close connection and discard connection identifier. */
	  if (err == ERR_OK)
	  {
		  netconn_close(conn);																// close()
		  netconn_delete(conn);
	  }
  }
}
/*-----------------------------------------------------------------------------------*/
void
tcpecho_init(void)
{
  sys_thread_new("tcpecho_thread", tcpecho_thread, NULL, DEFAULT_THREAD_STACKSIZE, DEFAULT_THREAD_PRIO);
}
/*-----------------------------------------------------------------------------------*/

#endif /* LWIP_NETCONN */
