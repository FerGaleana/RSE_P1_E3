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
#include "aes.h"										// AES128

struct AES_ctx ctx;

uint8_t key[] = "aaaaaaaaaaaaaaaa";
uint8_t Rx_msg1[] = { '-','-','-','-','-','-','-','-','-','R','e','p','l','y','1','\0'};
uint8_t Rx_msg2[] = { '-','-','-','-','-','-','-','-','-','R','e','p','l','y','2','\0'};
uint8_t Rx_msg3[] = { '-','-','-','-','-','-','-','-','-','R','e','p','l','y','3','\0'};
uint8_t Rx_msg4[] = { '-','-','-','-','-','-','-','-','-','R','e','p','l','y','4','\0'};
uint8_t Inv_msg[] = { 'I','n','v','a','l','i','d','-','m','e','s','s','a','g','e','\0'};

uint8_t Tx_msg1[] = { '-','-','-','-','-','-','-','R','e','q','u','e','s','t','1','\0'};
uint8_t Tx_msg2[] = { '-','-','-','-','-','-','-','R','e','q','u','e','s','t','2','\0'};
uint8_t Tx_msg3[] = { '-','-','-','-','-','-','-','R','e','q','u','e','s','t','3','\0'};
uint8_t Tx_msg4[] = { '-','-','-','-','-','-','-','R','e','q','u','e','s','t','4','\0'};

/*-----------------------------------------------------------------------------------*/
static void
tcpecho_thread(void *arg)
{
  struct netconn *conn, *newconn;
  err_t err;
  LWIP_UNUSED_ARG(arg);
  uint8_t Rx_msg[16];
  /* Create a new connection identifier. */
  /* Bind connection to well known port number 7. */
#if LWIP_IPV6
  conn = netconn_new(NETCONN_TCP_IPV6);
  netconn_bind(conn, IP6_ADDR_ANY, 7);
#else /* LWIP_IPV6 */
  conn = netconn_new(NETCONN_TCP);
  netconn_bind(conn, IP_ADDR_ANY, 7);
#endif /* LWIP_IPV6 */
  LWIP_ERROR("tcpecho: invalid conn", (conn != NULL), return;);

  /* Tell connection to go into listening mode. */
  netconn_listen(conn);

  while (1) {

    /* Grab new connection. */
    err = netconn_accept(conn, &newconn);
    /*printf("accepted new connection %p\n", newconn);*/
    /* Process the new connection. */

    AES_init_ctx(&ctx, key);				// AES128

    if (err == ERR_OK) {
      struct netbuf *buf;
      void *data;
      u16_t len;

      while ((err = netconn_recv(newconn, &buf)) == ERR_OK) {
        /*printf("Recved\n");*/
        do {
             netbuf_data(buf, &data, &len);
             PRINTF("Received (enc): %u bytes: %.2x \n", len, (uint8_t*)data);						// Rx:Encriptado
             AES_ECB_decrypt(&ctx, data);	// AES128
             PRINTF("Received (dec): %u bytes: %s \n", len, (char*)data);							// Rx:Desencriptado
             if(strcmp(Tx_msg1,(char*)data) == 0)
             {
            	 PRINTF("Sent (dec): %u bytes: %s \n", sizeof(Rx_msg1), (char*)Rx_msg1);			// Tx:Desencriptado
            	 AES_ECB_encrypt(&ctx, Rx_msg1);	// AES128
            	 err = netconn_write(newconn, Rx_msg1, sizeof(Rx_msg1), NETCONN_COPY);
            	 PRINTF("Sent (enc): %u bytes: %.2x \n", sizeof(Rx_msg1), (uint8_t*)Rx_msg1);		// Tx:Encriptado
             }
             else if(strcmp(Tx_msg2,(char*)data) == 0)
             {
            	 PRINTF("Sent (dec): %u bytes: %s \n", sizeof(Rx_msg2), (char*)Rx_msg2);			// Tx:Desencriptado
                 AES_ECB_encrypt(&ctx, Rx_msg2);	// AES128
                 err = netconn_write(newconn, Rx_msg2, sizeof(Rx_msg2), NETCONN_COPY);
                 PRINTF("Sent (enc): %u bytes: %.2x \n", sizeof(Rx_msg2), (uint8_t*)Rx_msg2);		// Tx:Encriptado
             }
             else if(strcmp(Tx_msg3,(char*)data) == 0)
             {
                 PRINTF("Sent (dec): %u bytes: %s \n", sizeof(Rx_msg3), (char*)Rx_msg3);			// Tx:Desencriptado
                 AES_ECB_encrypt(&ctx, Rx_msg3);	// AES128
                 err = netconn_write(newconn, Rx_msg3, sizeof(Rx_msg3), NETCONN_COPY);
                 PRINTF("Sent (enc): %u bytes: %.2x \n", sizeof(Rx_msg3), (uint8_t*)Rx_msg3);		// Tx:Encriptado
             }
             else if(strcmp(Tx_msg4,(char*)data) == 0)
             {
                 PRINTF("Sent (dec): %u bytes: %s \n", sizeof(Rx_msg4), (char*)Rx_msg4);			// Tx:Desencriptado
                 AES_ECB_encrypt(&ctx, Rx_msg4);	// AES128
                 err = netconn_write(newconn, Rx_msg4, sizeof(Rx_msg4), NETCONN_COPY);
                 PRINTF("Sent (enc): %u bytes: %.2x \n", sizeof(Rx_msg4), (uint8_t*)Rx_msg4);		// Tx:Encriptado
             }
             else
             {
                 PRINTF("Sent (dec): %u bytes: %s \n", sizeof(Inv_msg), (char*)Inv_msg);			// Tx:Desencriptado
                 AES_ECB_encrypt(&ctx, Inv_msg);	// AES128
                 err = netconn_write(newconn, Inv_msg, sizeof(Inv_msg), NETCONN_COPY);
                 PRINTF("Sent (enc): %u bytes: %.2x \n", sizeof(Inv_msg), (uint8_t*)Inv_msg);		// Tx:Encriptado
             }

#if 0
            if (err != ERR_OK) {
              printf("tcpecho: netconn_write: error \"%s\"\n", lwip_strerr(err));
            }
#endif

        } while (netbuf_next(buf) >= 0);
        netbuf_delete(buf);
      }
      /*printf("Got EOF, looping\n");*/
      /* Close connection and discard connection identifier. */
      netconn_close(newconn);
      netconn_delete(newconn);
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
