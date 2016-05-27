#include <stdio.h>
#include "csapp.h"
/* WebProxy Lab */
/* Logging:
 * Log on each line each message:
 * Date: browserIP URL size
 * browserIP is the IP of the client
 * URL is the site URL
 * size is the number of bytes in reply - Received from end server from when the connection is opened to closed
 * Only requests met be a response are logged.
 */
/* HTTP Requset Format:
 * COMMAND URL VERSION\r\n
 * blah blah\r\n
 * \r\n
 * HTTP Reply Format:
 * VERSION CODE STATUS\r\n
 * blah\r\n
 * \r\n

/* Error Codes */
#define SUCCESS 1
#define SOCK_FAILURE -1
#define SOCK_OPT_FAILURE -2
#define SOCK_BIND_FAILURE -3
#define SOCK_LISTEN_FAILURE -4

#define DEFAULT_PORT 0
//Parse Message functions
//Create HTTP functions
//Log functions
int initClient(char* hostname, int port) {

}

int initServer(int port) {
    /* Options value for setsockopt */
    int optval = 1;
    /* Socket Address, includes port */
    struct sockaddr_in server_addr;
    /* Create Socket */
    int serverSock = Socket(AF_INET,SOCK_STREAM,0);
    if (serverSock < 0) return SOCK_FAILURE;
    /* Set Socket Options */
    /* Let us rerun the server immediately after killing it */
    if (Setsockopt(socket,SOL_SOCKET,SO_REUSEADDR,(const void*)&optval,sizeof(int)) < 0) return SOCK_OPT_FAILURE;
    /* Set address to all zero */
    bzero((char*)&server_addrr,sizeof(server_addr));
    /* Set the Socket Address */
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons((unsigned short)port);
    /* Bind Socket Address to Socket */
    if (Bind(serverSock,(SA*)&server_addr,sizeof(server_addr)) < 0) return SOCK_BIND_FAILURE;
    /* Set Socket to Listen */
    if(Listen(serverSock,LISTENQ) < 0) return SOCK_LISTEN_FAILURE;

    return serverSock;
}

int main(int argc, char *argv[]) {
    int port = DEFAULT_PORT;
    if (argc > 1) {
        port = atoi(argv[1]);
    }
	/* Client will connect to this server IP explicitly */
    /* Create and Set Server-Side Socket */
    int serverSock = initServer(port);
    while (1) { /* Main Loop */
        //Listen for connection request
        //Accept if able
        //Receive HTTP request via read
        //Parse request to isolate the request header
		//Get URL and find associated IP from the host via  gethostbyname and inet_ntoa
        //Create Client Socket and Connect to End Server
        //Create new HTTP request using the old one
        //Receive HTTP reply via reio_readlineb
        //Parse reply to isolate the reply header
		//Do things depending on the code
		//Find the size of the reply
		//Log if able
		//Create new HTTP reply from old one
        //Send HTTP reply via rio_writen
        //Close connection to end server via send EOF via close
		//Close connection to client if EOF from client via readlineb
    }
	//Close listening socket
    return 0;
    /* FROM THE POWER POINT on Echo Server
     * int listenfd, connfd, port, clientlen;
    struct sockaddr_in clientaddr;
    struct hostent *hp;
    char *haddrp;
    unsigned short client_port;

    port = atoi(argv[1]);
    listenfd = open_listenfd(port);

    while (1) {
        clientlen = sizeof(clientaddr);
        connfd = Accept(listenfd, (SA *)&clientaddr, &clientlen);
        hp = Gethostbyaddr((const char *)&clientaddr.sin_addr.s_addr,
                        sizeof(clientaddr.sin_addr.s_addr), AF_INET);
        haddrp = inet_ntoa(clientaddr.sin_addr);
        client_port = ntohs(clientaddr.sin_port);
        printf("server connected to %s (%s), port %u\n",
                hp->h_name, haddrp, client_port);
        echo(connfd);
        Close(connfd);
    }
    */
    /* FROM THE POWER POINT on Echo Client
     * int clientfd, port;
    char *host, buf[MAXLINE];
    rio_t rio;
    host = argv[1];  port = atoi(argv[2]);
    clientfd = Open_clientfd(host, port);
    Rio_readinitb(&rio, clientfd);
    printf("type:"); fflush(stdout);
    while (Fgets(buf, MAXLINE, stdin) != NULL) {
        Rio_writen(clientfd, buf, strlen(buf));
        Rio_readlineb(&rio, buf, MAXLINE);
        printf("echo:");
        Fputs(buf, stdout);
        printf("type:"); fflush(stdout);
    }
    Close(clientfd);
    exit(0);
    */
}
