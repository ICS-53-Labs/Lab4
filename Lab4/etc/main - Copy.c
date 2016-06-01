
//TODO: NAMES
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
 */
 /* Compile with gcc .c .c -lpthread -o name */
 
 
/* Error Codes */
#define SUCCESS 1
#define SOCK_FAILURE -1
#define SOCK_OPT_FAILURE -2
#define SOCK_BIND_FAILURE -3
#define SOCK_LISTEN_FAILURE -4
#define RIO_READ_FAILURE -5
#define BAD_REQUEST_HEADER -6
#define BAD_VERSION -7
#define NOT_GET -8
#define BAD_URI -9
#define HOST_TO_IP_FAILURE -10
#define RIO_WRITE_FAILURE -11
#define BAD_RESPONSE_HEADER -12
#define CONNECT_FAILURE -13
#define BAD_FILE -14
#define UNKNOWN_FAILURE -15
#define BAD_PORT -16

#define DEFAULT_PORT 0
#define REALLOC 2
#define HTTP_VER_0 "HTTP/1.0"
#define HTTP_VER_1 "HTTP/1.1"
#define OK 200
#define LOG_NAME "proxy.log"
#define MIN_PORT 1024
#define MAX_PORT 65536

#define GET_ONLY 1
#define DEBUG 0
#define NFO 1

FILE* log_file;
char* errorLookUp(int code) {
	switch(code) {
		case SUCCESS:				return "Success";
		case SOCK_FAILURE:			return "Socket Creation Failure";
		case SOCK_OPT_FAILURE:		return "Socket Option Failure";
		case SOCK_BIND_FAILURE:		return "Socket Bind Failure";
		case SOCK_LISTEN_FAILURE:	return "Socket Listen Failure";
		case RIO_READ_FAILURE:		return "Rio_Read Failure";
		case BAD_REQUEST_HEADER:	return "Bad Request Header Format";
		case BAD_VERSION:			return "Bad Version";
		case NOT_GET:				return "Method is not GET";
		case BAD_URI:				return "Bad URL";
		case HOST_TO_IP_FAILURE:	return "Host to IP Convert Failure";	
		case RIO_WRITE_FAILURE:		return "Rio_Write Failure";
		case BAD_RESPONSE_HEADER:	return "Bad Response Header Format";
		case CONNECT_FAILURE:		return "Connection Failure";	
		case BAD_FILE:				return "Bad File";
		case UNKNOWN_FAILURE:		return "Unknown Failure";
		case BAD_PORT:				return "Bad Port";
		default: 					return "Unknown Code";
	}
}

int readRequest(int* sock, char* buf, int* size) {
	*size = 0;
	if(DEBUG)printf("In reading...\n");
	rio_t rio; /* Rio buffer */
	int res;
	int alloc = REALLOC;
	int curr = MAXLINE;
	char buffer[MAXLINE]; /* Temporary buffer */

	Rio_readinitb(&rio,*sock);
	while (1) {
		/* Read in one line */
		if(DEBUG)printf("rio reading...\n");
		res = Rio_readlineb(&rio,buffer,MAXLINE);
		if(DEBUG && 0)printf("FInished rio reading: res: %d buffer:%s\n",res,buffer);
		if (res < 0){ /* Error with Client buf */
			return RIO_READ_FAILURE;
		}

		/* Make room in buffer if needed */
		/* Res is the number of bytes read in */
		if (*size + res + 1 > curr){
			if(DEBUG)printf("not enough room: news: %d cur:%d\n",*size + res + 1, curr);
			curr *= alloc;
			Realloc(buf,curr);
		}
		/* Add to buf buffer */
		if(DEBUG)printf("cating...\n");
		strcat(buf,buffer);
		if(DEBUG)printf("Finished cating: buf:%s buffer:%s\n",buf,buffer);
		*size += res;
		if(DEBUG)printf("new size:%d\n",*size);
		/* Check for end of buf. Terminated by an \r\n on its own line */
		if (strcmp(buffer, "\r\n") == 0) {
			if(DEBUG)printf("Found terminator\n");
			buf[*size] = '\0';
			return SUCCESS;
		}
	}
	return UNKNOWN_FAILURE;
}

int readAndForwardResponse (int* readSock, int* writeSock, char* buf, int* size, int* status) {
	if(DEBUG)printf("read:%d,write:%d\n",*readSock,*writeSock);
	rio_t rio;
	*size = 0;
	int res;
	int alloc = MAXLINE;
	char buffer[MAXLINE];
	if(DEBUG)printf("init\b");
	Rio_readinitb(&rio,*readSock);
	if(DEBUG)printf("Entering while\n");
	res = Read(*readSock,buffer,MAXLINE);
	if(DEBUG)printf("Read res: %d\n",res);
	
	char vers[MAXLINE], code[MAXLINE];
	sscanf(buffer,"%s %s ",vers,code);
	*status = atoi(code);
	if (NFO) printf("*** Status Code ***\n%d\n",*status);
	if(NFO) printf("*** Response from Server and to Client ***\n");
	//while ((res = Rio_readn(*readSock,buffer,MAXLINE)) > 0) {
	while (res > 0) {
		*size += res;
		if(DEBUG)printf("new size:%d\n",*size);
		//Rio_writen(*writeSock,buffer,res);
		Write(*writeSock,buffer,res);
		if(NFO)printf("%s",buffer);
		if(DEBUG) printf("Wrote\n");
		bzero(buffer,MAXLINE);
		if(DEBUG) printf("zeroed\n");
		
		if(0 && res < MAXLINE) {
			return SUCCESS;
		}
		res = Read(*readSock,buffer,MAXLINE);
		if(DEBUG)printf("Read res: %d\n",res);
	}
	if(DEBUG)printf("///COMPLETE///\n");
	return SUCCESS;
}

int sendRequest(int* clientSock, char* method, char* uri, int ver, char* rest) {
	if(DEBUG) printf("In sending request...\n");
	if (ver != 1 && ver != 0) return BAD_VERSION;
	/* Send Header */
	if(DEBUG)printf("THe message being sent: \n");
	if(NFO) printf("*** Request (from Proxy) ***\n");
	if (rio_writen(*clientSock,method,strlen(method)) != strlen(method)) 
		return RIO_WRITE_FAILURE;
	if(DEBUG || NFO)printf("%s",method);
	if (rio_writen(*clientSock," ",1) != 1)
		return RIO_WRITE_FAILURE;
	if(DEBUG || NFO)printf(" ");
	if (rio_writen(*clientSock,uri,strlen(uri)) != strlen(uri))
		return RIO_WRITE_FAILURE;
	if(DEBUG || NFO)printf("%s",uri);
	if (rio_writen(*clientSock,(ver == 1 ? " HTTP/1.1\r\n" : " HTTP/1.0\r\n"),strlen(" HTTP/1.1\r\n")) != strlen(" HTTP/1.1\r\n"))
		return RIO_WRITE_FAILURE;
	if(DEBUG || NFO)printf("%s",(ver == 1 ? " HTTP/1.1\r\n" : " HTTP/1.0\r\n"));
	/* Send the rest */
	if (rio_writen(*clientSock,rest,strlen(rest)) != strlen(rest))
		return RIO_WRITE_FAILURE;
	if(DEBUG || NFO)printf("%s",rest);
	return SUCCESS;
}

int sendResponse(int* connSock, char* response, int responselen) {
	Rio_writen(*connSock,response,responselen);
	if(DEBUG||NFO) printf("*** Response (from Proxy) ***\n%s\n",response);
	return SUCCESS;
}

int tokenizeHeader(char* uri, char* method, char* rest, int* ver, char* request, char* request_end) {
	if (0) {
		char* header_ptr = request; /* HTTP request header pointer */
		char* header_end = strpbrk(request,"\r\n");  /* Pointer to the very next char after the header */
		request_end = header_end;
		if (!header_end) return BAD_REQUEST_HEADER; /* If \r\n does not exist in the buffer */
		
		/* Check to make sure the header is of the form */
		char* method_ptr = header_ptr; /*Pointer to the method */
		char* method_end = strpbrk(request," "); /* End method */
		if (!method_end) return BAD_REQUEST_HEADER;
		
		char* uri_ptr = method_end + 1; /* Pointer to the URI */
		char* uri_end = strpbrk(method_end," "); /* End URI */
		if (!uri_end) return BAD_REQUEST_HEADER;
		
		char* ver_ptr = uri_end + 1; /* Pointer to the Version */
		char* ver_end = strpbrk(uri_end," "); /* End Version */
		if (!ver_end) return BAD_REQUEST_HEADER;
		if (GET_ONLY && strncmp(method_ptr,"GET",sizeof("GET")) != 0) {
		return NOT_GET;
		}
			/* Check Version */
		if (strncmp(ver_ptr,HTTP_VER_0,strlen(HTTP_VER_0)) == 0) {
			*ver = 0;
		}
		else if (strncmp(ver_ptr,HTTP_VER_1,strlen(HTTP_VER_1)) == 0) {
			*ver = 1;
		}
		else {
			*ver = -1;
			return BAD_VERSION;
	
		}
		/* Extract the URL from the first token */
		strncpy(uri,uri_ptr,uri_end - uri_ptr); /* Copy the URI */
		uri[uri_end - uri_ptr] = '\0';
		/* Extract the Method */
		strncpy(method,method_ptr,method_end - method_ptr);
		method[method_end - method_ptr] = '\0';
		/* Extract the Rest */
		char* rest_ptr = header_end + 2;
		strncpy(rest,rest_ptr,strlen(rest_ptr));
		rest[strlen(rest_ptr)] = '\0';
		return SUCCESS;
	}
	char vers[MAXLINE];

	//Maybe use sscanf(buffer,"%s %s %s",method,uri,version) instead of the above
	sscanf(request, "%s %s %s",method,uri,vers);
	if(DEBUG)printf("method:%s,uri:%s,vers:%s||\n",method,uri,vers);
	char* ptr = request;
	int moveup = strlen(method) + strlen(uri) + strlen(vers) + 4;
	if(DEBUG)printf("mvoeup:%d\n",moveup);
	ptr += moveup;
	if(DEBUG) printf("ptr:%s\n",ptr);
	request_end = strpbrk(request,"\r\n");
	if(DEBUG) printf("request_end:%s\n",request_end);
	if(DEBUG)printf("request:%s\n",request);
	strncpy(rest,ptr,strlen(request) - strlen(ptr));
	/* Only for GET ONLY */
	if (GET_ONLY && strcasecmp(method,"GET")) return NOT_GET;
	if (strncasecmp(vers,HTTP_VER_0,strlen(HTTP_VER_0)) == 0)
		*ver = 0;
	else if (strncasecmp(vers,HTTP_VER_1,strlen(HTTP_VER_1)) == 0)
		*ver = 1;
	else
		return BAD_VERSION;
	return SUCCESS;
}

int parseURI(char* uri, char* host, char* path, int* port) {
	if(DEBUG) printf("Entering parsing...\n");
	char* begin = uri;
	char* end;
	char* pbegin;
	char* porten;
	char portn [MAXLINE];
	int https;
	/* Check for http:// or https:// */
	if(DEBUG)printf("Checking for URI HTTP:// ...\n");
	if (strncmp(uri,"http://",strlen("http://")) == 0)
		https = 0;
	else if (strncmp(uri,"https://",strlen("https://")) == 0)
		https = 1;
	else return BAD_URI;
	if(DEBUG) printf("URI has HTTP://\n");
	/* host name is www.~~~.~~~ */
	begin += (https == 1 ? strlen("https://") : strlen("http://"));
	if(DEBUG)printf("Added HTTP size to begin: %s\n",begin);
	end = strpbrk(begin,"/:\r\n\0");
	if (!end && begin[strlen(begin)] == '\0')
		end = begin + strlen(begin);
	else if (!end) return BAD_URI;
	if(DEBUG)printf("Found end: %s\n",end);
	if(DEBUG)printf("Copying from begin to host, this many bytes:%d...\n",end-begin);
	strncpy(host,begin,end - begin);
	host[end - begin] = '\0';
	if(DEBUG)printf("Host:%s\n",host);
	/* port is after the : at the end of host */
	if (*end == ':') {
		if(DEBUG)printf("Port Number Found\n");
		porten = strpbrk(end,"/\r\n\0");
		if(DEBUG)printf("porten:%s\n",porten);
		strncpy(portn,end + 1, porten - end - 1);
		if(DEBUG)printf("Copied this many bytes: %d\n",porten-end-1);
		portn[porten - end - 1] = '\0';
		if(DEBUG)printf("portn:%s\n",portn);
		*port = atoi(portn);
	}
	else *port = 80; /* Default HTTP Port */
	if(DEBUG)printf("port:%d\n",*port);
	/* path begins at the next char to end of uri */
	if(DEBUG)printf("Finding path...\n");
	pbegin = strchr(begin,'/');
	if(DEBUG)printf("pbegin:%s\n",pbegin);
	if (!pbegin) path[0] = '\0';
	else {
		//++pbegin; //Removes the first/
		strcpy(path,pbegin);
	}
	if(DEBUG)printf("path:%s\n",path);
	return SUCCESS;
}

int logInfo (struct sockaddr_in* addr, char* uri, int size) {
	if(DEBUG) printf("In loggin...\n");
	/* Get Date */
	time_t this_time = time(NULL);
	char date[MAXLINE];
	if(DEBUG)printf("Grabbing time...");
	strftime(date,MAXLINE,"%a %d %b %Y %H:%M:%S %Z", localtime(&this_time));
	if(DEBUG)printf("date:%s\n",date);

	char* ip = inet_ntoa(addr->sin_addr);
	if(DEBUG)printf("ip;%s\n",ip);
	if(DEBUG)printf("Printing to log...\n");
	fprintf(log_file,"%s: %s %s %d\n",date,ip,uri,size);
	if(NFO)printf("*** Logging Information ***\nDate: %s\nIP: %s\nURI: %s\nSize: %d\n",date,ip,uri,size);
	if(DEBUG)printf("Done\n");
	fflush(log_file);
	return SUCCESS;
}

int process(int* connSock, struct sockaddr_in* clientaddr) {
	if(DEBUG) printf("Entering processing...\n");
	struct hostent* hp; /* Host Address */
	unsigned short clientport; /* Client port number */
	
	char* request_buffer; /* HTTP request buffer */
	request_buffer = (char*)Malloc(MAXLINE);
	request_buffer[0] = '\0';
	int requestlen = 0;
	/* Read in HTTP request */
	if(DEBUG) printf("Reading from Socket...\n");
	int res = readRequest(connSock,request_buffer,&requestlen);
	if (res != SUCCESS) {
		free(request_buffer);
		return res;
	}
	if(NFO)printf("*** Request from Client ***\n");
	if(NFO || DEBUG) printf("%s\n", request_buffer);
	if(DEBUG) printf("Finished Reading Request: %s\n",request_buffer);
	/* Parse HTTP request and split header i
	nto uri, method, and version */
	char uri[MAXLINE], method[MAXLINE], rest[MAXLINE]; char* end;
	int ver;
	if(DEBUG) printf("Tokenizing request...\n");
	res = tokenizeHeader(uri,method,rest,&ver,request_buffer,end);
	if (res != SUCCESS) {
		free(request_buffer);
		return res;
	}
	if(DEBUG) printf("Finished Tokenizing request: uri:%s,method:%s,ver:%d,rest:%s\n",uri,method,ver,rest);
	if(NFO)printf("*** Request Header Info ***\n");
	if(NFO) printf("Method: %s\nURI: %s\nVersion: HTTP/1.%d\nRest of Request: %s\n",method,uri,ver,rest);
	/* Get Hostname from URL */
	char host[MAXLINE], path[MAXLINE];
	int port;
	if(DEBUG) printf("Parsing uri...\n");
	res = parseURI(uri,host,path,&port);
	if (res != SUCCESS) return res;
	if(DEBUG) printf("Finished Parsing URI: host:%s,path:%s,port:%d\n",host,path,port);
	if(NFO) printf("*** URI Info ***\n");
	if(NFO) printf("Host: %s\nPath: %s\nPort: %d\n",host,path,port);
	/* Get IP and Port from Host */
	/* Create Client Socket */
	struct sockaddr_in end_server;
	int clientSock;
	if(DEBUG) printf("Creating client Socket...");
	char portc[15];
	printf(portc,15,"%d",port);
	clientSock = Open_clientfd(host,portc);
	if(clientSock < 0) return SOCK_FAILURE;
	if(DEBUG) printf("Finished\n");
	if(DEBUG)printf("clientSock:%d\n",clientSock);
	/* Forward the HTTP request */
	if(DEBUG) printf("Sending request...\n");
	res = sendRequest(&clientSock,method,uri,ver,rest);
	if(DEBUG) printf("Finished sending request\n");
	/* Get HTTP response *//* Read HTTP response */
	char* response_buffer = (char*)Malloc(MAXLINE);
	int responselen = 0;
	int status;
	if (0){
		if(DEBUG) printf("Reading response...\n");
		
		if (res != SUCCESS) {
			free(request_buffer);
			free(response_buffer);
			return res;
		}
		if(DEBUG) printf("Finished reading response: %s\n",response_buffer);
		if (NFO) printf("*** Response from Server ***\n");
		if(NFO) printf("%s\n",response_buffer);
		/* Forward response */
		if(DEBUG)printf("Sending response...\n");
		res = sendResponse(connSock,response_buffer,responselen);
		if (res != SUCCESS) {
			free(request_buffer);
			free(response_buffer);
			return res;
		}
		if(DEBUG)printf("Finished sending response\n");
	}
	else {
		if(DEBUG) printf("Reading and Forwarding response...\n");
		res = readAndForwardResponse(&clientSock,connSock,response_buffer,&responselen,&status);
		if (res != SUCCESS) {
			free(request_buffer);
			free(response_buffer);
			return res;
		}
		if(DEBUG) printf("Finished reading response: %s\n",response_buffer);
		//if (NFO) printf("*** Response from Server and to Client ***\n");
		//if(NFO) printf("%s\n",response_buffer);
	}
	/* Assume the server does things well i.e. the response is of form */
	/* Check status for OK */
	if (status == OK) {
		/* Log information */
		if(DEBUG) printf("Logging info...\n");
		res = logInfo(clientaddr,uri,responselen);
		if (res != SUCCESS) {
			free(request_buffer);
			free(response_buffer);
			return res;
		}
		if(DEBUG) printf("Finished logging info\n");
	}

	/* Clean Up Dynamic Memory */
	free(request_buffer);
	free(response_buffer);
	/* Close client connection */
	close(clientSock);
	return SUCCESS;
}
void cleanup() {
	//Close(*sock);
	fclose(log_file);
}

int main(int argc, char *argv[]) {
	atexit(cleanup); //Fix this for listen close
	if(DEBUG) printf("Starting program...\n");
    int port = DEFAULT_PORT, res;
    if (argc > 1) {
		port = atoi(argv[1]);
		if (port < MIN_PORT || port > MAX_PORT) {
			printf("Error: %s\n",errorLookUp(BAD_PORT));
			exit(0);
		}
    }
	char portc[15];
	snprintf(portc,15,"%d",port);
	if(DEBUG) printf("Proxy Port is: %d\n",port);
	/* Open Log File */
	if(DEBUG) printf("Opening file %s...\n",LOG_NAME);
	log_file = Fopen(LOG_NAME, "a"); /* "a" mode appends to file */
	if (log_file == NULL) {
		printf("Error: %s\n",errorLookUp(BAD_FILE));
		//fclose(log_file);
		exit(0);
	}
    /* Create and Set Server-Side Listen Socket */
    int serverSock;
	if(DEBUG) printf("Creating server socket...\n");
	if(0) {
		res = initServer(port,&serverSock);
		if (res != SUCCESS) {
			printf("Error: %s\n",errorLookUp(res));
			fclose(log_file);
			exit(0);
		}
	}
	serverSock = Open_listenfd(portc);
	int connSock, clientlen; /* Connection Socket, Length of client address */
	struct sockaddr_in clientaddr; /* Client Address Socket */
	
	if(DEBUG) printf("Entering main loop...\n");
    while (1) { /* Main Loop */
		/* Accept connection */
		if(DEBUG) printf("Calculating Client Addr Len...");
		clientlen = sizeof(clientaddr);
		if(DEBUG) printf("%d\n",clientlen);
		if(DEBUG) printf("Listening and Accepting...");
		connSock = Accept(serverSock,(SA*)&clientaddr,&clientlen);
		if(DEBUG || NFO) {
			struct hostent* hp = Gethostbyaddr((const char*)&clientaddr.sin_addr.s_addr,sizeof(clientaddr.sin_addr.s_addr),AF_INET);
			char* haddrp = inet_ntoa(clientaddr.sin_addr);
			printf("*** Connection Info ***\nAccepted Connection: @ %s(%s)\n",hp->h_name,haddrp);
		}
		if(DEBUG)printf("Processing request...\n");
		res = process(&connSock,&clientaddr);
		if (res != SUCCESS) printf("Error: %s\n",errorLookUp(res));
		if(DEBUG) printf("Finished processing and closing\n");
		Close(connSock);
		if(DEBUG) printf("Closed connection to client...\n");
		//How to exit though? so that we can close the listen socket and the file
    }
    return 0;
}
