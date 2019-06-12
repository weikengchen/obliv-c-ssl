// --------------------------- TLS trans -----------------------------------

// TLS connections for 2-Party protocols. Ignores src/dest parameters
//   since there is only one remote

// For two-party computation with semi-honest security, we only ensure
//   authenticity, but no confidentiality of the two parties' transcript.

typedef struct ssl2PTransport
{ ProtocolTransport cb;
  int sock;
  bool isClient;
  bool isProfiled;
  bool needFlush;
  bool keepAlive;
  int sinceFlush;
  size_t bytes;
  size_t flushCount;
  struct ssl2PTransport* parent;

  SSL_CTX *shared_ssl_ctx;
  SSL *ssl_socket;
} ssl2PTransport;

// Profiling output
size_t ssl2PBytesSent(ProtocolDesc* pd) { return ((ssl2PTransport*)(pd->trans))->bytes; }
size_t ssl2PFlushCount(ProtocolDesc* pd) { return ((ssl2PTransport*)(pd->trans))->flushCount; }

static int ssl2PSend(ProtocolTransport* pt, int dest, const void* s, size_t n)
{
  struct ssl2PTransport* sslt = CAST(pt);
  size_t n2 = 0;
  sslt->needFlush = true;
  while(n > n2) {
    int res = SSL_write(sslt->ssl_socket, ((char*)s) + n2, n - n2);
    if(res < 0) { perror("SSL write error: "); return res; }
    n2 += res;
  }
  return n2;
}

static int ssl2PSendProfiled(ProtocolTransport* pt, int dest, const void* s, size_t n)
{
  struct ssl2PTransport* sslt = CAST(pt);
  size_t res = ssl2PSend(pt, dest, s, n);
  if (res >= 0) sslt->bytes += res;
  return res;
}

static int ssl2PRecv(ProtocolTransport* pt, int src, void* s, size_t n)
{
  struct ssl2PTransport* sslt = CAST(pt);
  int res = 0, n2 = 0;
  if(sslt->needFlush) {
    transFlush(pt);
    sslt->needFlush = false;
  }

  while(n > n2) {
    res = SSL_read(sslt->ssl_socket, ((char*)s) + n2, n - n2);
    if(res < 0 || BIO_eof(SSL_get_rbio(sslt->ssl_socket))) {
      perror("SSL read error: ");
      return res;
    }
    n2 += res;
  }
  return res;
}

static int ssl2PFlush(ProtocolTransport* pt)
{
  struct ssl2PTransport* sslt = CAST(pt);
  return BIO_flush(SSL_get_wbio(sslt->ssl_socket));
}

static int ssl2PFlushProfiled(ProtocolTransport* pt)
{
  struct ssl2PTransport* sslt = CAST(pt);
  if(sslt->needFlush) sslt->flushCount++;
  return ssl2PFlush(pt);
}

static void ssl2PCleanup(ProtocolTransport* pt)
{
  struct ssl2PTransport* sslt = CAST(pt);
  BIO_flush(SSL_get_wbio(sslt->ssl_socket));
  if(!sslt->keepAlive){
    SSL_shutdown(sslt->ssl_socket);
    close(sslt->sock);
  }
  SSL_free(sslt->ssl_socket);
  free(pt);
}

static void ssl2PCleanupProfiled(ProtocolTransport* pt)
{
  struct ssl2PTransport* sslt = CAST(pt);
  sslt->flushCount++;
  if(sslt->parent != NULL) {
    sslt->parent->bytes += sslt->bytes;
    sslt->parent->flushCount += sslt->flushCount;
  }
  ssl2PCleanup(pt);
}

static ProtocolTransport* ssl2PSplit(ProtocolTransport* tsrc);

static const ssl2PTransport ssl2PTransportTemplate
  = {{.maxParties = 2, .split = ssl2PSplit, .send = ssl2PSend, .recv = ssl2PRecv, .flush = ssl2PFlush,
      .cleanup = ssl2PCleanup},
     .sock = 0, .isClient = 0, .needFlush = false, .bytes = 0, .flushCount = 0,
     .parent = NULL, .shared_ssl_ctx = NULL, .ssl_socket = NULL};

static const ssl2PTransport ssl2PProfiledTransportTemplate
  = {{.maxParties = 2, .split = ssl2PSplit, .send = ssl2PSendProfiled, .recv = ssl2PRecv,
     .flush=ssl2PFlushProfiled, .cleanup = ssl2PCleanupProfiled},
     .sock = 0, .isClient = 0, .needFlush = false, .bytes = 0, .flushCount = 0,
     .parent = NULL, .shared_ssl_ctx = NULL, .ssl_socket = NULL};

/*
* Using the code from https://github.com/okba-zoueghi/tls_examples
* for the context creation and auxiliary functions
*/
#define LOG_ERROR(msg) printf("[ERROR] : %s\n", msg)
#define LOG_INFO(msg) printf("[INFO] : %s\n", msg)

/*
* For every initialization of protocol using protocolConnectSSL2P or protocolConnectSSL2P,
* the program takes the IP address of the other party as the identity.
*
* This is to allow in one program multiple instances of Obliv-C can be invoked with different parties in different PSK.
*/
typedef struct _ssl_key_dictionary {
  struct _ssl_key_dictionary *next;
  char identity[40];
  unsigned char key[16];
} ssl_key_dictionary;

ssl_key_dictionary *ssl_key_dictionary_head = NULL;

unsigned char* ssl_key_dictionary_search(ssl_key_dictionary *head, char *target_identity){
  ssl_key_dictionary *cur = head;

  while(cur != NULL) {
    if(strcmp(cur->identity, target_identity) == 0){
      return cur->key;
    }
  }

  return NULL;
}

ssl_key_dictionary* ssl_key_dictionary_insert(ssl_key_dictionary *head, char *new_identity, unsigned char *new_key){
  ssl_key_dictionary *new_cur = (ssl_key_dictionary*) malloc(sizeof(ssl_key_dictionary));

  if(new_cur == NULL) {
    LOG_ERROR("Cannot allocate space for the linked list.");
    exit(EXIT_FAILURE);
  }

  new_cur->next = head;
  strcpy(new_cur->identity, new_identity);
  memcpy(new_cur->key, key, 16);

  return new_cur;
}

unsigned int ssl_server_callback(SSL *ssl, const char *identity, unsigned char *psk, int max_psk_len){
  unsigned char *key = ssl_key_dictionary_search(ssl_key_dictionary_head, identity);

  if(key == NULL) {
    LOG_ERROR("Cannot find the key for this identity (IP address).");
    exit(EXIT_FAILURE);
  }

  
}

void ssl_library_init(){
  static init_done = 0;

  if(init_done == 0){
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    init_done = 1;
  }
}

SSL_CTX* ssl_get_ctx(){
  static SSL_CTX *saved_ctx = NULL;

  if(saved_ctx == NULL){
    const SSL_METHOD * method = TLSv1_method();
    if(!method) {
      LOG_ERROR("Failed to create method");
      exit(EXIT_FAILURE);
    }

    saved_ctx = SSL_CTX_new(method);
    if(!saved_ctx) {
      LOG_ERROR("Failed to create context");
      exit(EXIT_FAILURE);
    }

    if(!SSL_CTX_set_cipher_list(ctx, "PSK-NULL-SHA256")) {
      LOG_ERROR("Failed to cipher suites list for TLS v1.2");
      exit(EXIT_FAILURE);
    }
  }

  return saved_ctx;
}


// isClient value will only be used for the split() method, otherwise
// its value doesn't matter. In that case, it indicates which party should be
// the server vs. client for the new connections (which is usually the same as
// the old roles).
static ssl2PTransport* ssl2PNew(int sock, bool isClient, bool isProfiled) {
  ssl2PTransport* trans = malloc(sizeof(*trans));
  if (isProfiled) {
    *trans = ssl2PProfiledTransportTemplate;
  } else {
    *trans = ssl2PTransportTemplate;
  }
  trans->sock = sock;
  trans->isProfiled = isProfiled;
  trans->isClient = isClient;
  trans->sockStream = fdopen(sock, "rb+");
  trans->sinceFlush = 0;
  const int one=1;
  setsockopt(sock,IPPROTO_TCP,TCP_NODELAY,&one,sizeof(one));

  return trans;
}

void protocolUseTcp2P(ProtocolDesc* pd, int sock, bool isClient)
{
  pd->trans = &ssl2PNew(sock, isClient, false)->cb;
  ssl2PTransport* t = CAST(pd->trans);
  t->keepAlive = false;
}

void protocolUseTcp2PProfiled(ProtocolDesc* pd, int sock, bool isClient)
{
  pd->trans = &ssl2PNew(sock, isClient, true)->cb;
  ssl2PTransport* t = CAST(pd->trans);
  t->keepAlive = false;
}

void protocolUseTcp2PKeepAlive(ProtocolDesc* pd,int sock,bool isClient)
{
  pd->trans = &tcp2PNew(sock,isClient, false)->cb;
  tcp2PTransport* t = CAST(pd->trans);
  t->keepAlive = true;
}

static int getsockaddr(const char* name,const char* port, struct sockaddr* res)
{
  struct addrinfo *list, *iter;
  if(getaddrinfo(name,port,NULL,&list) < 0) return -1;
  for(iter=list;iter!=NULL && iter->ai_family!=AF_INET;iter=iter->ai_next);
  if(!iter) { freeaddrinfo(list); return -1; }
  memcpy(res,iter->ai_addr,iter->ai_addrlen);
  freeaddrinfo(list);
  return 0;
}
// used as sock=tcpConnect(...); ...; close(sock);
static int tcpConnect(struct sockaddr_in* sa)
{
  int outsock;
  if((outsock=socket(AF_INET,SOCK_STREAM,0))<0) return -1;
  if(connect(outsock,(struct sockaddr*)sa,sizeof(*sa))<0) return -1;
  return outsock;
}

int protocolConnectTcp2P(ProtocolDesc* pd,const char* server,const char* port)
{
  struct sockaddr_in sa;
  if(getsockaddr(server,port,(struct sockaddr*)&sa)<0) return -1; // dns error
  int sock=tcpConnect(&sa); if(sock<0) return -1;
  protocolUseTcp2P(pd,sock,true);
  return 0;
}

int protocolConnectTcp2PProfiled(ProtocolDesc* pd,const char* server,const char* port)
{
  struct sockaddr_in sa;
  if(getsockaddr(server,port,(struct sockaddr*)&sa)<0) return -1; // dns error
  int sock=tcpConnect(&sa); if(sock<0) return -1;
  protocolUseTcp2PProfiled(pd,sock,true);
  return 0;
}

// used as sock=tcpListenAny(...); sock2=accept(sock); ...; close(both);
static int tcpListenAny(const char* portn)
{
  in_port_t port;
  int outsock;
  if(sscanf(portn,"%hu",&port)<1) return -1;
  if((outsock=socket(AF_INET,SOCK_STREAM,0))<0) return -1;
  int reuse = 1;
  if (setsockopt(outsock, SOL_SOCKET, SO_REUSEADDR, (const char*)&reuse, sizeof(reuse)) < 0)
  { fprintf(stderr,"setsockopt(SO_REUSEADDR) failed\n"); return -1; }

  struct sockaddr_in sa = { .sin_family=AF_INET, .sin_port=htons(port)
                          , .sin_addr={INADDR_ANY} };
  if(bind(outsock,(struct sockaddr*)&sa,sizeof(sa))<0) return -1;
  if(listen(outsock,SOMAXCONN)<0) return -1;
  return outsock;
}

int protocolAcceptTcp2P(ProtocolDesc* pd,const char* port)
{
  int listenSock, sock;
  listenSock = tcpListenAny(port);
  if((sock=accept(listenSock,0,0))<0) return -1;
  protocolUseTcp2P(pd,sock,false);
  close(listenSock);
  return 0;
}

int protocolAcceptTcp2PProfiled(ProtocolDesc* pd,const char* port)
{
  int listenSock, sock;
  listenSock = tcpListenAny(port);
  if((sock=accept(listenSock,0,0))<0) return -1;
  protocolUseTcp2PProfiled(pd,sock,false);
  close(listenSock);
  return 0;
}

/*
   If two parties connected over a given socket execute this function
   (one with isClient true and the other with false), they both end up with
   a new socket that they can use in parallel with the old one. This is useful
   just before two parties are planning to spawn a new thread each, such that
   the two threads can have an independent channel with the corresponding thread
   on the remote side. Meant to work on TCP sockets only.

   Needs transport object to send the new port number along.
   Used only with tcp2PSplit, so won't need a party number.
   */
static int ssl_sockSplit(int sock,ProtocolTransport* t,bool isClient)
{
  struct sockaddr_in sa; socklen_t sz=sizeof(sa);
  if(isClient)
  {
    if(getpeername(sock,(struct sockaddr*)&sa,&sz)<0) return -1;
    //int rres=read(sock,&sa.sin_port,sizeof(sa.sin_port));
    int rres = transRecv(t,0,&sa.sin_port,sizeof(sa.sin_port));
    if(rres<0) { fprintf(stderr,"Socket read error\n"); return -1; }
    if(rres<sizeof(sa.sin_port))
      { fprintf(stderr,"BUG: fix with repeated reads\n"); return -1; }
    return tcpConnect(&sa);
  }
  else
  { // any change here should also change PROFILE_NETWORK in tcp2PSplit()
    int listenSock=tcpListenAny("0");
    if(getsockname(listenSock,(struct sockaddr*)&sa,&sz)<0) return -1;
    //if(write(sock,&sa.sin_port,sizeof(sa.sin_port))<0) return -1;
    if(transSend(t,0,&sa.sin_port,sizeof(sa.sin_port))<0) return -1;
    transFlush(t);
    int newsock = accept(listenSock,0,0);
    close(listenSock);
    return newsock;
  }
}

static ProtocolTransport* tcp2PSplit(ProtocolTransport* tsrc)
{
  tcp2PTransport* t = CAST(tsrc);
  transFlush(tsrc);
  // I should really rewrite sockSplit to use FILE* sockStream
  int newsock = sockSplit(t->sock,tsrc,t->isClient);
  if(newsock<0) { fprintf(stderr,"sockSplit() failed\n"); return NULL; }
  tcp2PTransport* tnew = tcp2PNew(newsock,t->isClient,t->isProfiled);
  tnew->parent=t;
  return CAST(tnew);
}

typedef struct
{ ProtocolTransport cb;
  ProtocolDesc pd;
} SizeCheckTransportAdapter; // spliced object

static int sizeCheckSend(ProtocolTransport* pt,int dest,const void* s,size_t n)
{ int sent = osend(&((SizeCheckTransportAdapter*)pt)->pd,dest,s,n);
  if(sent==n) return n;
  else
  { fprintf(stderr,"Was going to send %zu bytes to %d, sent %d\n",
                   n,dest,sent);
    if(sent<0) fprintf(stderr,"That means %s\n",strerror(sent));
    exit(-1);
  }
}

static int sizeCheckRecv(ProtocolTransport* pt,int src,void* s,size_t n)
{ int recv = orecv(&((SizeCheckTransportAdapter*)pt)->pd,src,s,n);
  if(recv==n) return n;
  else
  { fprintf(stderr,"Was going to recv %zu bytes from %d, received %d\n",
                    n,src,recv);
    if(recv<0) fprintf(stderr,"That means %s\n",strerror(recv));
    exit(-1);
  }
}
static void sizeCheckCleanup(ProtocolTransport* pt)
{ ProtocolTransport *inner = ((SizeCheckTransportAdapter*)pt)->pd.trans;
  inner->cleanup(inner);
  free(pt);
}

void protocolAddSizeCheck(ProtocolDesc* pd)
{
  SizeCheckTransportAdapter* t = malloc(sizeof(SizeCheckTransportAdapter));
  t->pd = *pd; // Dummy protocol object, sliced just for the Transport object
  pd->trans = &t->cb;
  t->cb.send=sizeCheckSend;
  t->cb.recv=sizeCheckRecv;
  t->cb.cleanup=sizeCheckCleanup;
}
