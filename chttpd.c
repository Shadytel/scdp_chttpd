#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <microhttpd.h>
#include <sqlite3.h>

#define PORT 8082

#define NOT_FOUND 404
#define INTERNAL_SERVER_ERROR 500
#define BAD_REQUEST 400

// Some globals

/* TO DO: Instead of strcpy'ing error pages, just keep them in resident memory and use them as needed.
 * const char * 404page = "<html><title>404 Not Found</title><body>404 Not Found</body></html>";
 * const char * 500page = "<html><title>500 Internal Server Error</title><body>500 Internal Server Error</body></html>";
 * const char * 400page = "<html><title>400 Bad Request</title><body>400 Bad Request</body></html>";
 */

void * isrpage[6];
sqlite3 * DB; // For the moment, the database pointer will be global; we'll likely need it in multiple function calls.

struct Request {
    struct Session *session;
    struct MHD_PostProcessor *pp;
    const char *post_url;

};

char * lowercase ( char * instring, size_t length) {
    // This converts alphabetic ASCII characters to lower case
    size_t counter = 0;
    while (counter < length) {
        if ( (instring[counter] > 0x40) && (instring[counter] < 0x5B)) {
            instring[counter] += 0x20;
        }
        counter++;
    }
    return instring;
}

struct Session {
    char ipaddr[18]; // IPv4 addresses only. Sowwy :(
    char nataddr[18];
    char gateway[18];
    unsigned short nxx;
    unsigned char fxs;
    unsigned char fxo;
    unsigned char cemslot;
    unsigned char fxoslot;
    unsigned char fxosubslot;
    unsigned char fxoport;
    unsigned char fxsslot;
    unsigned char fxssubslot;
    unsigned char fxsport;
    char fxodest[15];
    unsigned char tslot;
    unsigned char tsubslot;
    unsigned char tport;
    unsigned char tlen;
    unsigned char cemlen;
    char isdnflavor[8]; // This was made signed to stop the compiler from complaining
    char isdnside[9];
    unsigned char pritb;
    char numplan[10];
    char cntyp[16];
    char cablelength[9];
    char cemlength[9];
    char features; // Amalgamation of annc, fxscid, fxocid, pri, ttiming and isdnside. We'll need to actually initialize this one.
};

int gen_error_page(struct MHD_Connection *connection, unsigned short pagetype) {
    struct MHD_Response *response;
    int ret;
    char page[92] = {0};

    switch(pagetype) {
        case NOT_FOUND:
            strcpy(page, "<html><title>404 Not Found</title><body>404 Not Found</body></html>"); // 68 characters
            break;
        case INTERNAL_SERVER_ERROR:
            strcpy(page, "<html><title>500 Internal Server Error</title><body>500 Internal Server Error</body></html>"); // 92 characters
            break;
        // Default behavior is bad request
        default:
            strcpy(page, "<html><title>400 Bad Request</title><body>400 Bad Request</body></html>"); // 72 characters
    }

    response = MHD_create_response_from_buffer (strlen (page), (void*) page, MHD_RESPMEM_MUST_COPY);
    ret = MHD_queue_response (connection, pagetype, response);
    MHD_destroy_response (response);
    return ret;
}

static struct Session * get_session(struct MHD_Connection *connection ) {

    struct Session *ret;
    // The cookie functionality has been removed since we don't especially need it here.

    // Create fresh session
    ret = calloc (1, sizeof(struct Session));
    if (ret == NULL)
    {
         fprintf(stderr, "ERROR: calloc: %s\n", strerror(errno));
         return NULL;
    }

    // memsetting the buffer to zero is very important; if integers aren't passed in the POST request, they could get random values from uninitialized memory.
    memset( ret, 0x00, sizeof(struct Session));

    // TO DO: Re-insert actual cookie things here as needed

    return ret;
}

static int isr_post_parse( void *cls,
                       enum MHD_ValueKind kind,
                       const char *key,
                       const char *filename,
                       const char *content_type,
                       const char *transfer_enconding,
                       const char *data, uint64_t off, size_t size)
{
    struct Request *request = cls;
    struct Session *session = request->session;
    // We can assume the httpd won't pass us a null pointer, but someone could still send us a key with a value of zero bytes.
    if (data[0] == 0x00) {
        printf("WARNING: Parameter %s with length of zero passed! Ignoring...\n", key);
        return MHD_YES;
    }

    // TO DO: strncmp with maximum of maximum key size so the string compare function doesn't go bananas
    switch(key[0]) {
        case 'i':
            if (strcmp("ipaddr", key) == 0 ) {
                strncpy(session->ipaddr, data, 17);
            }
            else if(strcmp("isdnflavor", key) == 0) {
                strncpy(session->isdnflavor, data, 7);
            }
            else if(strcmp("isdnside", key) == 0) {
                strncpy(session->isdnside, data, 8);
            }
            break;
        case 'n':
            if (strcmp("nataddr", key) == 0 ) {
                strncpy(session->nataddr, data, 17);
            }
            else if (strcmp("nxx", key) == 0 ) {
                session->nxx = (unsigned short) strtoul(data, NULL, 10);
            }
            else if(strcmp("numplan", key) == 0) {
                strncpy(session->numplan, data, 9);
            }
            break;
        case 'a':
            if (strcmp("annc", key) == 0) {
                if (data[0] == 'y') {
                    session->features |= 1;
                }
            }
            break;
        case 'f':
            if (strcmp("fxscid", key) == 0) {
                if (data[0] == 'y') session->features |= 2;
            }
            else if (strcmp("fxs", key) == 0) {
                //session->fxs = (data[0] - 0x30);
                session->fxs = atoi(data);
                // This is to prevent someone from eating up all the buffer memory with an artificially large number of FXS ports. Or, y'know, causing an overflow.
                if (session->fxs > 24) session->fxs = 24;
            }
            else if (strcmp("fxodest", key) == 0) {
                strncpy(session->fxodest, data, 14);
            }
            else if (strcmp("fxocid", key) == 0) {
                if (data[0] == 'y') session->features |= 4;
            }
            else if (strcmp("fxo", key) == 0) {
                session->fxo = (data[0] - 0x30);
                if (session->fxo > 24) session->fxo = 24;
                // This one too. H4X0R N0 H4XX0R1NG!!!
            }
            else if (strcmp("fxsport", key) == 0) {
                //session->fxsport = (data[0] - 0x30);
                session->fxsport = atoi(data);
            }
            else if (strcmp("fxoport", key) == 0) {
                //session->fxoport = (data[0] - 0x30);
                session->fxoport = atoi(data);
            }
            else if (strcmp("fxsslot", key) == 0) {
                session->fxsslot = (data[0] - 0x30);
            }
            else if (strcmp("fxoslot", key) == 0) {
                session->fxoslot = (data[0] - 0x30);
            }
            else if (strcmp("fxssubslot", key) == 0) {
                session->fxssubslot = (data[0] - 0x30);
            }
            else if (strcmp("fxosubslot", key) == 0) {
                session->fxosubslot = (data[0] - 0x30);
            }
            break;
        case 'p':
            if(strcmp("pri", key) == 0) {
                if (data[0] == 'y') session->features |= 8;
            }
            else if(strcmp("pritb", key) == 0) {
                session->pritb = data[0] - 0x30;
            }
            break;
        case 't':
            if(strcmp("t1slot", key) == 0) {
                session->tslot = (data[0] - 0x30);
            }
            if(strcmp("t1subslot", key) == 0) {
                session->tsubslot = data[0]; // tsubslot is, um, special; we need to know if this is a null value or not.
            }
            else if(strcmp("t1port", key) == 0) {
                session->tport = (data[0] - 0x30);
            }
            else if(strcmp("t1timing", key) == 0) {
                if (data[0] == 'y') session->features |= 16;
            }

            // T1 framing/linecode are only used for AS5300 FXS

            else if(strcmp("t1framing", key) == 0) {
                if (data[0] == 'e') session->features |=2; // This is for the AS5300 only. Since there's no FXS caller ID feature, we can just reuse that
            }

            else if(strcmp("t1linecode", key) == 0) {
                if (data[0] == 'b') session->features |=4; // No FXO either
            }

            else if(strcmp("t1len", key) == 0) {
                //session->tlen = (data[0] - 0x30); // Single digit value
                session->tlen = atoi(data);
                switch(session->tlen) {
                    // Yeah, yeah, s00p3r d00p3r unsafe, I know. Since this is a constant and not a buffer passed from the user though, there's nothing inherently unsafe about it
                    // Second/newer generation VIC long values
                    case 16:
                    strcpy(session->cablelength, "0db");
                    break;
                    case 15:
                    strcpy(session->cablelength, "-7.5db");
                    break;
                    case 14:
                    strcpy(session->cablelength, "-15db");
                    break;
                    case 13:
                    strcpy(session->cablelength, "-22.5db");
                    break;
                    // First generation VIC long values
                    case 12:
                    strcpy(session->cablelength, "gain36");
                    break;
                    case 11:
                    strcpy(session->cablelength, "gain26");
                    break;
                    // Second/newer generation VIC values
                    case 10:
                    strcpy(session->cablelength, "600ft");
                    break;
                    case 9:
                    strcpy(session->cablelength, "550ft");
                    break;
                    case 8:
                    strcpy(session->cablelength, "440ft");
                    break;
                    case 7:
                    strcpy(session->cablelength, "330ft");
                    break;
                    case 6:
                    strcpy(session->cablelength, "220ft");
                    break;
                    case 5:
                    strcpy(session->cablelength, "110ft");
                    break;
                    // First generation VIC values?
                    case 4:
                    strcpy(session->cablelength, "655ft");
                    break;
                    case 3:
                    strcpy(session->cablelength, "533ft");
                    break;
                    case 2:
                    strcpy(session->cablelength, "399ft");
                    break;
                    case 1:
                    strcpy(session->cablelength, "266ft");
                    break;
                    default:
                    strcpy(session->cablelength, "133ft");
                    break;
                }
            }
            break;
        case 'c':
            if(strcmp("cntyp", key) == 0) {
                strncpy(session->cntyp, data, 15);
            }
            else if(strcmp("cempri", key) == 0) {
                if (data[0] == 'y') session->features |= 32;
            }
            else if (strcmp("cemslot", key) == 0 ) {
                session->cemslot = (data[0] - 0x30);
            }
            else if(strcmp("cemsource", key) == 0) {
                if (data[0] == 'y') session->features |= 64;
            }
            else if(strcmp("cemlen", key) == 0) {
                session->cemlen = (data[0] - 0x30); // Single digit value
                switch(session->cemlen) {
                    // Yeah, yeah, s00p3r d00p3r unsafe, I know. Since this is a constant and not a buffer passed from the user though, there's nothing inherently unsafe about it
                    case 9:
                    strcpy(session->cemlength, "0db");
                    break;
                    case 8:
                    strcpy(session->cemlength, "-7.5db");
                    break;
                    case 7:
                    strcpy(session->cemlength, "-15db");
                    break;
                    case 6:
                    strcpy(session->cemlength, "-22.5db");
                    break;
                    case 5:
                    strcpy(session->cemlength, "600ft");
                    break;
                    case 4:
                    strcpy(session->cemlength, "550ft");
                    break;
                    case 3:
                    strcpy(session->cemlength, "440ft");
                    break;
                    case 2:
                    strcpy(session->cemlength, "330ft");
                    break;
                    case 1:
                    strcpy(session->cemlength, "220ft");
                    break;
                    default:
                    strcpy(session->cemlength, "110ft");
                    break;
                }
            }
            break;
        case 'g':
            if (strcmp("gateway", key) == 0 ) {
                strncpy(session->gateway, data, 17);
            }
            break;
        default:
            if (strcmp("DONE", key) == 0) {
                return MHD_YES;
            }
            fprintf(stderr, "WARNING: Unknown option passed to POST parseamawhoozit! - %s\n", key);

    }

    return MHD_YES;
}

int answer_to_connection (void *cls, struct MHD_Connection *connection,
                          const char *url,
                          const char *method, const char *version,
                          const char *upload_data,
                          size_t *upload_data_size, void **con_cls)
{
    int ret;

    if (strcmp(method, MHD_HTTP_METHOD_POST) == 0) {
        if (strcmp(url, "/2800config") == 0) {
            struct Request *request = *con_cls;
            if (request == NULL) {
                request = calloc(1, sizeof(struct Request));
                if (request == NULL) {
                    fprintf( stderr, "ERROR: calloc/%s\n", strerror(errno));
                    return MHD_NO;
                }
                request->pp = MHD_create_post_processor(connection, 1024, &isr_post_parse, request);
                if (request->pp == NULL) {
                    fprintf( stderr, "ERROR: Failed to setup post process for %s!\n", url);
                    return MHD_NO;
                }
                *con_cls = request;
                return MHD_YES;
            }
            if (request->session == NULL) {
                request->session = get_session(connection);
                if (request->session == NULL) {
                    fprintf(stderr, "ERROR: Failed to start session for %s\n", url);
                    return MHD_NO;
                }

            }
            if (*upload_data_size) {
                MHD_post_process(request->pp, upload_data, *upload_data_size);
                *upload_data_size = 0;
                return MHD_YES;
            }
            else {
                struct MHD_Response *response;
                sqlite3_stmt *statement = NULL;
                // The SQL query is executed on another thread, and we need as close as we can get to a blocking function call for this.
                // Thankfully, sqlite3_prepare_v2() works rather well. This particular call is just to see how many entries are in the DB.
                // If it fails, we'll send back a 500 error.
                sqlite3_prepare_v2(DB, "SELECT COUNT(*) FROM PEER;", -1, &statement, 0);
                if (statement == NULL) {
                    fprintf(stderr, "ERROR: sqlite3_prepare_v2 returned null pointer for query!\n");
                    return gen_error_page(connection, INTERNAL_SERVER_ERROR);
                }
                int result = sqlite3_step(statement);
                int count = 0;

                if (result == SQLITE_ROW) {
                    count = sqlite3_column_int(statement, 0);
                }
                else {
                    // WHAT IN THE NAME OF HATBOWLS?! BAIL OOOOUT D:
                    fprintf(stderr, "ERROR: SQL Result code was %d\n", result);
                    return gen_error_page(connection, INTERNAL_SERVER_ERROR);
                }

                if (count == 0) {
                    fprintf(stderr, "ERROR: SQL query returned zero results!\n");
                    return gen_error_page(connection, INTERNAL_SERVER_ERROR);
                }

                char postpage[4076 + (count * 386) + (request->session->fxs * 354) + (request->session->fxo * 333)]; // ...seriously? We can create a variable-sized array like this? Maybe this should be a malloc or something, so we can handle a memory allocation failure gracefully.
                memset(postpage, 0x00, sizeof(postpage));
                char loopback[171]; // snprintf size + 1 to make sure the compiler doesn't complain. TO DO: Refer to reference to make sure this is how2sprintf, since it likes to complain anyway.
                unsigned char looplen = strlen(request->session->nataddr);
                if (looplen != 0) {
                    snprintf(loopback,sizeof(loopback), "\n! Be sure that interface Loopback0 is unallocated before pasting this\n"\
                    "interface Loopback0\n"\
                    " ip address %s 255.255.255.255\n"\
                    " no shut\n"\
                    " exit\n", request->session->nataddr);
                    //strncat(postpage, loopback, 161);
                }
                snprintf(postpage, 992, "! Please paste this into your router:\n"\
                "interface GigabitEthernet0/0 ! We'll be assuming use of the primary ethernet interface here\n"\
                " ip address %s 255.255.255.0 ! Subnet mask of 255.255.255.0 is also assumed at this point.\n"\
                " no shutdown\n"\
                " exit\n"\
                "%s"\
                "ip routing\n"\
                "ip route 0.0.0.0 0.0.0.0 %s\n"\
                "! WARNING: This command *will* fail if no PVDMs are installed\n"\
                "voice-card 0\n"\
                " dspfarm\n"\
                " exit\n"\
                "voice service voip\n"\
                " ip address trusted list\n"\
                "  ipv4 64.71.190.130\n"\
                "  exit\n"\
                " allow-connections h323 to h323\n"\
                " allow-connections h323 to sip\n"\
                " allow-connections sip to h323\n"\
                " allow-connections sip to sip\n"\
                " redirect ip2ip\n"\
                " signaling forward unconditional\n"\
                " fax protocol none\n"\
                " sip\n"\
                "  bind control source-interface GigabitEthernet0/0\n"\
                "  bind media source-interface %s\n"\
                "  bearer-capability clear-channel audio\n"\
                "  exit\n"\
                " exit\n", request->session->ipaddr, looplen ? loopback : "", request->session->gateway, looplen ? "Loopback0" : "GigabitEthernet0/0");

                if (request->session->features & 8) {
                    char priconfig[1604];
                    char routerslot[7] = {0};
                    if (request->session->tsubslot == 0x00) {
                        snprintf(routerslot, 6, "%d/%d", request->session->tslot, request->session->tport);
                    }

                    else {
                        snprintf(routerslot, 6, "%d/%c/%d", request->session->tslot, request->session->tsubslot, request->session->tport);
                    }
                    snprintf(priconfig, 1603, "\nivr prompt streamed flash\n"\
                    "card type t1 %d %c\n"\
                    "network-clock-participate %s %d\n"\
                    "isdn switch-type primary-%s\n"\
                    " controller T1 %s\n"\
                    " cablelength %s %s\n pri-group timeslots 1-24\n"\
                    " ! DS0 group options may be added at a later point\n"\
                    " clock source %s\n"\
                    " ! For PRI, we will be hard set to B8ZS/ESF linecoding/framing on the T1\n"\
                    " framing esf\n"\
                    " linecode b8zs\n"\
                    " exit\n\ninterface Serial%s:23\n"\
                    " no ip address\n"\
                    " encapsulation hdlc\n"\
                    " isdn switch-type primary-%s\n"\
                    " isdn protocol-emulate %s\n"\
                    " isdn incoming-voice voice\n isdn map address .* plan %s type %s\n"\
                    " isdn send-alerting\n"\
                    " ! cdp is effectively logging; beyond the scope of the project.\n"\
                    " no cdp enable\n"\
                    " exit\n\n"\
                    "! Please make sure this dial-peer is unallocated.\n"\
                    "dial-peer voice %d%d pots\n"\
                    " destination-pattern %d%d...\n"\
                    " supplementary-service pass-through\n"\
                    " port %s:23\n"\
                    " no sip-register\n"\
                    " description SCDP PRI\n"\
                    " exit\n", request->session->tslot, (request->session->tsubslot == 0x00) ? 0x20 : request->session->tsubslot, (request->session->tslot != 0) ? "slot" : "wic", (request->session->tslot != 0) ? request->session->tslot : (request->session->tsubslot % 0x30), request->session->isdnflavor, routerslot, ( request->session->tlen > 10 ) ? "long" : "short", request->session->cablelength, (request->session->features & 16) ? "internal" : "line", routerslot, request->session->isdnflavor, request->session->isdnside, request->session->numplan, request->session->cntyp, request->session->nxx, request->session->pritb, request->session->nxx, request->session->pritb, routerslot);
                strncat(postpage, priconfig, 1603);
                }
                if (request->session->features & 1) {
                    // Since there's no strings to input into the config, we're just using sprintf here. If there ever are, well, yyyyeah.
                    char announcement[191];
                    sprintf( announcement, "\napplication\n"\
                    " service playback flash:/playback.tcl\n"\
                    "  param playback-file flash:verification.au\n"\
                    "  exit\nexit\n"\
                    "dial-peer voice 9901 pots\n"\
                    " service playback\n"\
                    " destination-pattern %d9901\n"\
                    " exit\n", request->session->nxx);
                    strncat(postpage, announcement, 190);
                }
                char fxobuffer[333];
                if (request->session->fxo > 0) {
                    snprintf(fxobuffer, 332, "\nvoice translation-profile fxo-outbound\n"\
                    " translate called 1\n"\
                    " exit\n\n"\
                    "voice translation-rule 1\n"\
                    " rule 1 /^8./ //\n"\
                    " exit\n");
                    strncat(postpage, fxobuffer, 332);
                }
                for (unsigned char iterator = 0; iterator < request->session->fxo; iterator++) {
                    snprintf(fxobuffer, 332, "\nvoice-port %d/%d/%d\n"\
                    " connection plar opx %s\n"\
                    " %s\nexit\n\n"\
                    "dial-peer voice %d pots\n"\
                    " description Automatically provisioned FXO port %d of %d\n"\
                    " port %d/%d/%d\n"\
                    " no sip-register\n"\
                    "translation-profile outgoing fxo-outbound\n"\
                    " destination-pattern 8%d.T\n"\
                    " exit\n", request->session->fxoslot, request->session->fxosubslot, (request->session->fxoport + iterator), request->session->fxodest, (request->session->features & 4) ? "caller-id enable type 1\n" : "",(100 + iterator), iterator+1, request->session->fxo, request->session->fxoslot, request->session->fxosubslot, (request->session->fxoport + iterator), iterator);
                    strncat(postpage, fxobuffer, 332);
                }
                char fxsbuffer[355];
                for (unsigned char iterator = 0; iterator < request->session->fxs; iterator++) {
                    snprintf(fxsbuffer, 354, "\nvoice-port %d/%d/%d\n"\
                    " no comfort-noise\n"\
                    " %s"\
                    "station-id number %d909%d\n exit\n\n"\
                    "dial-peer voice %d pots\n"\
                    " description Automatically provisioned FXS port %d of %d\n"\
                    " port %d/%d/%d\n"\
                    " no sip-register\n"\
                    " destination-pattern %d909%d\n"\
                    " exit\n", request->session->fxsslot, request->session->fxssubslot, (request->session->fxsport + iterator), ( request->session->features & 2) ? "caller-id enable type 1\n ": "", request->session->nxx, iterator, (200 + iterator), iterator+1, request->session->fxs, request->session->fxsslot, request->session->fxssubslot, (request->session->fxsport + iterator), request->session->nxx, iterator);

                    strncat(postpage, fxsbuffer, 354);
                }
                // SQL output goes here
                char sqlpeer[371]; // TO DO: An actual dial peer config line is going to be longer. Establish the length and make it longer.
                unsigned char cemcounter = 0;
                sqlite3_prepare_v2(DB, "SELECT * FROM PEER;", -1, &statement, 0);

                for (int counter = 0; counter < count; counter++) {
                    result = sqlite3_step(statement);
                    if (result == SQLITE_ROW) {
                        if (sqlite3_column_int(statement, 2)) {
                            // H.323 or SIP peer. TO DO: If protocol == 2, add SIP protocol specifier.
                            snprintf(sqlpeer, 370, "dial-peer voice 4%02d voip\n"\
                            "description %s\n"\
                            "session target ipv4:%s\n"\
                            "destination-pattern %d....\n"\
                            "huntstop\n"\
                            "codec g711ulaw\n"\
                            "exit\n\n",
                            sqlite3_column_int(statement, 0),
                            sqlite3_column_text(statement, 1),
                            sqlite3_column_text(statement, 3),
                            sqlite3_column_int(statement, 4));
                            strncat(postpage, sqlpeer, 370);
                        }
                        else {
                            // CEM-T1 dial-peer.
                            if (request->session->features & 32) {
                                if (cemcounter < 4) {
                                    // Only print if CEM T1 peer is active
                                    snprintf(sqlpeer, 370, "card type t1 %d\n"\
                                    "network-clock-participate slot %d\n"\
                                    "controller t1 %d/%d\n"\
                                    " framing UNFRAMED\n"\
                                    " cem-group %d unframed\n"\
                                    " clock source %s %c\n"\
                                    " cablelength %s %s\n"\
                                    " exit\n\n"\
                                    "cem %d/0/%d\n"\
                                    "! %s peer: NXX %d\n"
                                    "payload-compression\n"\
                                    "payload-size 256\n"\
                                    "xconnect %s 0 encapsulation udp\n"\
                                    "local ip address %s\n"\
                                    // TO DO: Can all CEM spans share the same port?
                                    "local udp port 15901\n"\
                                    "remote udp port 15901\n"\
                                    "exit\nexit\n\n", request->session->cemslot, request->session->cemslot, request->session->cemslot, cemcounter, cemcounter, request->session->features & 64 ? "adaptive" : "line", request->session->features & 64 ? (cemcounter + 0x30) : 0x20, ( request->session->cemlen > 10 ) ? "long" : "short", request->session->cemlength, request->session->cemslot, cemcounter, sqlite3_column_text(statement, 1), sqlite3_column_int(statement, 4), sqlite3_column_text(statement, 3), (looplen != 0) ? request->session->nataddr : request->session->ipaddr);
                                    strncat(postpage, sqlpeer, 370);
                                    cemcounter++;
                                }
                            }
                        }
                    }

                    else {
                        fprintf(stderr, "ERROR Result code was %d\n", result);
                    }

                }
                response = MHD_create_response_from_buffer (strlen (postpage), (void*) postpage, MHD_RESPMEM_PERSISTENT); // Is this still persistent?
                MHD_add_response_header( response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/plain"); // The config file we return will be a text file, because why wouldn't it?
                ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
                MHD_destroy_response (response);
                return ret;
            }
            printf("DEBUG: We should never get to this point.\n");
            return MHD_NO;
        }
        // TO DO: Clean this up and/or functionalize it. A lot of this code is reused.
        else if (strcmp(url, "/2400config") == 0) {
            struct Request *request = *con_cls;
            if (request == NULL) {
                request = calloc(1, sizeof(struct Request));
                if (request == NULL) {
                    fprintf( stderr, "ERROR: calloc/%s\n", strerror(errno));
                    return MHD_NO;
                }
                request->pp = MHD_create_post_processor(connection, 1024, &isr_post_parse, request);
                if (request->pp == NULL) {
                    fprintf( stderr, "ERROR: Failed to setup post process for %s!\n", url);
                    return MHD_NO;
                }
                *con_cls = request;
                return MHD_YES;
            }
            if (request->session == NULL) {
                request->session = get_session(connection);
                if (request->session == NULL) {
                    fprintf(stderr, "ERROR: Failed to start session for %s\n", url);
                    return MHD_NO;
                }

            }
            if (*upload_data_size) {
                MHD_post_process(request->pp, upload_data, *upload_data_size);
                *upload_data_size = 0;
                return MHD_YES;
            }
            else {
                struct MHD_Response *response;
                sqlite3_stmt *statement = NULL;
                // The SQL query is executed on another thread, and we need as close as we can get to a blocking function call for this.
                // Thankfully, sqlite3_prepare_v2() works rather well. This particular call is just to see how many entries are in the DB.
                // If it fails, we'll send back a 500 error.
                sqlite3_prepare_v2(DB, "SELECT COUNT(*) FROM PEER;", -1, &statement, 0);
                if (statement == NULL) {
                    fprintf(stderr, "ERROR: sqlite3_prepare_v2 returned null pointer for query!\n");
                    return gen_error_page(connection, INTERNAL_SERVER_ERROR);
                }
                int result = sqlite3_step(statement);
                int count = 0;

                if (result == SQLITE_ROW) {
                    count = sqlite3_column_int(statement, 0);
                }
                else {
                    // WHAT IN THE NAME OF HATBOWLS?! BAIL OOOOUT D:
                    fprintf(stderr, "ERROR: SQL Result code was %d\n", result);
                    return gen_error_page(connection, INTERNAL_SERVER_ERROR);
                }

                if (count == 0) {
                    fprintf(stderr, "ERROR: SQL query returned zero results!\n");
                    return gen_error_page(connection, INTERNAL_SERVER_ERROR);
                }

                char postpage[4701 + (count * 371)]; // ...seriously? We can create a variable-sized array like this? Maybe this should be a malloc or something, so we can handle a memory allocation failure gracefully.
                memset(postpage, 0x00, sizeof(postpage));
                char loopback[171]; // snprintf size + 1 to make sure the compiler doesn't complain. TO DO: Refer to reference to make sure this is how2sprintf, since it likes to complain anyway.
                unsigned char looplen = strlen(request->session->nataddr);
                if (looplen != 0) {
                    snprintf(loopback,sizeof(loopback), "\n! Be sure that interface Loopback0 is unallocated before pasting this\n"\
                    "interface Loopback0\n"\
                    " ip address %s 255.255.255.255\n"\
                    " no shut\n"\
                    " exit\n", request->session->nataddr);
                    //strncat(postpage, loopback, 161);
                }
                // TO DO: Re-check length for this
                snprintf(postpage, 934, "! Please paste this into your router:\n"\
                "interface FastEthernet0/0 ! We'll be assuming use of the primary ethernet interface here\n"\
                " ip address %s 255.255.255.0 ! Subnet mask of 255.255.255.0 is also assumed at this point.\n"\
                " no shutdown\n"\
                " exit\n"\
                "%s"\
                "ip routing\n"\
                "ip route 0.0.0.0 0.0.0.0 %s\n"\
                "voice-card 0\n"\
                " dsp services dspfarm\n"\
                " exit\n"\
                "voice service voip\n"\
                " ip address trusted list\n"\
                "  ipv4 64.71.190.130\n"\
                "  exit\n"\
                " allow-connections h323 to h323\n"\
                " allow-connections h323 to sip\n"\
                " allow-connections sip to h323\n"\
                " allow-connections sip to sip\n"\
                " redirect ip2ip\n"\
                " signaling forward unconditional\n"\
                " fax protocol none\n"\
                " sip\n"\
                "  bind control source-interface FastEthernet0/0\n"\
                "  bind media source-interface %s\n"\
                "  bearer-capability clear-channel audio\n"\
                "  exit\n"\
                " exit\n", request->session->ipaddr, looplen ? loopback : "", request->session->gateway, looplen ? "Loopback0" : "FastEthernet0/0");

                if (request->session->features & 8) {
                    char priconfig[1604];
                    snprintf(priconfig, 1603, "\nivr prompt streamed flash\n"\
                    "card type t1 %d\n"\
                    "network-clock-participate %s %d/%d\n"\
                    "isdn switch-type primary-%s\n"\
                    " controller T1 %d/%d\n"\
                    " ! WARNING: on 8FXS or 16FXS models, pri-group timeslots 1-24 will NOT work! Reduce the number of timeslots appropriately.\n"\
                    " cablelength %s %s\n pri-group timeslots 1-24\n"\
                    " ! DS0 group options may be added at a later point\n"\
                    " clock source %s\n"\
                    " ! For PRI, we will be hard set to B8ZS/ESF linecoding/framing on the T1\n"\
                    " framing esf\n"\
                    " linecode b8zs\n"\
                    " exit\n\ninterface Serial%d/%d:23\n"\
                    " no ip address\n"\
                    " encapsulation hdlc\n"\
                    " isdn switch-type primary-%s\n"\
                    " isdn protocol-emulate %s\n"\
                    " isdn incoming-voice voice\n isdn map address .* plan %s type %s\n"\
                    " isdn send-alerting\n"\
                    " ! cdp is effectively logging; beyond the scope of the project.\n"\
                    " no cdp enable\n"\
                    " exit\n\n"\
                    "! Please make sure this dial-peer is unallocated.\n"\
                    "dial-peer voice %d%d pots\n"\
                    " destination-pattern %d%d...\n"\
                    " supplementary-service pass-through\n"\
                    " port %d/%d:23\n"\
                    " no sip-register\n"\
                    " description SCDP PRI\n"\
                    " exit\n", request->session->tslot, (request->session->tslot == 1) ? "t1" : "wic", request->session->tslot, request->session->tport, request->session->isdnflavor, request->session->tslot, request->session->tport, ( request->session->tlen > 10 ) ? "long" : "short", request->session->cablelength, (request->session->features & 16) ? "internal" : "line", request->session->tslot, request->session->tport, request->session->isdnflavor, request->session->isdnside, request->session->numplan, request->session->cntyp, request->session->nxx, request->session->pritb, request->session->nxx, request->session->pritb, request->session->tslot, request->session->tport);
                strncat(postpage, priconfig, 1603);
                }
                if (request->session->features & 1) {
                    // Since there's no strings to input into the config, we're just using sprintf here. If there ever are, well, yyyyeah.
                    char announcement[191];
                    sprintf( announcement, "\napplication\n"\
                    " service playback flash:/playback.tcl\n"\
                    "  param playback-file flash:verification.au\n"\
                    "  exit\nexit\n"\
                    "dial-peer voice 9901 pots\n"\
                    " service playback\n"\
                    " destination-pattern %d9901\n"\
                    " exit\n", request->session->nxx);
                    strncat(postpage, announcement, 190);
                }
                char fxobuffer[333];
                if (request->session->fxo > 0) {
                    snprintf(fxobuffer, 332, "\nvoice translation-profile fxo-outbound\n"\
                    " translate called 1\n"\
                    " exit\n\n"\
                    "voice translation-rule 1\n"\
                    " rule 1 /^8./ //\n"\
                    " exit\n");
                    strncat(postpage, fxobuffer, 332);
                }
                for (unsigned char iterator = 0; iterator < request->session->fxo; iterator++) {
                    snprintf(fxobuffer, 332, "\nvoice-port %d/%d\n"\
                    " connection plar opx %s\n"\
                    " %s\nexit\n\n"\
                    "dial-peer voice %d pots\n"\
                    " description Automatically provisioned FXO port %d of %d\n"\
                    " port %d/%d\n"\
                    " no sip-register\n"\
                    "translation-profile outgoing fxo-outbound\n"\
                    " destination-pattern 8%d.T\n"\
                    " exit\n", request->session->fxoslot, (request->session->fxoport + iterator), request->session->fxodest, (request->session->features & 4) ? "caller-id enable type 1\n" : "",(100 + iterator), iterator+1, request->session->fxo, request->session->fxoslot, (request->session->fxoport + iterator), iterator);
                    strncat(postpage, fxobuffer, 332);
                }
                char fxsbuffer[355];
                for (unsigned char iterator = 0; iterator < request->session->fxs; iterator++) {
                    snprintf(fxsbuffer, 354, "\nvoice-port %d/%d\n"\
                    " no comfort-noise\n"\
                    " %s"\
                    "station-id number %d909%d\n exit\n\n"\
                    "dial-peer voice %d pots\n"\
                    " description Automatically provisioned FXS port %d of %d\n"\
                    " port %d/%d\n"\
                    " no sip-register\n"\
                    " destination-pattern %d909%d\n"\
                    " exit\n", request->session->fxsslot, (request->session->fxsport + iterator), ( request->session->features & 2) ? "caller-id enable type 1\n ": "", request->session->nxx, iterator, (200 + iterator), iterator+1, request->session->fxs, request->session->fxsslot, (request->session->fxsport + iterator), request->session->nxx, iterator);

                    strncat(postpage, fxsbuffer, 354);
                }
                // SQL output goes here
                char sqlpeer[386]; // TO DO: An actual dial peer config line is going to be longer. Establish the length and make it longer.
                sqlite3_prepare_v2(DB, "SELECT * FROM PEER;", -1, &statement, 0);

                for (int counter = 0; counter < count; counter++) {
                    result = sqlite3_step(statement);
                    if (result == SQLITE_ROW) {
                        if (sqlite3_column_int(statement, 2)) {
                            // H.323 or SIP peer. TO DO: If protocol == 2, add SIP protocol specifier.
                            snprintf(sqlpeer, 370, "dial-peer voice 4%02d voip\n"\
                            "description %s\n"\
                            "session target ipv4:%s\n"\
                            "destination-pattern %d....\n"\
                            "huntstop\n"\
                            "codec g711ulaw\n"\
                            "exit\n\n",
                            sqlite3_column_int(statement, 0),
                            sqlite3_column_text(statement, 1),
                            sqlite3_column_text(statement, 3),
                            sqlite3_column_int(statement, 4));
                            strncat(postpage, sqlpeer, 385);
                        }
                    }

                    else {
                        fprintf(stderr, "ERROR Result code was %d\n", result);
                    }

                }
                response = MHD_create_response_from_buffer (strlen (postpage), (void*) postpage, MHD_RESPMEM_PERSISTENT); // Is this still persistent?
                MHD_add_response_header( response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/plain"); // The config file we return will be a text file, because why wouldn't it?
                ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
                MHD_destroy_response (response);
                return ret;
            }
            printf("DEBUG: We should never get to this point.\n");
            return MHD_NO;
        }
        else if (strcmp(url, "/as5300config") == 0) {
            struct Request *request = *con_cls;
            if (request == NULL) {
                request = calloc(1, sizeof(struct Request));
                if (request == NULL) {
                    fprintf( stderr, "ERROR: calloc/%s\n", strerror(errno));
                    return MHD_NO;
                }
                request->pp = MHD_create_post_processor(connection, 1024, &isr_post_parse, request);
                if (request->pp == NULL) {
                    fprintf( stderr, "ERROR: Failed to setup post process for %s!\n", url);
                    return MHD_NO;
                }
                *con_cls = request;
                return MHD_YES;
            }
            if (request->session == NULL) {
                request->session = get_session(connection);
                if (request->session == NULL) {
                    fprintf(stderr, "ERROR: Failed to start session for %s\n", url);
                    return MHD_NO;
                }

            }
            if (*upload_data_size) {
                MHD_post_process(request->pp, upload_data, *upload_data_size);
                *upload_data_size = 0;
                return MHD_YES;
            }
            else {
                struct MHD_Response *response;
                sqlite3_stmt *statement = NULL;
                // The SQL query is executed on another thread, and we need as close as we can get to a blocking function call for this.
                // Thankfully, sqlite3_prepare_v2() works rather well. This particular call is just to see how many entries are in the DB.
                // If it fails, we'll send back a 500 error.
                sqlite3_prepare_v2(DB, "SELECT COUNT(*) FROM PEER;", -1, &statement, 0);
                if (statement == NULL) {
                    fprintf(stderr, "ERROR: sqlite3_prepare_v2 returned null pointer for query!\n");
                    return gen_error_page(connection, INTERNAL_SERVER_ERROR);
                }
                int result = sqlite3_step(statement);
                int count = 0;

                if (result == SQLITE_ROW) {
                    count = sqlite3_column_int(statement, 0);
                }
                else {
                    // WHAT IN THE NAME OF HATBOWLS?! BAIL OOOOUT D:
                    fprintf(stderr, "ERROR: SQL Result code was %d\n", result);
                    return gen_error_page(connection, INTERNAL_SERVER_ERROR);
                }

                if (count == 0) {
                    fprintf(stderr, "ERROR: SQL query returned zero results!\n");
                    return gen_error_page(connection, INTERNAL_SERVER_ERROR);
                }

                char postpage[4701 + (count * 371)]; // ...seriously? We can create a variable-sized array like this? Maybe this should be a malloc or something, so we can handle a memory allocation failure gracefully.
                memset(postpage, 0x00, sizeof(postpage));
                char loopback[171]; // snprintf size + 1 to make sure the compiler doesn't complain. TO DO: Refer to reference to make sure this is how2sprintf, since it likes to complain anyway.
                unsigned char looplen = strlen(request->session->nataddr);
                if (looplen != 0) {
                    snprintf(loopback,sizeof(loopback), "\n! Be sure that interface Loopback0 is unallocated before pasting this\n"\
                    "interface Loopback0\n"\
                    " ip address %s 255.255.255.255\n"\
                    " no shut\n"\
                    " exit\n", request->session->nataddr);
                    //strncat(postpage, loopback, 161);
                }
                // TO DO: Re-check length for this
                snprintf(postpage, 934, "! Please paste this into your router:\n"\
                "interface FastEthernet0 ! We'll be assuming use of the non-T Base 10 ethernet interface here\n"\
                " ip address %s 255.255.255.0 ! Subnet mask of 255.255.255.0 is also assumed at this point.\n"\
                " no shutdown\n"\
                " exit\n"\
                "%s"\
                "ip routing\n"\
                "ip route 0.0.0.0 0.0.0.0 %s\n"\
                "voice service voip\n"\
                " h323\n"\
                "  exit\n"\
                " sip\n"\
                "  exit\n"\
                "voice class codec 1\n"\
                " codec preference 1 g711ulaw\n"\
                " exit\n", request->session->ipaddr, looplen ? loopback : "", request->session->gateway);

                if (request->session->features & 8) {
                    char priconfig[1604];
                    snprintf(priconfig, 1603, "\nivr prompt streamed flash\n"\
                    "isdn switch-type primary-%s\n"\
                    " controller T1 %d\n"\
                    " cablelength %s %s\n pri-group timeslots 1-24\n"\
                    " ! DS0 group options may be added at a later point\n"\
                    " clock source %s\n"\
                    " ! For PRI, we will be hard set to B8ZS/ESF linecoding/framing on the T1\n"\
                    " framing esf\n"\
                    " linecode b8zs\n"\
                    " exit\n\ninterface Serial%d:23\n"\
                    " no ip address\n"\
                    " encapsulation hdlc\n"\
                    " isdn switch-type primary-%s\n"\
                    " isdn protocol-emulate %s\n"\
                    " isdn incoming-voice modem\n isdn map address .* plan %s type %s\n"\
                    " isdn send-alerting\n"\
                    " ! cdp is effectively logging; beyond the scope of the project.\n"\
                    " no cdp enable\n"\
                    " exit\n\n"\
                    "! Please make sure this dial-peer is unallocated.\n"\
                    "dial-peer voice %d%d pots\n"\
                    " destination-pattern %d%d...\n"\
                    " supplementary-service pass-through\n"\
                    " port %d:D\n"\
                    " description SCDP PRI\n"\
                    " exit\n", request->session->isdnflavor, request->session->tport, ( request->session->tlen > 10 ) ? "long" : "short", request->session->cablelength, (request->session->features & 16) ? "internal" : "line primary", request->session->tport, request->session->isdnflavor, request->session->isdnside, request->session->numplan, request->session->cntyp, request->session->nxx, request->session->pritb, request->session->nxx, request->session->pritb, request->session->tport);
                strncat(postpage, priconfig, 1603);
                }
                if (request->session->features & 1) {
                    // Since there's no strings to input into the config, we're just using sprintf here. If there ever are, well, yyyyeah.
                    char announcement[207];
                    sprintf( announcement, "\ncall application voice playback flash:/playback.tcl\n"\
                    "call application voice playback playback-file flash:verification.au\n"\
                    "dial-peer voice 9901 pots\n"\
                    " application playback\n"\
                    " destination-pattern %d9901\n"\
                    " exit\n", request->session->nxx);
                    strncat(postpage, announcement, 206);
                }
                // TO DO: Re-evaluate allocation size

                    if (request->session->fxs > 0) {
                    unsigned short fxscap = (50 * request->session->fxs) + 193;
                    if (fxscap < 355) fxscap = 355;
                    char fxsbuffer[fxscap];
                    char changroup[50];
                    snprintf( fxsbuffer, fxscap, "controller t1 %d\n"\
                    " framing %s\n"\
                    " linecode %s\n"\
                    " clock source internal\n"\
                    " ! We'll be assuming at this point that we're providing clock to the channel bank and not the other way around\n"\
                    " no shut\n", request->session->fxsslot, request->session->features & 2 ? "esf" : "sf", request->session->features & 4 ? "b8zs" : "ami");
                    for (unsigned char iterator = 0; iterator < request->session->fxs; iterator++) {
                        snprintf(changroup, 50, " ds0-group %d timeslots %d type fxs-loop-start\n", iterator, (iterator + 1) );
                        strncat(fxsbuffer, changroup, 50);
                    }
                    strncat(fxsbuffer, " exit\n", 7);
                    strncat(postpage, fxsbuffer, fxscap);
                for (unsigned char iterator = 0; iterator < request->session->fxs; iterator++) {
                    snprintf(fxsbuffer, 354, "\nvoice-port %d:%d\n"\
                    " no comfort-noise\n"\
                    "station-id number %d90%d\n exit\n\n"\
                    "dial-peer voice %d pots\n"\
                    " description Automatically provisioned FXS port %d of %d\n"\
                    " port %d:%d\n"\
                    " destination-pattern %d90%d\n"\
                    " exit\n", request->session->fxsslot, (request->session->fxsport + iterator), request->session->nxx, (iterator + 70), (200 + iterator), iterator+1, request->session->fxs, request->session->fxsslot, (request->session->fxsport + iterator), request->session->nxx, (iterator + 70) );

                    strncat(postpage, fxsbuffer, 354);
                    }
                }
                // SQL output goes here
                char sqlpeer[386]; // TO DO: An actual dial peer config line is going to be longer. Establish the length and make it longer.
                sqlite3_prepare_v2(DB, "SELECT * FROM PEER;", -1, &statement, 0);

                for (int counter = 0; counter < count; counter++) {
                    result = sqlite3_step(statement);
                    if (result == SQLITE_ROW) {
                        if (sqlite3_column_int(statement, 2)) {
                            // H.323 or SIP peer. TO DO: If protocol == 2, add SIP protocol specifier.
                            snprintf(sqlpeer, 370, "dial-peer voice 4%02d voip\n"\
                            "description %s\n"\
                            "session target ipv4:%s\n"\
                            "destination-pattern %d....\n"\
                            "huntstop\n"\
                            "voice-class codec 1\n"\
                            "no vad\n"\
                            "exit\n\n",
                            sqlite3_column_int(statement, 0),
                            sqlite3_column_text(statement, 1),
                            sqlite3_column_text(statement, 3),
                            sqlite3_column_int(statement, 4));
                            strncat(postpage, sqlpeer, 385);
                        }
                    }

                    else {
                        fprintf(stderr, "ERROR Result code was %d\n", result);
                    }

                }
                response = MHD_create_response_from_buffer (strlen (postpage), (void*) postpage, MHD_RESPMEM_PERSISTENT); // Is this still persistent?
                MHD_add_response_header( response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/plain"); // The config file we return will be a text file, because why wouldn't it?
                ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
                MHD_destroy_response (response);
                return ret;
            }
            printf("DEBUG: We should never get to this point.\n");
            return MHD_NO;
        }
        else if (strcmp(url, "/mc3810config") == 0) {
            struct Request *request = *con_cls;
            if (request == NULL) {
                request = calloc(1, sizeof(struct Request));
                if (request == NULL) {
                    fprintf( stderr, "ERROR: calloc/%s\n", strerror(errno));
                    return MHD_NO;
                }
                request->pp = MHD_create_post_processor(connection, 1024, &isr_post_parse, request);
                if (request->pp == NULL) {
                    fprintf( stderr, "ERROR: Failed to setup post process for %s!\n", url);
                    return MHD_NO;
                }
                *con_cls = request;
                return MHD_YES;
            }
            if (request->session == NULL) {
                request->session = get_session(connection);
                if (request->session == NULL) {
                    fprintf(stderr, "ERROR: Failed to start session for %s\n", url);
                    return MHD_NO;
                }

            }
            if (*upload_data_size) {
                MHD_post_process(request->pp, upload_data, *upload_data_size);
                *upload_data_size = 0;
                return MHD_YES;
            }
            else {
                struct MHD_Response *response;
                sqlite3_stmt *statement = NULL;
                // The SQL query is executed on another thread, and we need as close as we can get to a blocking function call for this.
                // Thankfully, sqlite3_prepare_v2() works rather well. This particular call is just to see how many entries are in the DB.
                // If it fails, we'll send back a 500 error.
                sqlite3_prepare_v2(DB, "SELECT COUNT(*) FROM PEER;", -1, &statement, 0);
                if (statement == NULL) {
                    fprintf(stderr, "ERROR: sqlite3_prepare_v2 returned null pointer for query!\n");
                    return gen_error_page(connection, INTERNAL_SERVER_ERROR);
                }
                int result = sqlite3_step(statement);
                int count = 0;

                if (result == SQLITE_ROW) {
                    count = sqlite3_column_int(statement, 0);
                }
                else {
                    // WHAT IN THE NAME OF HATBOWLS?! BAIL OOOOUT D:
                    fprintf(stderr, "ERROR: SQL Result code was %d\n", result);
                    return gen_error_page(connection, INTERNAL_SERVER_ERROR);
                }

                if (count == 0) {
                    fprintf(stderr, "ERROR: SQL query returned zero results!\n");
                    return gen_error_page(connection, INTERNAL_SERVER_ERROR);
                }

                char postpage[4701 + (count * 371)]; // ...seriously? We can create a variable-sized array like this? Maybe this should be a malloc or something, so we can handle a memory allocation failure gracefully.
                memset(postpage, 0x00, sizeof(postpage));
                char loopback[171]; // snprintf size + 1 to make sure the compiler doesn't complain. TO DO: Refer to reference to make sure this is how2sprintf, since it likes to complain anyway.
                unsigned char looplen = strlen(request->session->nataddr);
                if (looplen != 0) {
                    snprintf(loopback,sizeof(loopback), "\n! Be sure that interface Loopback0 is unallocated before pasting this\n"\
                    "interface Loopback0\n"\
                    " ip address %s 255.255.255.255\n"\
                    " no shut\n"\
                    " exit\n", request->session->nataddr);
                    //strncat(postpage, loopback, 161);
                }
                // TO DO: Re-check length for this
                snprintf(postpage, 934, "! Please paste this into your router:\n"\
                "interface Ethernet0\n"\
                " ip address %s 255.255.255.0 ! Subnet mask of 255.255.255.0 is also assumed at this point.\n"\
                " no shutdown\n"\
                " exit\n"\
                "%s"\
                "ip routing\n"\
                "ip route 0.0.0.0 0.0.0.0 %s\n"\
                "voice service voip\n"\
                " h323\n"\
                "  exit\n"\
                " sip\n"\
                "  exit\n"\
                " network-clock base-rate 64k\n"\
                "voice class codec 1\n"\
                " codec preference 1 g711ulaw\n"\
                " exit\n", request->session->ipaddr, looplen ? loopback : "", request->session->gateway);

                if (request->session->features & 8) {
                    char priconfig[1604];
                    snprintf(priconfig, 1603, "\nivr prompt streamed flash\n"\
                    "isdn switch-type primary-%s\n"\
                    " controller T1 %d\n"\
                    " pri-group timeslots 1-24\n"\
                    " ! DS0 group options may be added at a later point\n"\
                    " clock source %s\n"\
                    " ! For PRI, we will be hard set to B8ZS/ESF linecoding/framing on the T1\n"\
                    " framing esf\n"\
                    " linecode b8zs\n"\
                    " exit\n\ninterface Serial%d:23\n"\
                    " no ip address\n"\
                    " encapsulation hdlc\n"\
                    " isdn switch-type primary-%s\n"\
                    " isdn protocol-emulate %s\n"\
                    " isdn incoming-voice voice\n isdn map address .* plan %s type %s\n"\
                    " isdn send-alerting\n"\
                    " ! cdp is effectively logging; beyond the scope of the project.\n"\
                    " no cdp enable\n"\
                    " exit\n\n"\
                    "! Please make sure this dial-peer is unallocated.\n"\
                    "dial-peer voice %d%d pots\n"\
                    " destination-pattern %d%d...\n"\
                    " supplementary-service pass-through\n"\
                    " port %d:23\n"\
                    " description SCDP PRI\n"\
                    " exit\n", request->session->isdnflavor, request->session->tport, (request->session->features & 16) ? "internal" : "line", request->session->tport, request->session->isdnflavor, request->session->isdnside, request->session->numplan, request->session->cntyp, request->session->nxx, request->session->pritb, request->session->nxx, request->session->pritb, request->session->tport);
                strncat(postpage, priconfig, 1603);
                }
                if (request->session->features & 1) {
                    // Since there's no strings to input into the config, we're just using sprintf here. If there ever are, well, yyyyeah.
                    char announcement[207];
                    sprintf( announcement, "\ncall application voice playback flash:/playback.tcl\n"\
                    "call application voice playback playback-file flash:verification.au\n"\
                    "dial-peer voice 9901 pots\n"\
                    " application playback\n"\
                    " destination-pattern %d9901\n"\
                    " exit\n", request->session->nxx);
                    strncat(postpage, announcement, 206);
                }
                // TO DO: Re-evaluate allocation size

                char fxobuffer[333];
                if (request->session->fxo > 0) {
                    snprintf(fxobuffer, 332, "\nvoice translation-profile fxo-outbound\n"\
                    " translate called 1\n"\
                    " exit\n\n"\
                    "voice translation-rule 1\n"\
                    " rule 1 /^8./ //\n"\
                    " exit\n");
                    strncat(postpage, fxobuffer, 332);
                }
                for (unsigned char iterator = 0; iterator < request->session->fxo; iterator++) {
                    snprintf(fxobuffer, 332, "\nvoice-port %d/%d\n"\
                    " connection plar opx %s\n"\
                    " %s\nexit\n\n"\
                    "dial-peer voice %d pots\n"\
                    " description Automatically provisioned FXO port %d of %d\n"\
                    " port %d/%d\n"\
                    " no sip-register\n"\
                    "translation-profile outgoing fxo-outbound\n"\
                    " destination-pattern 8%d.T\n"\
                    " exit\n", request->session->fxoslot, (request->session->fxoport + iterator), request->session->fxodest, (request->session->features & 4) ? "caller-id enable type 1\n" : "",(100 + iterator), iterator+1, request->session->fxo, request->session->fxoslot, (request->session->fxoport + iterator), iterator);
                    strncat(postpage, fxobuffer, 332);
                }
                char fxsbuffer[355];
                for (unsigned char iterator = 0; iterator < request->session->fxs; iterator++) {
                    snprintf(fxsbuffer, 354, "\nvoice-port %d/%d\n"\
                    " no comfort-noise\n"\
                    " %s"\
                    "station-id number %d909%d\n exit\n\n"\
                    "dial-peer voice %d pots\n"\
                    " description Automatically provisioned FXS port %d of %d\n"\
                    " port %d/%d\n"\
                    " no sip-register\n"\
                    " destination-pattern %d909%d\n"\
                    " exit\n", request->session->fxsslot, (request->session->fxsport + iterator), ( request->session->features & 2) ? "caller-id enable type 1\n ": "", request->session->nxx, iterator, (200 + iterator), iterator+1, request->session->fxs, request->session->fxsslot, (request->session->fxsport + iterator), request->session->nxx, iterator);

                    strncat(postpage, fxsbuffer, 354);
                }
                // SQL output goes here
                char sqlpeer[386]; // TO DO: An actual dial peer config line is going to be longer. Establish the length and make it longer.
                sqlite3_prepare_v2(DB, "SELECT * FROM PEER;", -1, &statement, 0);

                for (int counter = 0; counter < count; counter++) {
                    result = sqlite3_step(statement);
                    if (result == SQLITE_ROW) {
                        if (sqlite3_column_int(statement, 2)) {
                            // H.323 or SIP peer. TO DO: If protocol == 2, add SIP protocol specifier.
                            snprintf(sqlpeer, 370, "dial-peer voice 4%02d voip\n"\
                            "description %s\n"\
                            "session target ipv4:%s\n"\
                            "destination-pattern %d....\n"\
                            "huntstop\n"\
                            "voice-class codec 1\n"\
                            "no vad\n"\
                            "exit\n\n",
                            sqlite3_column_int(statement, 0),
                            sqlite3_column_text(statement, 1),
                            sqlite3_column_text(statement, 3),
                            sqlite3_column_int(statement, 4));
                            strncat(postpage, sqlpeer, 385);
                        }
                    }

                    else {
                        fprintf(stderr, "ERROR Result code was %d\n", result);
                    }

                }
                response = MHD_create_response_from_buffer (strlen (postpage), (void*) postpage, MHD_RESPMEM_PERSISTENT); // Is this still persistent?
                MHD_add_response_header( response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/plain"); // The config file we return will be a text file, because why wouldn't it?
                ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
                MHD_destroy_response (response);
                return ret;
            }
            printf("DEBUG: We should never get to this point.\n");
            return MHD_NO;
        }
        else {
            return gen_error_page(connection, NOT_FOUND);
        }
    }

    else if (strcmp(method, MHD_HTTP_METHOD_GET) != 0) {
        return gen_error_page(connection, BAD_REQUEST);
    }

    // TO DO: Is strncmp necessary?

    // For reference, a URL is generally accepted to be a maximum of 2000 characters.

    // Do be aware of any potential HTML injection.
    struct MHD_Response *response;
    if (strncmp("/diskspace", url, 10) == 0) {
        // Return df -h command
        FILE *cmddescriptor = popen("df -h", "r");
        if (cmddescriptor == NULL) {
            printf("ERROR: popen() failed!!\n");
            return MHD_NO;
        }
        // Especially with how big the buffer is here, initializing everything to 0x00 is really important. So uhh, do it.
        char cmdout[9974] = {0};
        fread( cmdout, 9973, 1, cmddescriptor);
        pclose(cmddescriptor);
        response = MHD_create_response_from_buffer (strlen (cmdout), (void*) cmdout, MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header( response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/plain");
        ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
        MHD_destroy_response (response);
        return ret;
    }
    else if (strncmp("/cpuinfo", url, 8) == 0) {
        // Return cat /proc/cpuinfo
        FILE *cmddescriptor = popen("cat /proc/cpuinfo", "r");
        if (cmddescriptor == NULL) {
            printf("ERROR: popen() failed!!\n");
            return MHD_NO;
        }
        char cmdout[15474] = {0};
        fread( cmdout, 15473, 1, cmddescriptor);
        pclose(cmddescriptor);
        response = MHD_create_response_from_buffer (strlen (cmdout), (void*) cmdout, MHD_RESPMEM_MUST_COPY);// Don't use MHD_RESPMEM_PERSISTENT here; the buffer is being stored in transient memory
        MHD_add_response_header( response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/plain");
        ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
        MHD_destroy_response (response);
        return ret;
    }

    else if (strncmp("/mem", url, 4) == 0) {
        // Return free command
        FILE *cmddescriptor = popen("free -h", "r");
        if (cmddescriptor == NULL) {
            printf("ERROR: popen() failed!!\n");
            return MHD_NO;
        }
        char cmdout[9974] = {0};
        fread( cmdout, 9973, 1, cmddescriptor);
        pclose(cmddescriptor);
        response = MHD_create_response_from_buffer (strlen (cmdout), (void*) cmdout, MHD_RESPMEM_MUST_COPY);
        MHD_add_response_header( response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/plain");
        ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
        MHD_destroy_response (response);
        return ret;
    }

    else if (strncmp("/", url, 2) == 0) {
        response = MHD_create_response_from_buffer (strlen (isrpage[1]), (void*) isrpage[1], MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header( response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/html"); // by request, a text/html header is being added to the output
        ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
        MHD_destroy_response (response);
        return ret;
    }
    else if (strncmp("/model", url, 18) == 0) {
        const char * type = MHD_lookup_connection_value(connection, MHD_GET_ARGUMENT_KIND, "model");
        // TO DO: Get reasonable max value, change with strncmp

        if (type == NULL) {
            return gen_error_page(connection, INTERNAL_SERVER_ERROR);
        }
        if (strcmp("2800", type) == 0) {
            response = MHD_create_response_from_buffer (strlen (isrpage[0]), (void*) isrpage[0], MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header( response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/html"); // by request, a text/html header is being added to the output
            ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
            MHD_destroy_response (response);
            return ret;
        }
        else if (strcmp("2900", type) == 0) {
            response = MHD_create_response_from_buffer (strlen (isrpage[2]), (void*) isrpage[2], MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header( response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/html"); // by request, a text/html header is being added to the output
            ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
            MHD_destroy_response (response);
            return ret;
        }
        else if (strcmp("iad2430", type) == 0) {
            response = MHD_create_response_from_buffer (strlen (isrpage[3]), (void*) isrpage[3], MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header( response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/html"); // by request, a text/html header is being added to the output
            ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
            MHD_destroy_response (response);
            return ret;
        }
        else if (strcmp("as5300", type) == 0) {
            response = MHD_create_response_from_buffer (strlen (isrpage[4]), (void*) isrpage[4], MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header( response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/html"); // by request, a text/html header is being added to the output
            ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
            MHD_destroy_response (response);
            return ret;
        }
        else if (strcmp("mc3800", type) == 0) {
            response = MHD_create_response_from_buffer (strlen (isrpage[5]), (void*) isrpage[5], MHD_RESPMEM_PERSISTENT);
            MHD_add_response_header( response, MHD_HTTP_HEADER_CONTENT_TYPE, "text/html"); // by request, a text/html header is being added to the output
            ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
            MHD_destroy_response (response);
            return ret;
        }
        // Can we get rid of this last line and just let it fall through to the 404 at the bottom? That might break things later...
        else {
            return gen_error_page(connection, NOT_FOUND);
        }
    }


    const char * page = "<html><title>404 Not Found</title><body>404 Not Found</body></html>";
    response = MHD_create_response_from_buffer (strlen (page), (void*) page, MHD_RESPMEM_PERSISTENT);
    ret = MHD_queue_response (connection, MHD_HTTP_NOT_FOUND, response);
    MHD_destroy_response (response);
    return ret;

    //return gen_error_page(connection, NOT_FOUND); // Reverted to resident memory/non-functionalized for 404; this is the most likely error condition, and should be dealt with efficiently
}

void completereq_hdlr( void *cls, struct MHD_Connection *connection, void **con_cls, enum MHD_RequestTerminationCode toe)
{
    struct Request *request = *con_cls;
    if (request == NULL) return;
    if (NULL != request->pp) MHD_destroy_post_processor (request->pp);
    free(request);
    return;
}

// This is an implementation of the Windows fsize() library function, since that doesn't exist on *nix systems.
long fsize(FILE *fp) {
    // ftell will return -1 if there's an error. This should be worked into all error handling functionality.
    fseek(fp, 0, SEEK_END);
    long bytes = ftell(fp);
    rewind(fp);
    return bytes;
}


void * openhtml(char * filename) {
    void * mem;
    FILE * isrpagefd;
    isrpagefd = fopen(filename, "r");
    if (isrpagefd == NULL) {
        fprintf(stderr, "ERROR: Couldn't open %s! Exiting...\n", filename);
        return NULL;
    }
    long htmlsize = fsize(isrpagefd);
    if (htmlsize == -1) {
        fprintf( stderr, "ERROR: fsize() returned -1 for HTML file! Cannot initialize chttpd!\n");
        fclose(isrpagefd);
        return NULL;
    }
    mem = malloc(htmlsize);
    if (mem == NULL) {
        fprintf( stderr, "ERROR: Couldn't allocate memory for HTML file! Exiting...\n");
        fclose(isrpagefd);
        return NULL;
    }
    if ((fread(mem, 1, htmlsize, isrpagefd)) != htmlsize) {
        if(feof(isrpagefd)) {
            fprintf(stderr, "ERROR: Couldn't read %s! Unexpected end of file\n", filename);
        }

        else if (ferror(isrpagefd)) {
            fprintf(stderr, "ERROR: Coudln't read %s!\n", filename);
        }

        else {
            fprintf(stderr, "ERROR: Unknown error reading %s!\n", filename);
        }

        fclose(isrpagefd);
        return NULL;
    }
    printf("DEBUG: Successfully read %s!\n", filename);
    fclose(isrpagefd);
    return mem;
}

int main()
{
    if (sqlite3_open("scdp_peers.db", &DB) != SQLITE_OK) {
        fprintf(stderr, "ERROR: Unable to open SQL database! Exiting...\n");
        return -1;
    }
    isrpage[0] = openhtml("2800post.html");
    if (isrpage[0] == NULL) {
        sqlite3_close(DB);
        return -1;
    }
    isrpage[1] = openhtml("main.html");
    if (isrpage[1] == NULL) {
        sqlite3_close(DB);
        free(isrpage[0]);
        return -1;
    }
    isrpage[2] = openhtml("2900post.html");
    if (isrpage[2] == NULL) {
        free(isrpage[0]);
        free(isrpage[1]);
        sqlite3_close(DB);
        return -1;
    }
    isrpage[3] = openhtml("2400post.html");
    if (isrpage[3] == NULL) {
        free(isrpage[0]);
        free(isrpage[1]);
        free(isrpage[2]);
        sqlite3_close(DB);
        return -1;
    }
    isrpage[4] = openhtml("as5300post.html");
    if (isrpage[4] == NULL) {
        free(isrpage[0]);
        free(isrpage[1]);
        free(isrpage[2]);
        free(isrpage[3]);
        sqlite3_close(DB);
        return -1;
    }
    isrpage[5] = openhtml("mc3800post.html");
    if (isrpage[5] == NULL) {
        free(isrpage[0]);
        free(isrpage[1]);
        free(isrpage[2]);
        free(isrpage[3]);
        free(isrpage[4]);
        sqlite3_close(DB);
        return -1;
    }
    struct MHD_Daemon *daemon;
    daemon = MHD_start_daemon (MHD_USE_INTERNAL_POLLING_THREAD, PORT, NULL, NULL,
    &answer_to_connection, NULL, MHD_OPTION_NOTIFY_COMPLETED, &completereq_hdlr, NULL, MHD_OPTION_END);
    if (daemon == NULL) return 1;

    getchar(); // TO DO: This requires stdin to exist, which it may not for a Docker container. It should be removed.
    // TO DO: Many of the errors are directed to stderr. If stdout and stderr don't exist (like in a Docker container), this will be a problem. The code should deal with this.

    MHD_stop_daemon (daemon);
    free(isrpage[0]);
    free(isrpage[1]);
    free(isrpage[2]);
    free(isrpage[3]);
    free(isrpage[4]);
    sqlite3_close(DB);
    return 0;
}
