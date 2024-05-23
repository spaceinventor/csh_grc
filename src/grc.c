#include <slash/slash.h>
#include <slash/optparse.h>
#include <slash/dflopt.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <stdint.h>

#include <zmq.h>
#include <assert.h>
#include <stdlib.h>

#include <csp/csp.h>
#include <csp/csp_debug.h>
#include <csp/csp_id.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <csp/interfaces/csp_if_zmqhub.h>

#include <ccsds.h>
#include <crypto/crypto.h>

static int ifidx = 0;
#define TX_BUF_LEN 2048

typedef struct {
	pthread_t rx_thread;
	void * context;
	void * publisher;
	void * subscriber;
	char name[CSP_IFLIST_NAME_MAX + 1];
	csp_iface_t iface;

    ccsds_frame_obj_t tx_ccsds_obj;
    ccsds_frame_obj_t rx_ccsds_obj;
} zmq_driver_t;

struct grc_msg_s {
	char padding[29];
	uint8_t *frame;
};

/* Linux is fast, so we keep it simple by having a single lock */
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;

static int zmq_grc_ccsds_tx(csp_iface_t * iface, uint16_t via, csp_packet_t * packet, int from_me) {

    int result = CSP_ERR_NONE;

    zmq_driver_t * drv = iface->driver_data;

    csp_id_prepend(packet);

    if (param_get_uint8(&tx_encrypt)){
        packet->frame_length = crypto_encrypt(packet->frame_begin, packet->frame_length);
    }

    uint8_t *frame_buffer = malloc(sizeof(uint8_t) * TX_BUF_LEN);
    if (!frame_buffer) {
        result = CSP_ERR_NOMEM;
        goto out;
    }

    /* Split the transmission of the CSP packet up into a series of CCSDS frames */
    int nof_frames = ccsds_get_num_frames(packet->frame_length);
    ccsds_init_frame(&drv->tx_ccsds_obj, true, &CCSDS_ASM);
    for (int idx = 0; idx < nof_frames; idx++) {
        int len_total;

        len_total = ccsds_pack_next_frame(&drv->tx_ccsds_obj, packet, frame_buffer, drv->tx_ccsds_obj.this_seq);
        drv->tx_ccsds_obj.this_seq++;

	struct grc_msg_s pack = {
		.padding = {	
		0x07, 0x09, 0x07, 0x02, 0x00, 0x09, 0x72,
		0x73, 0x5f, 0x65, 0x72, 0x72, 0x6f, 0x72,
		0x73, 0x03, 0x00, 0x00, 0x00, 0x00, 0x06,
		0x0a, 0x00, 0x00, 0x00, 0x00, 0x0a, 0x01,
		0x00 },
		.frame = frame_buffer
	};

        pthread_mutex_lock(&lock);
        int result = zmq_send(drv->publisher, (void *) &pack, len_total, 0);
        pthread_mutex_unlock(&lock);

        if (result < 0) {
            csp_print("ZMQ send error: %u %s\n", result, zmq_strerror(zmq_errno()));
        }
    }

out:
    csp_buffer_free(packet);
    return result;
}

static void * zmq_grc_ccsds_task(void * param) {

	zmq_driver_t * drv = param;
    struct tm ts_time;

	while (1) {
		int ret;
		(void)ret; /* Silence unused variable warning (promoted to an error if -Werr) issued when building with NDEBUG (release with asserts turned off) */
		zmq_msg_t msg;

		ret = zmq_msg_init(&msg);
		assert(ret == 0);

		// Receive data
		if (zmq_msg_recv(&msg, drv->subscriber, 0) < 0) {
			csp_print("ZMQ RX err %s: %s\n", drv->iface.name, zmq_strerror(zmq_errno()));
			continue;
		}

		unsigned int datalen = zmq_msg_size(&msg);
        if(datalen < sizeof(cblk_hdr_t)){
            csp_print("GRC RX %s: CBLK HEADER LEN EXPECTED %u got datalen %u", drv->iface.name, sizeof(cblk_hdr_t), datalen);
			zmq_msg_close(&msg);
            continue;
        }

		uint8_t * rx_data = ((uint8_t *)zmq_msg_data(&msg));
        time_t ctx_time;
        /* Convert time stamp to UNIX time stamp */
        ctx_time = mktime(&ts_time);
        ccsds_unpack_frame(&drv->rx_ccsds_obj, &drv->iface, rx_data, ctx_time);
        zmq_msg_close(&msg);
    }
    return NULL;
}

static int csp_grc_zmq_init(const char * ifname, const char * host, uint16_t addr, uint16_t netmask, csp_iface_t ** return_interface, uint16_t subport, uint16_t pubport) {
	
	char pub[100];
	csp_zmqhub_make_endpoint(host, pubport, pub, sizeof(pub));

	char sub[100];
	csp_zmqhub_make_endpoint(host, subport, sub, sizeof(sub));

	int ret;
	(void)ret; /* Silence unused variable warning (promoted to an error if -Werr) issued when building with NDEBUG (release with asserts turned off) */
	pthread_attr_t attributes;
	zmq_driver_t * drv = calloc(1, sizeof(*drv));
	assert(drv != NULL);

	if (ifname == NULL) {
		ifname = "GRC_ZMQ";
	}

	strncpy(drv->name, ifname, sizeof(drv->name) - 1);
	drv->iface.name = drv->name;
	drv->iface.driver_data = drv;
	drv->iface.nexthop = zmq_grc_ccsds_tx;

	drv->context = zmq_ctx_new();
	assert(drv->context != NULL);

	csp_print("  ZMQ init %s: addr: %u, pub(tx): [%s], sub(rx): [%s]\n", drv->iface.name, addr, pub, sub);

	/* Publisher (TX) */
	drv->publisher = zmq_socket(drv->context, ZMQ_PUB);
	assert(drv->publisher != NULL);

	/* Subscriber (RX) */
	drv->subscriber = zmq_socket(drv->context, ZMQ_SUB);
	assert(drv->subscriber != NULL);

	int keep_alive = 1;
	/* Time in seconds a connection must be idle before keep-alive packet send*/
	int idle = 900;
	/* Maximum number of keep-alive probes to send without ack before connection closed */
	int cnt = 2;
	/* Interval in seconds between each keep-alive probe */
	int intvl = 900;
	/* Publisher (TX) */
	zmq_setsockopt(drv->publisher, ZMQ_TCP_KEEPALIVE, &keep_alive, sizeof(keep_alive));
	zmq_setsockopt(drv->publisher, ZMQ_TCP_KEEPALIVE_IDLE, &idle, sizeof(idle));
	zmq_setsockopt(drv->publisher, ZMQ_TCP_KEEPALIVE_CNT, &cnt, sizeof(cnt));
	zmq_setsockopt(drv->publisher, ZMQ_TCP_KEEPALIVE_INTVL, &intvl, sizeof(intvl));
	/* Subscriber (RX) */
	zmq_setsockopt(drv->subscriber, ZMQ_TCP_KEEPALIVE, &keep_alive, sizeof(keep_alive));
	zmq_setsockopt(drv->subscriber, ZMQ_TCP_KEEPALIVE_IDLE, &idle, sizeof(idle));
	zmq_setsockopt(drv->subscriber, ZMQ_TCP_KEEPALIVE_CNT, &cnt, sizeof(cnt));
	zmq_setsockopt(drv->subscriber, ZMQ_TCP_KEEPALIVE_INTVL, &intvl, sizeof(intvl));

	/* Connect to server */
	ret = zmq_connect(drv->publisher, pub);
	assert(ret == 0);
	ret = zmq_connect(drv->subscriber, sub);
	assert(ret == 0);


	// subscribe to all packets - no filter
	ret = zmq_setsockopt(drv->subscriber, ZMQ_SUBSCRIBE, NULL, 0);
	assert(ret == 0);

	/* Start RX thread */
	ret = pthread_attr_init(&attributes);
	assert(ret == 0);
	ret = pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
	assert(ret == 0);
	ret = pthread_create(&drv->rx_thread, &attributes, zmq_grc_ccsds_task, drv);
	assert(ret == 0);

	/* Register interface */
	csp_iflist_add(&drv->iface);

	if (return_interface) {
		*return_interface = &drv->iface;
	}

	return CSP_ERR_NONE;
}


static int csp_ifadd_grc(struct slash *slash) {

    char name[10];
    sprintf(name, "GRC%u", ifidx++);
   
    int dfl = 0;
    int mask = 8;
    unsigned int subport = 6666;
    unsigned int pubport = 7777;
    int dbg_lvl = 0;

    optparse_t * parser = optparse_new("csp add grc", "<node> <server>");
    optparse_add_help(parser);
    optparse_add_int(parser, 'm', "mask", "NUM", 0, &mask, "Netmask (defaults to 8)");
    optparse_add_set(parser, 'd', "default", 1, &dfl, "Set as default");
    optparse_add_unsigned(parser, 'S', "subport", "NUM", 0, &subport, "Subscriber port of GRC (default: 6666)");
    optparse_add_unsigned(parser, 'P', "pubport", "NUM", 0, &pubport, "Publisher port of GRC (default: 7777)");
    optparse_add_int(parser, 'D', "debug", "NUM", 0, &dbg_lvl, "debug level 0 - 5");

    int argi = optparse_parse(parser, slash->argc - 1, (const char **) slash->argv + 1);

    if (argi < 0) {
        optparse_del(parser);
	    return SLASH_EINVAL;
    }

	if (++argi >= slash->argc) {
		printf("missing parameter addr\n");
        optparse_del(parser);
		return SLASH_EINVAL;
	}
    char * endptr;
    unsigned int addr = strtoul(slash->argv[argi], &endptr, 10);

	if (++argi >= slash->argc) {
		printf("missing parameter server\n");
        optparse_del(parser);
		return SLASH_EINVAL;
	}
    char * server = slash->argv[argi];

    csp_iface_t * iface;
    csp_grc_zmq_init((const char *) name, server, addr, mask, &iface, subport, pubport);

    iface->is_default = dfl;
    iface->addr = addr;
	iface->netmask = mask;
    ccsds_frame_obj_t * rx_obj= &((zmq_driver_t*)iface->driver_data)->rx_ccsds_obj;
    ccsds_frame_obj_t * tx_obj= &((zmq_driver_t*)iface->driver_data)->tx_ccsds_obj;

	rx_obj->dbg_lvl = dbg_lvl;
	tx_obj->dbg_lvl = dbg_lvl;

	ccsds_init_frame(rx_obj, false, NULL);
	ccsds_init_frame(tx_obj, true, &CCSDS_ASM);

    optparse_del(parser);
    return SLASH_SUCCESS;
}
slash_command_subsub(csp, add, grc, csp_ifadd_grc, NULL, "Add a new GRC zmq interface");
