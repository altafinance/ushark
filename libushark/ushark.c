// START includes from tshark.c
#include <config.h>

#define WS_LOG_DOMAIN  LOG_DOMAIN_MAIN

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <limits.h>

#include <wsutil/ws_getopt.h>

#include <errno.h>

#ifdef _WIN32
# include <winsock2.h>
#endif

#ifndef _WIN32
#include <signal.h>
#endif

#include <glib.h>

#include <epan/exceptions.h>
#include <epan/epan.h>

#include <ui/clopts_common.h>
#include <ui/cmdarg_err.h>
#include <ui/exit_codes.h>
#include <ui/urls.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/socket.h>
#include <wsutil/privileges.h>
#include <wsutil/report_message.h>
#include <wsutil/please_report_bug.h>
#include <wsutil/wslog.h>
#include <wsutil/ws_assert.h>
#include <wsutil/strtoi.h>
#include <cli_main.h>
#include <ui/version_info.h>
#include <wiretap/wtap_opttypes.h>

#include "globals.h"
#include <epan/timestamp.h>
#include <epan/packet.h>
#ifdef HAVE_LUA
#include <epan/wslua/init_wslua.h>
#endif
#include "frame_tvbuff.h"
#include <epan/disabled_protos.h>
#include <epan/prefs.h>
#include <epan/column.h>
#include <epan/decode_as.h>
#include <epan/print.h>
#include <epan/addr_resolv.h>
#ifdef HAVE_LIBPCAP
#include "ui/capture_ui_utils.h"
#endif
#include "ui/taps.h"
#include "ui/util.h"
#include "ui/ws_ui_util.h"
#include "ui/decode_as_utils.h"
#include "ui/filter_files.h"
#include "ui/cli/tshark-tap.h"
#include "ui/cli/tap-exportobject.h"
#include "ui/tap_export_pdu.h"
#include "ui/dissect_opts.h"
#include "ui/ssl_key_export.h"
#include "ui/failure_message.h"
#if defined(HAVE_LIBSMI)
#include "epan/oids.h"
#endif
#include "epan/maxmind_db.h"
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/conversation_table.h>
#include <epan/srt_table.h>
#include <epan/rtd_table.h>
#include <epan/ex-opt.h>
#include <epan/exported_pdu.h>
#include <epan/secrets.h>

#include "capture_opts.h"

#include "capture/capture-pcap-util.h"

#ifdef HAVE_LIBPCAP
#include "capture/capture_ifinfo.h"
#ifdef _WIN32
#include "capture/capture-wpcap.h"
#endif /* _WIN32 */
#include <capture/capture_session.h>
#include <capture/capture_sync.h>
#include <ui/capture_info.h>
#endif /* HAVE_LIBPCAP */
#include <epan/funnel.h>

#include <wsutil/str_util.h>
#include <wsutil/utf8_entities.h>
#include <wsutil/json_dumper.h>
#include <wsutil/wslog.h>
#ifdef _WIN32
#include <wsutil/win32-utils.h>
#endif

#include "extcap.h"

#ifdef HAVE_PLUGINS
#include <wsutil/codecs.h>
#include <wsutil/plugins.h>
#endif
// END includes from tshark.c

/* ********************************************************** */

#include "ushark.h"
#include <pcap/pcap.h>
#include <wiretap/wtap-int.h>
#include <wiretap/pcap-encap.h>

static epan_t *g_epan;
#define init_done() (g_epan != NULL)

struct ushark {
    output_fields_t *output_fields;
    capture_file cfile;
    epan_dissect_t *edt;
    wtap_rec rec;
    Buffer buf;
    json_dumper jdumper;
    gboolean jdumper_finalized;
    GString *json_output;
    gint64 data_offset;

    struct {
        const u_char *pkt;
        const struct pcap_pkthdr *hdr;
    } dissect;

    struct {
        guint32 cum_bytes;
        frame_data ref_frame;
        frame_data prev_dis_frame;
        frame_data prev_cap_frame;
    } fdata;
};

// NOTE: keep in sync with epan.c
struct epan_session {
    struct packet_provider_data *prov;  /* packet provider data for this session */
    struct packet_provider_funcs funcs; /* functions using that data */
};

/* ********************************************************** */

static void
gather_ushark_compile_info(feature_list l)
{
    /* Capture libraries */
    gather_caplibs_compile_info(l);
    epan_gather_compile_info(l);
}

static void
gather_ushark_runtime_info(feature_list l)
{
#ifdef HAVE_LIBPCAP
    gather_caplibs_runtime_info(l);
#endif

    /* stuff used by libwireshark */
    epan_gather_runtime_info(l);
}

static const nstime_t *
ushark_get_frame_ts(struct packet_provider_data *prov, guint32 frame_num)
{
    // NOTE: frame_num is always 1 - from frame_ref_num (epan.c)
    //ws_message("ushark_get_frame_ts %u", frame_num);
    if (prov->ref && prov->ref->num == frame_num)
        return &prov->ref->abs_ts;

    if (prov->prev_dis && prov->prev_dis->num == frame_num)
        return &prov->prev_dis->abs_ts;

    if (prov->prev_cap && prov->prev_cap->num == frame_num)
        return &prov->prev_cap->abs_ts;

    if (prov->frames) {
        frame_data *fd = frame_data_sequence_find(prov->frames, frame_num);

        return (fd) ? &fd->abs_ts : NULL;
    }

    return NULL;
}

const char *
ushark_provider_get_interface_name(struct packet_provider_data *prov, guint32 interface_id)
{
    return "ushark";
}

const char *
ushark_provider_get_interface_description(struct packet_provider_data *prov, guint32 interface_id)
{
    return "ushark";
}

static epan_t *
ushark_epan_new()
{
    static const struct packet_provider_funcs funcs = {
        ushark_get_frame_ts,
        ushark_provider_get_interface_name,
        ushark_provider_get_interface_description,
        NULL,
    };

    // NOTE: we are passing NULL as packet_provider_data because the dissector
    // will be initialized afterwards. We will set the epan->prov pointer before
    // each dissection (see ushark_dissect)
    return epan_new(NULL, &funcs);
}

// like write_json_preamble, but write json to string
static json_dumper
write_json_preamble_to_str(GString *s) {
    json_dumper dumper = {
        .output_string = s,
        .flags = JSON_DUMPER_FLAGS_PRETTY_PRINT
    };
    json_dumper_begin_array(&dumper);
    return dumper;
}

void
ushark_set_pref(const char *name, const char *val)
{
    char buf[PATH_MAX];
    char *errmsg = NULL;

    ws_assert(init_done());

    snprintf(buf, sizeof(buf), "%s:%s", name, val);

    switch (prefs_set_pref(buf, &errmsg)) {
    case PREFS_SET_OK:
        break;

    case PREFS_SET_SYNTAX_ERR:
        ws_warning("%s: syntax error", name);
        break;

    case PREFS_SET_NO_SUCH_PREF:
        ws_warning("%s: no such pref", name);
        break;

    case PREFS_SET_OBSOLETE:
        ws_warning("%s: obsolete", name);
        break;
    }
}

static gboolean
_compile_dfilter(const char *text, dfilter_t **dfp, const char *caller)
{
    gboolean ok;
    dfilter_loc_t err_loc;
    char *err_msg = NULL;
    char *err_off;
    char *expanded;

    expanded = dfilter_expand(text, &err_msg);
    if (expanded == NULL) {
        g_warning("%s", err_msg);
        g_free(err_msg);
        return FALSE;
    }

    ok = dfilter_compile_real(expanded, dfp, &err_msg, &err_loc, caller, FALSE, FALSE);
    if (!ok ) {
        g_warning("%s", err_msg);
        g_free(err_msg);
        if (err_loc.col_start >= 0) {
            err_off = ws_strdup_underline(NULL, err_loc.col_start, err_loc.col_len);
            g_warning("    %s", expanded);
            g_warning("    %s", err_off);
            g_free(err_off);
        }
    }

    g_free(expanded);
    return ok;
}

#define compile_dfilter(text, dfp)      _compile_dfilter(text, dfp, __func__)

/*
 * Sequential read with offset reporting.
 * Read the next frame in the file and adjust for the multiframe size
 * indication. Report back where reading of this frame started to
 * support subsequent random access read.
 */
static gboolean
ushark_read(wtap *wth, wtap_rec *rec, Buffer *buf, int *err, gchar **err_info,
                    gint64 *data_offset) {
    // see usbdump.c
    ushark_t *sk = (ushark_t*) wth->priv;
    uint32_t len = sk->dissect.hdr->len;

    /* Report the current file location */
    *data_offset = sk->data_offset;
    //ws_message("ushark: +read %d", len);

    /* Setup the per packet structure and fill it with info from this frame */
    rec->rec_type = REC_TYPE_PACKET;
    rec->block = wtap_block_create(WTAP_BLOCK_PACKET);
    rec->presence_flags = WTAP_HAS_TS | WTAP_HAS_CAP_LEN;
    rec->ts.secs = sk->dissect.hdr->ts.tv_sec;
    rec->ts.nsecs = sk->dissect.hdr->ts.tv_usec * 1000;
    rec->rec_header.packet_header.len = len;
    rec->rec_header.packet_header.caplen = sk->dissect.hdr->caplen;

    /* Copy the packet data to the buffer */
    ws_buffer_assure_space(buf, len);
    memcpy(ws_buffer_start_ptr(buf), sk->dissect.pkt, len);
    sk->data_offset += len;

    return TRUE;
}

/*
 * Random access read.
 * Read the frame at the given offset in the file. Store the frame data
 * in a buffer and fill in the packet header info.
 */
static gboolean
ushark_seek(wtap *wth, gint64 seek_off, wtap_rec *rec,
                    Buffer *buf, int *err, gchar **err_info) {
    ws_error("ushark: seek-read not supported!");
    return FALSE;
}

// see wtap_open_offline
static wtap *
ushark_wtap_open(ushark_t *sk, unsigned int type) {
    wtap_block_t shb;

    wtap *wth = g_new0(wtap, 1);
    if (!wth)
        return NULL;

    /* initialization */
    wth->ispipe = FALSE;
    wth->file_encap = type;
    wth->subtype_sequential_close = NULL;
    wth->subtype_close = NULL;
    wth->file_tsprec = WTAP_TSPREC_USEC;
    wth->pathname = g_strdup("");
    wth->priv = NULL;
    wth->wslua_data = NULL;
    wth->shb_hdrs = g_array_new(FALSE, FALSE, sizeof(wtap_block_t));
    shb = wtap_block_create(WTAP_BLOCK_SECTION);
    if (shb)
        g_array_append_val(wth->shb_hdrs, shb);

    wth->priv = sk;
    wth->subtype_read = ushark_read;
    wth->subtype_seek_read = ushark_seek;
    wth->file_type_subtype = wtap_pcap_file_type_subtype();
    wth->file_tsprec = WTAP_TSPREC_USEC;

    return wth;
}

// from tshark.c
void
ushark_init()
{
    if (init_done())
        return;

    static const struct report_message_routines ushark_report_routines = {
        failure_message,
        failure_message,
        open_failure_message,
        read_failure_message,
        write_failure_message,
        cfile_open_failure_message,
        cfile_dump_open_failure_message,
        cfile_read_failure_message,
        cfile_write_failure_message,
        cfile_close_failure_message
    };

    /* Initialize log handler early so we can have proper logging during startup. */
    ws_log_init("ushark", vcmdarg_err);

    /* Initialize the version information. */
    ws_init_version_info("UShark",
                    gather_ushark_compile_info, gather_ushark_runtime_info);

    init_report_message("UShark", &ushark_report_routines);

    timestamp_set_type(TS_RELATIVE);
    timestamp_set_precision(TS_PREC_AUTO);
    timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

    /*
     * Libwiretap must be initialized before libwireshark is, so that
     * dissection-time handlers for file-type-dependent blocks can
     * register using the file type/subtype value for the file type.
     */
    wtap_init(TRUE);

    /* Register all dissectors; we must do this before checking for the
     "-G" flag, as the "-G" flag dumps information registered by the
     dissectors, and we must do it before we read the preferences, in
     case any dissectors register preferences. */
    ws_assert(epan_init(NULL, NULL, TRUE));

    /* Create new epan session for dissection.
     NOTE: due to the internal call to init_dissection, multiple epan
     instances are not allowed. */
    g_epan = ushark_epan_new();

    /* Load default settings */
    epan_load_settings();

    /* Disable geo-ip (not needed) */
    ushark_set_pref("ip.use_geoip", "false");
    ushark_set_pref("ipv6.use_geoip", "false");
}

void
ushark_cleanup()
{
    postseq_cleanup_all_protocols();

    epan_free(g_epan);
    epan_cleanup();
    g_epan = NULL;

    free_filter_lists();
    wtap_cleanup();
}

ushark_t*
ushark_new(int pcap_encap, const char *dfilter)
{
    ws_assert(init_done());

    ushark_t *sk = g_new0(ushark_t, 1);
    capture_file *cf = &sk->cfile;

    /*
     * Enabled and disabled protocols and heuristic dissectors as per
     * command-line options.
     */
    setup_enabled_and_disabled_protocols();

    /* Build the column format array */
    build_column_format_array(&cf->cinfo, 8 /* num_cols */, TRUE);

    /* Init epan dissector */
    cf->epan = g_epan;
    sk->edt = epan_dissect_new(cf->epan,
                    TRUE /* protocol tree - required for JSON dump */,
                    TRUE /* protocol tree visible - required for JSON dump */);

    cf->provider.wth = ushark_wtap_open(sk, wtap_pcap_encap_to_wtap_encap(pcap_encap));

    /* Init packet buffers */
    wtap_rec_init(&sk->rec);
    ws_buffer_init(&sk->buf, 1514);

    if(dfilter && *dfilter) {
        if(!compile_dfilter(dfilter, &cf->dfcode))
            ws_warning("invalid display filter will be ignored");
    }

    /* Init JSON dumper */
    sk->output_fields = output_fields_new();
    sk->json_output = g_string_sized_new(0);
    sk->jdumper = write_json_preamble_to_str(sk->json_output);

    return sk;
}

static void
finalize_jdumper(ushark_t *sk)
{
    if (sk->jdumper_finalized)
        return;

    write_json_finale(&sk->jdumper);
    sk->jdumper_finalized = TRUE;
}

void
ushark_destroy(ushark_t *sk)
{
    finalize_jdumper(sk);
    g_string_free(sk->json_output, TRUE);
    output_fields_free(sk->output_fields);

    epan_dissect_free(sk->edt);
    wtap_rec_cleanup(&sk->rec);
    ws_buffer_free(&sk->buf);

    col_cleanup(&sk->cfile.cinfo);
    wtap_close(sk->cfile.provider.wth);

    if(sk->cfile.dfcode)
        dfilter_free(sk->cfile.dfcode);

    // NOTE: sk is freed by wtap_close (wth->priv)
    //g_free(sk);
}

// from tshark
static gboolean
process_packet_single_pass(ushark_t *sk, capture_file *cf, epan_dissect_t *edt, gint64 offset,
                wtap_rec *rec, Buffer *buf, guint tap_flags)
{
    frame_data      fdata;
    gboolean        passed;

    /* Count this packet. */
    cf->count++;

    /* If we're not running a display filter and we're not printing any
     packet information, we don't need to do a dissection. This means
     that all packets can be marked as 'passed'. */
    passed = TRUE;

    frame_data_init(&fdata, cf->count, rec, offset, sk->fdata.cum_bytes);

    /* If we're going to print packet information, or we're going to
     run a read filter, or we're going to process taps, set up to
     do a dissection and do so.  (This is the one and only pass
     over the packets, so, if we'll be printing packet information
     or running taps, we'll be doing it here.) */
    if (edt) {
        /* If we're running a filter, prime the epan_dissect_t with that
         filter. */
        if (cf->dfcode)
            epan_dissect_prime_with_dfilter(edt, cf->dfcode);

        /* This is the first and only pass, so prime the epan_dissect_t
         with the hfids postdissectors want on the first pass. */
        prime_epan_dissect_with_postdissector_wanted_hfids(edt);

        frame_data_set_before_dissect(&fdata, &cf->elapsed_time,
                        &cf->provider.ref, cf->provider.prev_dis);
        if (cf->provider.ref == &fdata) {
            sk->fdata.ref_frame = fdata;
            cf->provider.ref = &sk->fdata.ref_frame;
        }

        epan_dissect_run_with_taps(edt, cf->cd_t, rec,
                        frame_tvbuff_new_buffer(&cf->provider, &fdata, buf),
                        &fdata, &cf->cinfo);

        /* Run the filter if we have it. */
        if (cf->dfcode)
            passed = dfilter_apply_edt(cf->dfcode, edt);
    }

    if (passed) {
        frame_data_set_after_dissect(&fdata, &sk->fdata.cum_bytes);

        // print_packet(cf, edt);
        write_json_proto_tree(sk->output_fields, TRUE /* print_dissections_expanded */,
                        FALSE /* print_hex */, NULL /* protocolfilter */, PF_NONE /* protocolfilter_flags */,
                        edt, &cf->cinfo, proto_node_group_children_by_json_key /* --no-duplicate-keys */, &sk->jdumper);

        /* this must be set after print_packet() [bug #8160] */
        sk->fdata.prev_dis_frame = fdata;
        cf->provider.prev_dis = &sk->fdata.prev_dis_frame;
    }

    sk->fdata.prev_cap_frame = fdata;
    cf->provider.prev_cap = &sk->fdata.prev_cap_frame;

    if (edt) {
        epan_dissect_reset(edt);
        frame_data_destroy(&fdata);
    }
    return passed;
}

// see capture_input_new_packets
void
ushark_dissect(ushark_t *sk, const u_char *pkt, const struct pcap_pkthdr *hdr)
{
    int err;
    gchar *err_info;
    gint64 data_offset;
    capture_file *cf = &sk->cfile;
    epan_dissect_t *edt = sk->edt;

    if (sk->jdumper_finalized) {
        ws_warning("dissection has stopped (json already dumped)");
        return;
    }

    // NOTE: **THIS MAKES ushark_dissect NON-REENTRANT**
    g_epan->prov = &cf->provider;

    // set pointers to packet to dissect
    sk->dissect.pkt = pkt;
    sk->dissect.hdr = hdr;

    gboolean ret = wtap_read(cf->provider.wth, &sk->rec, &sk->buf, &err, &err_info, &data_offset);
    ws_assert(ret);

    process_packet_single_pass(sk, cf, edt, data_offset, &sk->rec, &sk->buf, TL_REQUIRES_NOTHING);
}

const char *
ushark_get_json(ushark_t *sk)
{
    finalize_jdumper(sk);

    return sk->json_output->str;
}
