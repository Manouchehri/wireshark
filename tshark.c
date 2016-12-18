/* tshark.c
 *
 * Text-mode variant of Wireshark, along the lines of tcpdump and snoop,
 * by Gilbert Ramirez <gram@alumni.rice.edu> and Guy Harris <guy@alum.mit.edu>.
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <config.h>

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <locale.h>
#include <limits.h>

#include <errno.h>

#ifndef _WIN32
#include <signal.h>
#endif

#ifdef HAVE_LIBCAP
# include <sys/capability.h>
#endif

#include <glib.h>

#include <epan/exceptions.h>
#include <epan/epan-int.h>
#include <epan/epan.h>

#include <wsutil/clopts_common.h>
#include <wsutil/cmdarg_err.h>
#include <wsutil/crash_info.h>
#include <wsutil/filesystem.h>
#include <wsutil/file_util.h>
#include <wsutil/privileges.h>
#include <wsutil/report_err.h>
#include <ws_version_info.h>
#include <wiretap/wtap_opttypes.h>
#include <wiretap/pcapng.h>

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
#include "ui/util.h"
#include "ui/ui_util.h"
#include "ui/decode_as_utils.h"
#include "ui/cli/tshark-tap.h"
#include "ui/cli/tap-exportobject.h"
#include "ui/tap_export_pdu.h"
#include "ui/dissect_opts.h"
#if defined(HAVE_LIBSMI)
#include "epan/oids.h"
#endif
#if defined(HAVE_GEOIP)
#include "epan/geoip_db.h"
#endif
#include "register.h"
#include "filter_files.h"
#include <epan/epan_dissect.h>
#include <epan/tap.h>
#include <epan/stat_tap_ui.h>
#include <epan/conversation_table.h>
#include <epan/srt_table.h>
#include <epan/rtd_table.h>
#include <epan/ex-opt.h>
#include <epan/exported_pdu.h>

#include "caputils/capture-pcap-util.h"

#ifdef HAVE_LIBPCAP
#include "caputils/capture_ifinfo.h"
#ifdef _WIN32
#include "caputils/capture-wpcap.h"
#include <wsutil/os_version_info.h>
#include <wsutil/unicode-utils.h>
#endif /* _WIN32 */
#include <capchild/capture_session.h>
#include <capchild/capture_sync.h>
#include <capture_info.h>
#endif /* HAVE_LIBPCAP */
#include "log.h"
#include <epan/funnel.h>

#include <wsutil/str_util.h>
#include <wsutil/utf8_entities.h>

#ifdef HAVE_EXTCAP
#include "extcap.h"
#endif

#ifdef HAVE_PLUGINS
#include <wsutil/plugins.h>
#endif


#if 1
#define tshark_debug(...) g_warning(__VA_ARGS__)
#else
#define tshark_debug(...)
#endif

static guint32 cum_bytes;
static const frame_data *ref;
static frame_data ref_frame;
static frame_data *prev_dis;
static frame_data *prev_cap;

static gboolean perform_two_pass_analysis;

/*
 * The way the packet decode is to be written.
 */
typedef enum {
  WRITE_TEXT,   /* summary or detail text */
  WRITE_XML,    /* PDML or PSML */
  WRITE_FIELDS, /* User defined list of fields */
  WRITE_JSON,    /* JSON */
  WRITE_EK      /* JSON bulk insert to Elasticsearch */
  /* Add CSV and the like here */
} output_action_e;

static output_action_e output_action;
static gboolean do_dissection;     /* TRUE if we have to dissect each packet */
static gboolean print_packet_info; /* TRUE if we're to print packet information */
static gint print_summary = -1;    /* TRUE if we're to print packet summary information */
static gboolean print_details;     /* TRUE if we're to print packet details information */
static gboolean print_hex;         /* TRUE if we're to print hex/ascci information */
static gboolean line_buffered;

static print_format_e print_format = PR_FMT_TEXT;
static print_stream_t *print_stream;

static output_fields_t* output_fields  = NULL;
static gchar **protocolfilter = NULL;

/* The line separator used between packets, changeable via the -S option */
static const char *separator = "";


static int load_cap_file(capture_file *, char *, int, gboolean, int, gint64);

static void show_print_file_io_error(int err);
static gboolean write_preamble(capture_file *cf);
static gboolean print_packet(capture_file *cf, epan_dissect_t *edt);
static gboolean write_finale(void);
static const char *cf_open_error_message(int err, gchar *err_info,
    gboolean for_writing, int file_type);

static void open_failure_message(const char *filename, int err,
    gboolean for_writing);
static void failure_message(const char *msg_format, va_list ap);
static void read_failure_message(const char *filename, int err);
static void write_failure_message(const char *filename, int err);
static void failure_message_cont(const char *msg_format, va_list ap);

capture_file cfile;

static GHashTable *output_only_tables = NULL;

struct string_elem {
  const char *sstr;   /* The short string */
  const char *lstr;   /* The long string */
};

int main(int argc, char *argv[]);


static void
tshark_log_handler (const gchar *log_domain, GLogLevelFlags log_level,
    const gchar *message, gpointer user_data)
{
  /* ignore log message, if log_level isn't interesting based
     upon the console log preferences.
     If the preferences haven't been loaded loaded yet, display the
     message anyway.

     The default console_log_level preference value is such that only
       ERROR, CRITICAL and WARNING level messages are processed;
       MESSAGE, INFO and DEBUG level messages are ignored.

     XXX: Aug 07, 2009: Prior tshark g_log code was hardwired to process only
           ERROR and CRITICAL level messages so the current code is a behavioral
           change.  The current behavior is the same as in Wireshark.
  */
  if ((log_level & G_LOG_LEVEL_MASK & prefs.console_log_level) == 0 &&
     prefs.console_log_level != 0) {
    return;
  }

  g_log_default_handler(log_domain, log_level, message, user_data);

}

static void
print_current_user(void) {
  gchar *cur_user, *cur_group;

  if (started_with_special_privs()) {
    cur_user = get_cur_username();
    cur_group = get_cur_groupname();
    fprintf(stderr, "Running as user \"%s\" and group \"%s\".",
      cur_user, cur_group);
    g_free(cur_user);
    g_free(cur_group);
    if (running_with_special_privs()) {
      fprintf(stderr, " This could be dangerous.");
    }
    fprintf(stderr, "\n");
  }
}

static void
get_tshark_compiled_version_info(GString *str)
{
  /* Capture libraries */
  get_compiled_caplibs_version(str);
}

static void
get_tshark_runtime_version_info(GString *str)
{
#ifdef HAVE_LIBPCAP
    /* Capture libraries */
    g_string_append(str, ", ");
    get_runtime_caplibs_version(str);
#endif

    /* stuff used by libwireshark */
    epan_get_runtime_version_info(str);
}

int init(int argc, char *argv[]){

  GString             *comp_info_str;
  GString             *runtime_info_str;
  char                *init_progfile_dir_error;

  #ifdef _WIN32
    WSADATA              wsaData;
  #endif  /* _WIN32 */

  char                *gpf_path, *pf_path;
  char                *gdp_path, *dp_path;
  char                *cf_path;
  int                  gpf_open_errno, gpf_read_errno;
  int                  pf_open_errno, pf_read_errno;
  int                  gdp_open_errno, gdp_read_errno;
  int                  dp_open_errno, dp_read_errno;
  int                  cf_open_errno;

  dfilter_t           *rfcode = NULL;
  dfilter_t           *dfcode = NULL;
  e_prefs             *prefs_p;
  int                  log_flags;

  tshark_debug("tshark started with %d args", argc);

  /* Set the C-language locale to the native environment. */
  setlocale(LC_ALL, "");

  cmdarg_err_init(failure_message, failure_message_cont);

#ifdef _WIN32
#if !GLIB_CHECK_VERSION(2,31,0)
  g_thread_init(NULL);
#endif
#endif /* _WIN32 */

  /*
   * Get credential information for later use, and drop privileges
   * before doing anything else.
   * Let the user know if anything happened.
   */
  init_process_policies();
  relinquish_special_privs_perm();
  print_current_user();

  /*
   * Attempt to get the pathname of the directory containing the
   * executable file.
   */
  init_progfile_dir_error = init_progfile_dir(argv[0], main);
  if (init_progfile_dir_error != NULL) {
    fprintf(stderr,
            "tshark: Can't get pathname of directory containing the tshark program: %s.\n"
            "It won't be possible to capture traffic.\n"
            "Report this to the Wireshark developers.",
            init_progfile_dir_error);
    g_free(init_progfile_dir_error);
  }

  initialize_funnel_ops();

#ifdef _WIN32
  ws_init_dll_search_path();
  /* Load wpcap if possible. Do this before collecting the run-time version information */
  load_wpcap();

  /* Warn the user if npf.sys isn't loaded. */
  if (!npf_sys_is_running() && get_windows_major_version() >= 6) {
    fprintf(stderr, "The NPF driver isn't running.  You may have trouble "
      "capturing or\nlisting interfaces.\n");
  }
#endif

  /* Get the compile-time version information string */
  comp_info_str = get_compiled_version_info(get_tshark_compiled_version_info,
                                            epan_get_compiled_version_info);

  /* Get the run-time version information string */
  runtime_info_str = get_runtime_version_info(get_tshark_runtime_version_info);

  /* Add it to the information to be reported on a crash. */
  ws_add_crash_info("TShark (Wireshark) %s\n"
         "\n"
         "%s"
         "\n"
         "%s",
      get_ws_vcs_version_info(), comp_info_str->str, runtime_info_str->str);
  g_string_free(comp_info_str, TRUE);
  g_string_free(runtime_info_str, TRUE);

  print_details = TRUE;
  print_packet_info = TRUE;
  

  /*
   * Print packet summary information is the default, unless either -V or -x
   * were specified and -P was not.  Note that this is new behavior, which
   * allows for the possibility of printing only hex/ascii output without
   * necessarily requiring that either the summary or details be printed too.
   */
  if (print_summary == -1)
    print_summary = (print_details || print_hex) ? FALSE : TRUE;

/** Send All g_log messages to our own handler **/

  log_flags =
                    G_LOG_LEVEL_ERROR|
                    G_LOG_LEVEL_CRITICAL|
                    G_LOG_LEVEL_WARNING|
                    G_LOG_LEVEL_MESSAGE|
                    G_LOG_LEVEL_INFO|
                    G_LOG_LEVEL_DEBUG|
                    G_LOG_FLAG_FATAL|G_LOG_FLAG_RECURSION;

  g_log_set_handler(NULL,
                    (GLogLevelFlags)log_flags,
                    tshark_log_handler, NULL /* user_data */);
  g_log_set_handler(LOG_DOMAIN_MAIN,
                    (GLogLevelFlags)log_flags,
                    tshark_log_handler, NULL /* user_data */);

  init_report_err(failure_message, open_failure_message, read_failure_message,
                  write_failure_message);

  timestamp_set_type(TS_RELATIVE);
  timestamp_set_precision(TS_PREC_AUTO);
  timestamp_set_seconds_type(TS_SECONDS_DEFAULT);

  wtap_init();

#ifdef HAVE_PLUGINS
  /* Register all the plugin types we have. */
  epan_register_plugin_types(); /* Types known to libwireshark */

  /* Scan for plugins.  This does *not* call their registration routines;
     that's done later. */
  scan_plugins(REPORT_LOAD_FAILURE);

  /* Register all libwiretap plugin modules. */
  register_all_wiretap_modules();
#endif

  /* Register all dissectors; we must do this before checking for the
     "-G" flag, as the "-G" flag dumps information registered by the
     dissectors, and we must do it before we read the preferences, in
     case any dissectors register preferences. */
  if (!epan_init(register_all_protocols, register_all_protocol_handoffs, NULL,
                 NULL))
    return 2;

#ifdef HAVE_PLUGINS
  register_all_plugin_tap_listeners();
#endif
#ifdef HAVE_EXTCAP
  extcap_register_preferences();
#endif
  register_all_tap_listeners();
  conversation_table_set_gui_info(init_iousers);
  hostlist_table_set_gui_info(init_hostlists);
  srt_table_iterate_tables(register_srt_tables, NULL);
  rtd_table_iterate_tables(register_rtd_tables, NULL);
  new_stat_tap_iterate_tables(register_simple_stat_tables, NULL);

  /* load the decode as entries of this profile */
  load_decode_as_entries();

  tshark_debug("tshark reading preferences");

  prefs_p = read_prefs(&gpf_open_errno, &gpf_read_errno, &gpf_path,
                     &pf_open_errno, &pf_read_errno, &pf_path);
  if (gpf_path != NULL) {
    if (gpf_open_errno != 0) {
      cmdarg_err("Can't open global preferences file \"%s\": %s.",
              pf_path, g_strerror(gpf_open_errno));
    }
    if (gpf_read_errno != 0) {
      cmdarg_err("I/O error reading global preferences file \"%s\": %s.",
              pf_path, g_strerror(gpf_read_errno));
    }
  }
  if (pf_path != NULL) {
    if (pf_open_errno != 0) {
      cmdarg_err("Can't open your preferences file \"%s\": %s.", pf_path,
              g_strerror(pf_open_errno));
    }
    if (pf_read_errno != 0) {
      cmdarg_err("I/O error reading your preferences file \"%s\": %s.",
              pf_path, g_strerror(pf_read_errno));
    }
    g_free(pf_path);
    pf_path = NULL;
  }

  read_filter_list(CFILTER_LIST, &cf_path, &cf_open_errno);
  if (cf_path != NULL) {
      cmdarg_err("Could not open your capture filter file\n\"%s\": %s.",
          cf_path, g_strerror(cf_open_errno));
      g_free(cf_path);
  }

  /* Read the disabled protocols file. */
  read_disabled_protos_list(&gdp_path, &gdp_open_errno, &gdp_read_errno,
                            &dp_path, &dp_open_errno, &dp_read_errno);
  read_disabled_heur_dissector_list(&gdp_path, &gdp_open_errno, &gdp_read_errno,
                            &dp_path, &dp_open_errno, &dp_read_errno);
  if (gdp_path != NULL) {
    if (gdp_open_errno != 0) {
      cmdarg_err("Could not open global disabled protocols file\n\"%s\": %s.",
                 gdp_path, g_strerror(gdp_open_errno));
    }
    if (gdp_read_errno != 0) {
      cmdarg_err("I/O error reading global disabled protocols file\n\"%s\": %s.",
                 gdp_path, g_strerror(gdp_read_errno));
    }
    g_free(gdp_path);
  }
  if (dp_path != NULL) {
    if (dp_open_errno != 0) {
      cmdarg_err(
        "Could not open your disabled protocols file\n\"%s\": %s.", dp_path,
        g_strerror(dp_open_errno));
    }
    if (dp_read_errno != 0) {
      cmdarg_err(
        "I/O error reading your disabled protocols file\n\"%s\": %s.", dp_path,
        g_strerror(dp_read_errno));
    }
    g_free(dp_path);
  }


  cap_file_init(&cfile);

  /* Print format defaults to this. */
  print_format = PR_FMT_TEXT;

  output_fields = output_fields_new();

  /* Notify all registered modules that have had any of their preferences
     changed either from one of the preferences file or from the command
     line that their preferences have changed. */
  prefs_apply_all();

  timestamp_set_type(global_dissect_options.time_format);

  /* Build the column format array */
  build_column_format_array(&cfile.cinfo, prefs_p->num_cols, TRUE);

  cfile.rfcode = rfcode;
  cfile.dfcode = dfcode;

  output_action = WRITE_TEXT;

  if (print_packet_info) {
    /* If we're printing as text or PostScript, we have
       to create a print stream. */
    if (output_action == WRITE_TEXT) {
      switch (print_format) {

      case PR_FMT_TEXT:
        print_stream = print_stream_text_stdio_new(stdout);
        break;

      case PR_FMT_PS:
        print_stream = print_stream_ps_stdio_new(stdout);
        break;

      default:
        g_assert_not_reached();
      }
    }
  }



  return 0;
}

void cleanup(void){

  if (cfile.frames != NULL) {
    free_frame_data_sequence(cfile.frames);
    cfile.frames = NULL;
  }

  draw_tap_listeners(TRUE);
  funnel_dump_all_text_windows();
  epan_free(cfile.epan);
  epan_cleanup();
#ifdef HAVE_EXTCAP
  extcap_cleanup();
#endif

  output_fields_free(output_fields);
  output_fields = NULL;

}

int
main(int argc, char *argv[])
{
  int                  err;
  volatile int         exit_status = 0;
#ifdef PCAP_NG_DEFAULT
  volatile int         out_file_type = WTAP_FILE_TYPE_SUBTYPE_PCAPNG;
#else
  volatile int         out_file_type = WTAP_FILE_TYPE_SUBTYPE_PCAP;
#endif
  volatile gboolean    out_file_name_res = FALSE;
  volatile int         in_file_type = WTAP_TYPE_AUTO;
  gchar               *volatile cf_name = NULL;

  init(argc, argv);


  perform_two_pass_analysis = TRUE;

while (__AFL_LOOP(1)) {
  cf_name = g_strdup(argv[1]);

  /* We have to dissect each packet if:
      we're printing information about each packet;
      we're using a read filter on the packets;
      we're using a display filter on the packets;
      we're exporting PDUs;
      we're using any taps that need dissection. */
  do_dissection = TRUE;
  tshark_debug("tshark: do_dissection = %s", do_dissection ? "TRUE" : "FALSE");

  if (cf_name) {
    tshark_debug("tshark: Opening capture file: %s", cf_name);
    /*
     * We're reading a capture file.
     */
    if (cf_open(&cfile, cf_name, in_file_type, FALSE, &err) != CF_OK) {
      epan_cleanup();
#ifdef HAVE_EXTCAP
      extcap_cleanup();
#endif
      return 2;
    }

    /* Process the packets in the file */
    tshark_debug("tshark: invoking load_cap_file() to process the packets");
    TRY {
      err = load_cap_file(&cfile, "NONE", out_file_type, out_file_name_res, 0, 0);
    }
    CATCH(OutOfMemoryError) {
      fprintf(stderr,
              "Out Of Memory.\n"
              "\n"
              "Sorry, but TShark has to terminate now.\n"
              "\n"
              "More information and workarounds can be found at\n"
              "https://wiki.wireshark.org/KnownBugs/OutOfMemory\n");
      err = ENOMEM;
    }
    ENDTRY;
    if (err != 0) {
      /* We still dump out the results of taps, etc., as we might have
         read some packets; however, we exit with an error status. */
      exit_status = 2;
    }
  }
  g_free(cf_name);
}

  cleanup();

  return exit_status;
}

guint32 packet_count = 0;


static const nstime_t *
tshark_get_frame_ts(void *data, guint32 frame_num)
{
  capture_file *cf = (capture_file *) data;

  if (ref && ref->num == frame_num)
    return &ref->abs_ts;

  if (prev_dis && prev_dis->num == frame_num)
    return &prev_dis->abs_ts;

  if (prev_cap && prev_cap->num == frame_num)
    return &prev_cap->abs_ts;

  if (cf->frames) {
     frame_data *fd = frame_data_sequence_find(cf->frames, frame_num);

     return (fd) ? &fd->abs_ts : NULL;
  }

  return NULL;
}

static epan_t *
tshark_epan_new(capture_file *cf)
{
  epan_t *epan = epan_new();

  epan->data = cf;
  epan->get_frame_ts = tshark_get_frame_ts;
  epan->get_interface_name = cap_file_get_interface_name;
  epan->get_user_comment = NULL;

  return epan;
}


static gboolean
process_packet_first_pass(capture_file *cf, epan_dissect_t *edt,
               gint64 offset, struct wtap_pkthdr *whdr,
               const guchar *pd)
{
  frame_data     fdlocal;
  guint32        framenum;
  gboolean       passed;

  /* The frame number of this packet is one more than the count of
     frames in this packet. */
  framenum = cf->count + 1;

  /* If we're not running a display filter and we're not printing any
     packet information, we don't need to do a dissection. This means
     that all packets can be marked as 'passed'. */
  passed = TRUE;

  frame_data_init(&fdlocal, framenum, whdr, offset, cum_bytes);

  /* If we're going to print packet information, or we're going to
     run a read filter, or display filter, or we're going to process taps, set up to
     do a dissection and do so. */
  if (edt) {
    if (gbl_resolv_flags.mac_name || gbl_resolv_flags.network_name ||
        gbl_resolv_flags.transport_name)
      /* Grab any resolved addresses */
      host_name_lookup_process();

    /* If we're running a read filter, prime the epan_dissect_t with that
       filter. */
    if (cf->rfcode)
      epan_dissect_prime_dfilter(edt, cf->rfcode);

    if (cf->dfcode)
      epan_dissect_prime_dfilter(edt, cf->dfcode);

    frame_data_set_before_dissect(&fdlocal, &cf->elapsed_time,
                                  &ref, prev_dis);
    if (ref == &fdlocal) {
      ref_frame = fdlocal;
      ref = &ref_frame;
    }

    epan_dissect_run(edt, cf->cd_t, whdr, frame_tvbuff_new(&fdlocal, pd), &fdlocal, NULL);

    /* Run the read filter if we have one. */
    if (cf->rfcode)
      passed = dfilter_apply_edt(cf->rfcode, edt);
  }

  if (passed) {
    frame_data_set_after_dissect(&fdlocal, &cum_bytes);
    prev_cap = prev_dis = frame_data_sequence_add(cf->frames, &fdlocal);

    /* If we're not doing dissection then there won't be any dependent frames.
     * More importantly, edt.pi.dependent_frames won't be initialized because
     * epan hasn't been initialized.
     * if we *are* doing dissection, then mark the dependent frames, but only
     * if a display filter was given and it matches this packet.
     */
    if (edt && cf->dfcode) {
      if (dfilter_apply_edt(cf->dfcode, edt)) {
        g_slist_foreach(edt->pi.dependent_frames, find_and_mark_frame_depended_upon, cf->frames);
      }
    }

    cf->count++;
  } else {
    /* if we don't add it to the frame_data_sequence, clean it up right now
     * to avoid leaks */
    frame_data_destroy(&fdlocal);
  }

  if (edt)
    epan_dissect_reset(edt);

  return passed;
}

static gboolean
process_packet_second_pass(capture_file *cf, epan_dissect_t *edt, frame_data *fdata,
               struct wtap_pkthdr *phdr, Buffer *buf,
               guint tap_flags)
{
  column_info    *cinfo;
  gboolean        passed;

  /* If we're not running a display filter and we're not printing any
     packet information, we don't need to do a dissection. This means
     that all packets can be marked as 'passed'. */
  passed = TRUE;

  /* If we're going to print packet information, or we're going to
     run a read filter, or we're going to process taps, set up to
     do a dissection and do so. */
  if (edt) {
    if (gbl_resolv_flags.mac_name || gbl_resolv_flags.network_name ||
        gbl_resolv_flags.transport_name)
      /* Grab any resolved addresses */
      host_name_lookup_process();

    /* If we're running a display filter, prime the epan_dissect_t with that
       filter. */
    if (cf->dfcode)
      epan_dissect_prime_dfilter(edt, cf->dfcode);

    col_custom_prime_edt(edt, &cf->cinfo);

    /* We only need the columns if either
         1) some tap needs the columns
       or
         2) we're printing packet info but we're *not* verbose; in verbose
            mode, we print the protocol tree, not the protocol summary.
     */
    if ((tap_flags & TL_REQUIRES_COLUMNS) || (print_packet_info && print_summary) || output_fields_has_cols(output_fields))
      cinfo = &cf->cinfo;
    else
      cinfo = NULL;

    frame_data_set_before_dissect(fdata, &cf->elapsed_time,
                                  &ref, prev_dis);
    if (ref == fdata) {
      ref_frame = *fdata;
      ref = &ref_frame;
    }

    epan_dissect_run_with_taps(edt, cf->cd_t, phdr, frame_tvbuff_new_buffer(fdata, buf), fdata, cinfo);

    /* Run the read/display filter if we have one. */
    if (cf->dfcode)
      passed = dfilter_apply_edt(cf->dfcode, edt);
  }

  if (passed) {
    frame_data_set_after_dissect(fdata, &cum_bytes);
    /* Process this packet. */
    if (print_packet_info) {
      /* We're printing packet information; print the information for
         this packet. */
      print_packet(cf, edt);

      /* The ANSI C standard does not appear to *require* that a line-buffered
         stream be flushed to the host environment whenever a newline is
         written, it just says that, on such a stream, characters "are
         intended to be transmitted to or from the host environment as a
         block when a new-line character is encountered".

         The Visual C++ 6.0 C implementation doesn't do what is intended;
         even if you set a stream to be line-buffered, it still doesn't
         flush the buffer at the end of every line.

         So, if the "-l" flag was specified, we flush the standard output
         at the end of a packet.  This will do the right thing if we're
         printing packet summary lines, and, as we print the entire protocol
         tree for a single packet without waiting for anything to happen,
         it should be as good as line-buffered mode if we're printing
         protocol trees.  (The whole reason for the "-l" flag in either
         tcpdump or TShark is to allow the output of a live capture to
         be piped to a program or script and to have that script see the
         information for the packet as soon as it's printed, rather than
         having to wait until a standard I/O buffer fills up. */
      if (line_buffered)
        fflush(stdout);

      if (ferror(stdout)) {
        show_print_file_io_error(errno);
        exit(2);
      }
    }
    prev_dis = fdata;
  }
  prev_cap = fdata;

  if (edt) {
    epan_dissect_reset(edt);
  }
  return passed || fdata->flags.dependent_of_displayed;
}

static int
load_cap_file(capture_file *cf, char *save_file, int out_file_type,
    gboolean out_file_name_res, int max_packet_count, gint64 max_byte_count)
{
  wtap_dumper *pdh = NULL;
  guint32      framenum;
  int          err = 0;
  gchar       *err_info = NULL;
  gint64       data_offset;
  gboolean     filtering_tap_listeners;
  guint        tap_flags;
  GArray                      *shb_hdrs = NULL;
  wtapng_iface_descriptions_t *idb_inf = NULL;
  GArray                      *nrb_hdrs = NULL;
  struct wtap_pkthdr phdr;
  Buffer       buf;
  epan_dissect_t *edt = NULL;

  wtap_phdr_init(&phdr);

  idb_inf = wtap_file_get_idb_info(cf->wth);

  if (print_packet_info) {
    if (!write_preamble(cf)) {
      err = errno;
      show_print_file_io_error(err);
      goto out;
    }
  }
  g_free(idb_inf);
  idb_inf = NULL;

  /* Do we have any tap listeners with filters? */
  filtering_tap_listeners = have_filtering_tap_listeners();

  /* Get the union of the flags for all tap listeners. */
  tap_flags = union_of_tap_listener_flags();

  if (perform_two_pass_analysis) {
    frame_data *fdata;

    tshark_debug("tshark: perform_two_pass_analysis, do_dissection=%s", do_dissection ? "TRUE" : "FALSE");

    /* Allocate a frame_data_sequence for all the frames. */
    cf->frames = new_frame_data_sequence();

    if (do_dissection) {
       gboolean create_proto_tree = FALSE;

      /* If we're going to be applying a filter, we'll need to
         create a protocol tree against which to apply the filter. */
      if (cf->rfcode || cf->dfcode)
        create_proto_tree = TRUE;

      tshark_debug("tshark: create_proto_tree = %s", create_proto_tree ? "TRUE" : "FALSE");

      /* We're not going to display the protocol tree on this pass,
         so it's not going to be "visible". */
      edt = epan_dissect_new(cf->epan, create_proto_tree, FALSE);
    }

    tshark_debug("tshark: reading records for first pass");
    while (wtap_read(cf->wth, &err, &err_info, &data_offset)) {
      if (process_packet_first_pass(cf, edt, data_offset, wtap_phdr(cf->wth),
                         wtap_buf_ptr(cf->wth))) {
        /* Stop reading if we have the maximum number of packets;
         * When the -c option has not been used, max_packet_count
         * starts at 0, which practically means, never stop reading.
         * (unless we roll over max_packet_count ?)
         */
        if ( (--max_packet_count == 0) || (max_byte_count != 0 && data_offset >= max_byte_count)) {
          tshark_debug("tshark: max_packet_count (%d) or max_byte_count (%" G_GINT64_MODIFIER "d/%" G_GINT64_MODIFIER "d) reached",
                        max_packet_count, data_offset, max_byte_count);
          err = 0; /* This is not an error */
          break;
        }
      }
    }

    if (edt) {
      epan_dissect_free(edt);
      edt = NULL;
    }

    /* Close the sequential I/O side, to free up memory it requires. */
    wtap_sequential_close(cf->wth);

    /* Allow the protocol dissectors to free up memory that they
     * don't need after the sequential run-through of the packets. */
    postseq_cleanup_all_protocols();

    prev_dis = NULL;
    prev_cap = NULL;
    ws_buffer_init(&buf, 1500);

    tshark_debug("tshark: done with first pass");

    if (do_dissection) {
      gboolean create_proto_tree;

      if (cf->dfcode || print_details || filtering_tap_listeners ||
         (tap_flags & TL_REQUIRES_PROTO_TREE) || have_custom_cols(&cf->cinfo))
           create_proto_tree = TRUE;
      else
           create_proto_tree = FALSE;

      tshark_debug("tshark: create_proto_tree = %s", create_proto_tree ? "TRUE" : "FALSE");

      /* The protocol tree will be "visible", i.e., printed, only if we're
         printing packet details, which is true if we're printing stuff
         ("print_packet_info" is true) and we're in verbose mode
         ("packet_details" is true). */
      edt = epan_dissect_new(cf->epan, create_proto_tree, print_packet_info && print_details);
    }

    for (framenum = 1; err == 0 && framenum <= cf->count; framenum++) {
      fdata = frame_data_sequence_find(cf->frames, framenum);
      if (wtap_seek_read(cf->wth, fdata->file_off, &phdr, &buf, &err,
                         &err_info)) {
        tshark_debug("tshark: invoking process_packet_second_pass() for frame #%d", framenum);
        if (process_packet_second_pass(cf, edt, fdata, &phdr, &buf,
                                       tap_flags)) {
        }
      }
    }

    if (edt) {
      epan_dissect_free(edt);
      edt = NULL;
    }

    ws_buffer_free(&buf);

    tshark_debug("tshark: done with second pass");
  }

  wtap_phdr_cleanup(&phdr);

  if (err != 0) {
    tshark_debug("tshark: something failed along the line (%d)", err);
    /*
     * Print a message noting that the read failed somewhere along the line.
     *
     * If we're printing packet data, and the standard output and error are
     * going to the same place, flush the standard output, so everything
     * buffered up is written, and then print a newline to the standard error
     * before printing the error message, to separate it from the packet
     * data.  (Alas, that only works on UN*X; st_dev is meaningless, and
     * the _fstat() documentation at Microsoft doesn't indicate whether
     * st_ino is even supported.)
     */
#ifndef _WIN32
    if (print_packet_info) {
      ws_statb64 stat_stdout, stat_stderr;

      if (ws_fstat64(1, &stat_stdout) == 0 && ws_fstat64(2, &stat_stderr) == 0) {
        if (stat_stdout.st_dev == stat_stderr.st_dev &&
            stat_stdout.st_ino == stat_stderr.st_ino) {
          fflush(stdout);
          fprintf(stderr, "\n");
        }
      }
    }
#endif
    switch (err) {

    case WTAP_ERR_UNSUPPORTED:
      cmdarg_err("The file \"%s\" contains record data that TShark doesn't support.\n(%s)",
                 cf->filename,
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      break;

    case WTAP_ERR_SHORT_READ:
      cmdarg_err("The file \"%s\" appears to have been cut short in the middle of a packet.",
                 cf->filename);
      break;

    case WTAP_ERR_BAD_FILE:
      cmdarg_err("The file \"%s\" appears to be damaged or corrupt.\n(%s)",
                 cf->filename,
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      break;

    case WTAP_ERR_DECOMPRESS:
      cmdarg_err("The compressed file \"%s\" appears to be damaged or corrupt.\n"
                 "(%s)", cf->filename,
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      break;

    default:
      cmdarg_err("An error occurred while reading the file \"%s\": %s.",
                 cf->filename, wtap_strerror(err));
      break;
    }
  } else {
    if (save_file != NULL) {
      if (pdh && out_file_name_res) {
        if (!wtap_dump_set_addrinfo_list(pdh, get_addrinfo_list())) {
          cmdarg_err("The file format \"%s\" doesn't support name resolution information.",
                     wtap_file_type_subtype_short_string(out_file_type));
        }
      }
      /* Now close the capture file. */

    } else {
      if (print_packet_info) {
        if (!write_finale()) {
          err = errno;
          show_print_file_io_error(err);
        }
      }
    }
  }

out:
  wtap_close(cf->wth);
  cf->wth = NULL;

  wtap_block_array_free(shb_hdrs);
  wtap_block_array_free(nrb_hdrs);

  return err;
}



static gboolean
write_preamble(capture_file *cf)
{
  switch (output_action) {

  case WRITE_TEXT:
    return print_preamble(print_stream, cf->filename, get_ws_vcs_version_info());

  case WRITE_XML:
    if (print_details)
      write_pdml_preamble(stdout, cf->filename);
    else
      write_psml_preamble(&cf->cinfo, stdout);
    return !ferror(stdout);

  case WRITE_FIELDS:
    write_fields_preamble(output_fields, stdout);
    return !ferror(stdout);

  case WRITE_JSON:
    write_json_preamble(stdout);
    return !ferror(stdout);

  case WRITE_EK:
    return !ferror(stdout);

  default:
    g_assert_not_reached();
    return FALSE;
  }
}

static char *
get_line_buf(size_t len)
{
  static char   *line_bufp    = NULL;
  static size_t  line_buf_len = 256;
  size_t         new_line_buf_len;

  for (new_line_buf_len = line_buf_len; len > new_line_buf_len;
       new_line_buf_len *= 2)
    ;
  if (line_bufp == NULL) {
    line_buf_len = new_line_buf_len;
    line_bufp = (char *)g_malloc(line_buf_len + 1);
  } else {
    if (new_line_buf_len > line_buf_len) {
      line_buf_len = new_line_buf_len;
      line_bufp = (char *)g_realloc(line_bufp, line_buf_len + 1);
    }
  }
  return line_bufp;
}

static inline void
put_string(char *dest, const char *str, size_t str_len)
{
  memcpy(dest, str, str_len);
  dest[str_len] = '\0';
}

static inline void
put_spaces_string(char *dest, const char *str, size_t str_len, size_t str_with_spaces)
{
  size_t i;

  for (i = str_len; i < str_with_spaces; i++)
    *dest++ = ' ';

  put_string(dest, str, str_len);
}

static inline void
put_string_spaces(char *dest, const char *str, size_t str_len, size_t str_with_spaces)
{
  size_t i;

  memcpy(dest, str, str_len);
  for (i = str_len; i < str_with_spaces; i++)
    dest[i] = ' ';

  dest[str_with_spaces] = '\0';
}

static gboolean
print_columns(capture_file *cf)
{
  char   *line_bufp;
  int     i;
  size_t  buf_offset;
  size_t  column_len;
  size_t  col_len;
  col_item_t* col_item;

  line_bufp = get_line_buf(256);
  buf_offset = 0;
  *line_bufp = '\0';
  for (i = 0; i < cf->cinfo.num_cols; i++) {
    col_item = &cf->cinfo.columns[i];
    /* Skip columns not marked as visible. */
    if (!get_column_visible(i))
      continue;
    switch (col_item->col_fmt) {
    case COL_NUMBER:
      column_len = col_len = strlen(col_item->col_data);
      if (column_len < 5)
        column_len = 5;
      line_bufp = get_line_buf(buf_offset + column_len);
      put_spaces_string(line_bufp + buf_offset, col_item->col_data, col_len, column_len);
      break;

    case COL_CLS_TIME:
    case COL_REL_TIME:
    case COL_ABS_TIME:
    case COL_ABS_YMD_TIME:  /* XXX - wider */
    case COL_ABS_YDOY_TIME: /* XXX - wider */
    case COL_UTC_TIME:
    case COL_UTC_YMD_TIME:  /* XXX - wider */
    case COL_UTC_YDOY_TIME: /* XXX - wider */
      column_len = col_len = strlen(col_item->col_data);
      if (column_len < 10)
        column_len = 10;
      line_bufp = get_line_buf(buf_offset + column_len);
      put_spaces_string(line_bufp + buf_offset, col_item->col_data, col_len, column_len);
      break;

    case COL_DEF_SRC:
    case COL_RES_SRC:
    case COL_UNRES_SRC:
    case COL_DEF_DL_SRC:
    case COL_RES_DL_SRC:
    case COL_UNRES_DL_SRC:
    case COL_DEF_NET_SRC:
    case COL_RES_NET_SRC:
    case COL_UNRES_NET_SRC:
      column_len = col_len = strlen(col_item->col_data);
      if (column_len < 12)
        column_len = 12;
      line_bufp = get_line_buf(buf_offset + column_len);
      put_spaces_string(line_bufp + buf_offset, col_item->col_data, col_len, column_len);
      break;

    case COL_DEF_DST:
    case COL_RES_DST:
    case COL_UNRES_DST:
    case COL_DEF_DL_DST:
    case COL_RES_DL_DST:
    case COL_UNRES_DL_DST:
    case COL_DEF_NET_DST:
    case COL_RES_NET_DST:
    case COL_UNRES_NET_DST:
      column_len = col_len = strlen(col_item->col_data);
      if (column_len < 12)
        column_len = 12;
      line_bufp = get_line_buf(buf_offset + column_len);
      put_string_spaces(line_bufp + buf_offset, col_item->col_data, col_len, column_len);
      break;

    default:
      column_len = strlen(col_item->col_data);
      line_bufp = get_line_buf(buf_offset + column_len);
      put_string(line_bufp + buf_offset, col_item->col_data, column_len);
      break;
    }
    buf_offset += column_len;
    if (i != cf->cinfo.num_cols - 1) {
      /*
       * This isn't the last column, so we need to print a
       * separator between this column and the next.
       *
       * If we printed a network source and are printing a
       * network destination of the same type next, separate
       * them with a UTF-8 right arrow; if we printed a network
       * destination and are printing a network source of the same
       * type next, separate them with a UTF-8 left arrow;
       * otherwise separate them with a space.
       *
       * We add enough space to the buffer for " \xe2\x86\x90 "
       * or " \xe2\x86\x92 ", even if we're only adding " ".
       */
      line_bufp = get_line_buf(buf_offset + 5);
      switch (col_item->col_fmt) {

      case COL_DEF_SRC:
      case COL_RES_SRC:
      case COL_UNRES_SRC:
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_DST:
        case COL_RES_DST:
        case COL_UNRES_DST:
          put_string(line_bufp + buf_offset, " " UTF8_RIGHTWARDS_ARROW " ", 5);
          buf_offset += 5;
          break;

        default:
          put_string(line_bufp + buf_offset, " ", 1);
          buf_offset += 1;
          break;
        }
        break;

      case COL_DEF_DL_SRC:
      case COL_RES_DL_SRC:
      case COL_UNRES_DL_SRC:
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_DL_DST:
        case COL_RES_DL_DST:
        case COL_UNRES_DL_DST:
          put_string(line_bufp + buf_offset, " " UTF8_RIGHTWARDS_ARROW " ", 5);
          buf_offset += 5;
          break;

        default:
          put_string(line_bufp + buf_offset, " ", 1);
          buf_offset += 1;
          break;
        }
        break;

      case COL_DEF_NET_SRC:
      case COL_RES_NET_SRC:
      case COL_UNRES_NET_SRC:
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_NET_DST:
        case COL_RES_NET_DST:
        case COL_UNRES_NET_DST:
          put_string(line_bufp + buf_offset, " " UTF8_RIGHTWARDS_ARROW " ", 5);
          buf_offset += 5;
          break;

        default:
          put_string(line_bufp + buf_offset, " ", 1);
          buf_offset += 1;
          break;
        }
        break;

      case COL_DEF_DST:
      case COL_RES_DST:
      case COL_UNRES_DST:
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_SRC:
        case COL_RES_SRC:
        case COL_UNRES_SRC:
          put_string(line_bufp + buf_offset, " " UTF8_LEFTWARDS_ARROW " ", 5);
          buf_offset += 5;
          break;

        default:
          put_string(line_bufp + buf_offset, " ", 1);
          buf_offset += 1;
          break;
        }
        break;

      case COL_DEF_DL_DST:
      case COL_RES_DL_DST:
      case COL_UNRES_DL_DST:
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_DL_SRC:
        case COL_RES_DL_SRC:
        case COL_UNRES_DL_SRC:
          put_string(line_bufp + buf_offset, " " UTF8_LEFTWARDS_ARROW " ", 5);
          buf_offset += 5;
          break;

        default:
          put_string(line_bufp + buf_offset, " ", 1);
          buf_offset += 1;
          break;
        }
        break;

      case COL_DEF_NET_DST:
      case COL_RES_NET_DST:
      case COL_UNRES_NET_DST:
        switch (cf->cinfo.columns[i+1].col_fmt) {

        case COL_DEF_NET_SRC:
        case COL_RES_NET_SRC:
        case COL_UNRES_NET_SRC:
          put_string(line_bufp + buf_offset, " " UTF8_LEFTWARDS_ARROW " ", 5);
          buf_offset += 5;
          break;

        default:
          put_string(line_bufp + buf_offset, " ", 1);
          buf_offset += 1;
          break;
        }
        break;

      default:
        put_string(line_bufp + buf_offset, " ", 1);
        buf_offset += 1;
        break;
      }
    }
  }
  return print_line(print_stream, 0, line_bufp);
}

static gboolean
print_packet(capture_file *cf, epan_dissect_t *edt)
{
  print_args_t print_args;

  if (print_summary || output_fields_has_cols(output_fields)) {
    /* Just fill in the columns. */
    epan_dissect_fill_in_columns(edt, FALSE, TRUE);

    if (print_summary) {
      /* Now print them. */
      switch (output_action) {

      case WRITE_TEXT:
        if (!print_columns(cf))
          return FALSE;
        break;

      case WRITE_XML:
        write_psml_columns(edt, stdout);
        return !ferror(stdout);
      case WRITE_FIELDS: /*No non-verbose "fields" format */
      case WRITE_JSON:
      case WRITE_EK:
        g_assert_not_reached();
        break;
      }
    }
  }
  if (print_details) {
    /* Print the information in the protocol tree. */
    switch (output_action) {

    case WRITE_TEXT:
      /* Only initialize the fields that are actually used in proto_tree_print.
       * This is particularly important for .range, as that's heap memory which
       * we would otherwise have to g_free().
      print_args.to_file = TRUE;
      print_args.format = print_format;
      print_args.print_summary = print_summary;
      print_args.print_formfeed = FALSE;
      packet_range_init(&print_args.range, &cfile);
      */
      print_args.print_hex = print_hex;
      print_args.print_dissections = print_details ? print_dissections_expanded : print_dissections_none;

      if (!proto_tree_print(&print_args, edt, output_only_tables, print_stream))
        return FALSE;
      if (!print_hex) {
        if (!print_line(print_stream, 0, separator))
          return FALSE;
      }
      break;

    case WRITE_XML:
      write_pdml_proto_tree(output_fields, protocolfilter, edt, stdout);
      printf("\n");
      return !ferror(stdout);
    case WRITE_FIELDS:
      write_fields_proto_tree(output_fields, edt, &cf->cinfo, stdout);
      printf("\n");
      return !ferror(stdout);
    case WRITE_JSON:
      print_args.print_hex = print_hex;
      write_json_proto_tree(output_fields, &print_args, protocolfilter, edt, stdout);
      printf("\n");
      return !ferror(stdout);
    case WRITE_EK:
      print_args.print_hex = print_hex;
      write_ek_proto_tree(output_fields, &print_args, protocolfilter, edt, stdout);
      printf("\n");
      return !ferror(stdout);
    }
  }
  if (print_hex) {
    if (print_summary || print_details) {
      if (!print_line(print_stream, 0, ""))
        return FALSE;
    }
    if (!print_hex_data(print_stream, edt))
      return FALSE;
    if (!print_line(print_stream, 0, separator))
      return FALSE;
  }
  return TRUE;
}

static gboolean
write_finale(void)
{
  switch (output_action) {

  case WRITE_TEXT:
    return print_finale(print_stream);

  case WRITE_XML:
    if (print_details)
      write_pdml_finale(stdout);
    else
      write_psml_finale(stdout);
    return !ferror(stdout);

  case WRITE_FIELDS:
    write_fields_finale(output_fields, stdout);
    return !ferror(stdout);

  case WRITE_JSON:
    write_json_finale(stdout);
    return !ferror(stdout);

  case WRITE_EK:
    return !ferror(stdout);

  default:
    g_assert_not_reached();
    return FALSE;
  }
}

cf_status_t
cf_open(capture_file *cf, const char *fname, unsigned int type, gboolean is_tempfile, int *err)
{
  wtap  *wth;
  gchar *err_info;
  char   err_msg[2048+1];

  wth = wtap_open_offline(fname, type, err, &err_info, perform_two_pass_analysis);
  if (wth == NULL)
    goto fail;

  /* The open succeeded.  Fill in the information for this file. */

  /* Create new epan session for dissection. */
  epan_free(cf->epan);
  cf->epan = tshark_epan_new(cf);

  cf->wth = wth;
  cf->f_datalen = 0; /* not used, but set it anyway */

  /* Set the file name because we need it to set the follow stream filter.
     XXX - is that still true?  We need it for other reasons, though,
     in any case. */
  cf->filename = g_strdup(fname);

  /* Indicate whether it's a permanent or temporary file. */
  cf->is_tempfile = is_tempfile;

  /* No user changes yet. */
  cf->unsaved_changes = FALSE;

  cf->cd_t      = wtap_file_type_subtype(cf->wth);
  cf->open_type = type;
  cf->count     = 0;
  cf->drops_known = FALSE;
  cf->drops     = 0;
  cf->snap      = wtap_snapshot_length(cf->wth);
  if (cf->snap == 0) {
    /* Snapshot length not known. */
    cf->has_snap = FALSE;
    cf->snap = WTAP_MAX_PACKET_SIZE;
  } else
    cf->has_snap = TRUE;
  nstime_set_zero(&cf->elapsed_time);
  ref = NULL;
  prev_dis = NULL;
  prev_cap = NULL;

  cf->state = FILE_READ_IN_PROGRESS;

  wtap_set_cb_new_ipv4(cf->wth, add_ipv4_name);
  wtap_set_cb_new_ipv6(cf->wth, (wtap_new_ipv6_callback_t) add_ipv6_name);

  return CF_OK;

fail:
  g_snprintf(err_msg, sizeof err_msg,
             cf_open_error_message(*err, err_info, FALSE, cf->cd_t), fname);
  cmdarg_err("%s", err_msg);
  return CF_ERROR;
}

static void
show_print_file_io_error(int err)
{
  switch (err) {

  case ENOSPC:
    cmdarg_err("Not all the packets could be printed because there is "
"no space left on the file system.");
    break;

#ifdef EDQUOT
  case EDQUOT:
    cmdarg_err("Not all the packets could be printed because you are "
"too close to, or over your disk quota.");
  break;
#endif

  default:
    cmdarg_err("An error occurred while printing packets: %s.",
      g_strerror(err));
    break;
  }
}

static const char *
cf_open_error_message(int err, gchar *err_info, gboolean for_writing,
                      int file_type)
{
  const char *errmsg;
  static char errmsg_errno[1024+1];

  if (err < 0) {
    /* Wiretap error. */
    switch (err) {

    case WTAP_ERR_NOT_REGULAR_FILE:
      errmsg = "The file \"%s\" is a \"special file\" or socket or other non-regular file.";
      break;

    case WTAP_ERR_RANDOM_OPEN_PIPE:
      /* Seen only when opening a capture file for reading. */
      errmsg = "The file \"%s\" is a pipe or FIFO; TShark can't read pipe or FIFO files in two-pass mode.";
      break;

    case WTAP_ERR_FILE_UNKNOWN_FORMAT:
      /* Seen only when opening a capture file for reading. */
      errmsg = "The file \"%s\" isn't a capture file in a format TShark understands.";
      break;

    case WTAP_ERR_UNSUPPORTED:
      /* Seen only when opening a capture file for reading. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The file \"%%s\" contains record data that TShark doesn't support.\n"
                 "(%s)",
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      errmsg = errmsg_errno;
      break;

    case WTAP_ERR_CANT_WRITE_TO_PIPE:
      /* Seen only when opening a capture file for writing. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The file \"%%s\" is a pipe, and \"%s\" capture files can't be "
                 "written to a pipe.", wtap_file_type_subtype_short_string(file_type));
      errmsg = errmsg_errno;
      break;

    case WTAP_ERR_UNWRITABLE_FILE_TYPE:
      /* Seen only when opening a capture file for writing. */
      errmsg = "TShark doesn't support writing capture files in that format.";
      break;

    case WTAP_ERR_UNWRITABLE_ENCAP:
      /* Seen only when opening a capture file for writing. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "TShark can't save this capture as a \"%s\" file.",
                 wtap_file_type_subtype_short_string(file_type));
      errmsg = errmsg_errno;
      break;

    case WTAP_ERR_ENCAP_PER_PACKET_UNSUPPORTED:
      if (for_writing) {
        g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                   "TShark can't save this capture as a \"%s\" file.",
                   wtap_file_type_subtype_short_string(file_type));
        errmsg = errmsg_errno;
      } else
        errmsg = "The file \"%s\" is a capture for a network type that TShark doesn't support.";
      break;

    case WTAP_ERR_BAD_FILE:
      /* Seen only when opening a capture file for reading. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The file \"%%s\" appears to be damaged or corrupt.\n"
                 "(%s)",
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      errmsg = errmsg_errno;
      break;

    case WTAP_ERR_CANT_OPEN:
      if (for_writing)
        errmsg = "The file \"%s\" could not be created for some unknown reason.";
      else
        errmsg = "The file \"%s\" could not be opened for some unknown reason.";
      break;

    case WTAP_ERR_SHORT_READ:
      errmsg = "The file \"%s\" appears to have been cut short"
               " in the middle of a packet or other data.";
      break;

    case WTAP_ERR_SHORT_WRITE:
      errmsg = "A full header couldn't be written to the file \"%s\".";
      break;

    case WTAP_ERR_COMPRESSION_NOT_SUPPORTED:
      errmsg = "This file type cannot be written as a compressed file.";
      break;

    case WTAP_ERR_DECOMPRESS:
      /* Seen only when opening a capture file for reading. */
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The compressed file \"%%s\" appears to be damaged or corrupt.\n"
                 "(%s)",
                 err_info != NULL ? err_info : "no information supplied");
      g_free(err_info);
      errmsg = errmsg_errno;
      break;

    default:
      g_snprintf(errmsg_errno, sizeof(errmsg_errno),
                 "The file \"%%s\" could not be %s: %s.",
                 for_writing ? "created" : "opened",
                 wtap_strerror(err));
      errmsg = errmsg_errno;
      break;
    }
  } else
    errmsg = file_open_error_message(err, for_writing);
  return errmsg;
}

/*
 * Open/create errors are reported with an console message in TShark.
 */
static void
open_failure_message(const char *filename, int err, gboolean for_writing)
{
  fprintf(stderr, "tshark: ");
  fprintf(stderr, file_open_error_message(err, for_writing), filename);
  fprintf(stderr, "\n");
}

/*
 * General errors are reported with an console message in TShark.
 */
static void
failure_message(const char *msg_format, va_list ap)
{
  fprintf(stderr, "tshark: ");
  vfprintf(stderr, msg_format, ap);
  fprintf(stderr, "\n");
}

/*
 * Read errors are reported with an console message in TShark.
 */
static void
read_failure_message(const char *filename, int err)
{
  cmdarg_err("An error occurred while reading from the file \"%s\": %s.",
          filename, g_strerror(err));
}

/*
 * Write errors are reported with an console message in TShark.
 */
static void
write_failure_message(const char *filename, int err)
{
  cmdarg_err("An error occurred while writing to the file \"%s\": %s.",
          filename, g_strerror(err));
}

/*
 * Report additional information for an error in command-line arguments.
 */
static void
failure_message_cont(const char *msg_format, va_list ap)
{
  vfprintf(stderr, msg_format, ap);
  fprintf(stderr, "\n");
}

/*
 * Editor modelines  -  https://www.wireshark.org/tools/modelines.html
 *
 * Local variables:
 * c-basic-offset: 2
 * tab-width: 8
 * indent-tabs-mode: nil
 * End:
 *
 * vi: set shiftwidth=2 tabstop=8 expandtab:
 * :indentSize=2:tabSize=8:noTabs=true:
 */
