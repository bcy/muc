/*
   JCR - Jabber Component Runtime
   Copyright (C) 2003 Paul Curtis

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

   $Id: main.c,v 1.2 2005/12/15 07:48:11 peregrine Exp $

*/

#include "jcomp.h"
#include "lib.h"

void usage() {
    printf("Usage: mu-conference [-B] [-s] [-h] [-d LEVEL] -c FILE\n");
    printf("          -B         Put the daemon in background\n");
    printf("          -s         Show debug messages on stderr\n");
    printf("          -h         Print this help\n");
    printf("          -d LEVEL   Set the level of debug output\n");
    printf("          -c FILE    Set the config file, mandatory argument\n");
}

int main(int argc, char *argv[]) {
  extern char *optarg;
  extern int optind, opterr, optopt;
  int inBackground = 0;
  int rc, pid, c;
  int message_mask_set = 0;
  int message_stderr_set = 0;
  int fdlimit, fd;
  struct sigaction act, act_hup;
  FILE *pid_stream;
  struct stat st;
  char *config_file = NULL;
  pool p;

  /* GThread       *dthread; */ /* the packet delivery thread */
  GMainLoop     *gmain;   /* the receive packet event loop */

  jcr = (jcr_instance)calloc(1, sizeof(_jcr_instance));

  g_thread_init(NULL);
  fprintf(stderr, "%s -- %s\n%s\n\n", _JCOMP_NAME, _JCOMP_VERS, _JCOMP_COPY);

  while ((c = getopt(argc, argv, "Bshd:c:")) != EOF)
    switch (c) {
      case 'B':
        inBackground = 1;
        break;

      case 'c':
        config_file = optarg;
        break;

      case 'd':
        jcr->message_mask = j_atoi(optarg, 124);
        message_mask_set = 1;
        break;

      case 's':
        jcr->message_stderr = 1;
        message_stderr_set = 1;
        break;

      case 'h':
        usage();
        return 0;
    }

  /* The configuration file must be specified, and there is no default */
  if (config_file == NULL) {
    fprintf(stderr, "%s: Configuration file not specified, exiting.\n", JDBG);
    usage();
    return 1;
  }

  /* Parse the XML in the config file -- store it as a node */
  jcr->config = xmlnode_file(config_file);
  if (jcr->config == NULL) {
    fprintf(stderr, "%s: XML parsing failed in configuration file '%s'\n%s\n", JDBG, config_file, xmlnode_file_borked(config_file));
    return 1;
  }

  /* The spool directory --- for all xdb calls. */
  if ((xmlnode_get_type(xmlnode_get_tag(jcr->config,"spool")) == NTYPE_TAG) == 0) {
    fprintf(stderr, "%s: No spool directory specified in configuration file '%s'\n", JDBG, config_file);
    return 1;
  }
  jcr->spool_dir = strdup(xmlnode_get_data(xmlnode_get_tag(jcr->config,"spool")));
  rc = stat(jcr->spool_dir, &st);
  if (rc < 0) {
    /* Directory doesn't seem to exist, we try to create it */
    if (mkdir(jcr->spool_dir,S_IRUSR | S_IWUSR | S_IXUSR)==0){
      fprintf(stdout, "%s: <spool> '%s': directory created.\n", JDBG, jcr->spool_dir);
      rc = stat(jcr->spool_dir, &st);
    }
    else {
      fprintf(stderr, "%s: <spool> '%s': ", JDBG, jcr->spool_dir);
      perror(NULL);
      return 1;
    }
  }
  if (!(S_ISDIR(st.st_mode))) {
    fprintf(stderr, "%s: <spool> '%s' is not a directory.\n", JDBG, jcr->spool_dir);
    return 1;
  }

  /* The log directory --- for the log_* functions */
  if ((xmlnode_get_type(xmlnode_get_tag(jcr->config,"logdir")) == NTYPE_TAG) == 0) {
    fprintf(stderr, "%s: No log directory specified in configuration file '%s'\n", JDBG, config_file);
    return 1;
  }
  jcr->log_dir = strdup(xmlnode_get_data(xmlnode_get_tag(jcr->config,"logdir")));
  rc = stat(jcr->log_dir, &st);
  if (rc < 0) {
    fprintf(stderr, "%s: <logdir> '%s': ", JDBG, jcr->log_dir);
    perror(NULL);
    return 1;
  }
  if (!(S_ISDIR(st.st_mode))) {
    fprintf(stderr, "%s: <logdir> '%s' is not a directory.\n", JDBG, jcr->log_dir);
    return 1;
  }

  if (!message_mask_set)
    jcr->message_mask = j_atoi(xmlnode_get_data(xmlnode_get_tag(jcr->config,"loglevel")), 124);
  if (!message_stderr_set)
    jcr->message_stderr = (xmlnode_get_type(xmlnode_get_tag(jcr->config,"logstderr")) == NTYPE_TAG);


  if (inBackground == 1) {
    if ((pid = fork()) == -1) {
      fprintf(stderr, "%s: Could not start in background\n", JDBG);
      exit(1);
    }
    if (pid)
      exit(0);

    /* in child process .... process and terminal housekeeping */
    setsid();
    fdlimit = sysconf(_SC_OPEN_MAX);
    fd = 0;
    while (fd < fdlimit)
      close(fd++);
    open("/dev/null",O_RDWR);
    dup(0);
    dup(0);
  }
  pid = getpid();

  /* We now can initialize the resources */
  g_log_set_handler (NULL, G_LOG_LEVEL_MASK | G_LOG_FLAG_FATAL
      | G_LOG_FLAG_RECURSION, jcr_log_handler, jcr);


  log_warn(JDBG, "%s -- %s  starting.", _JCOMP_NAME, _JCOMP_VERS);

  config_file = xmlnode_get_data(xmlnode_get_tag(jcr->config,"pidfile"));
  if (config_file == NULL)
    config_file = "./jcr.pid";
  pid_stream = fopen(config_file, "w");
  if (pid_stream != NULL) {
    fprintf(pid_stream, "%d", pid);
    fclose(pid_stream);
  }
  jcr->pid_file = j_strdup(config_file);

  jcr->dqueue = g_async_queue_new();
  gmain = g_main_loop_new(NULL, FALSE);
  jcr->gmain = gmain;
  jcr->recv_buffer_size = j_atoi(xmlnode_get_data(xmlnode_get_tag(jcr->config,"recv-buffer")), 8192);
  jcr->recv_buffer = (char *)malloc(jcr->recv_buffer_size);
  jcr->in_shutdown = 0;

  sigemptyset(&act.sa_mask);
  sigaddset(&act.sa_mask, SIGTERM);
  sigaddset(&act.sa_mask, SIGINT);
  sigaddset(&act.sa_mask, SIGKILL);
  act.sa_handler = jcr_server_shutdown;
  //act.sa_restorer = NULL;
  act.sa_flags = 0;

  sigemptyset(&act_hup.sa_mask);
  sigaddset(&act_hup.sa_mask, SIGHUP);
  act_hup.sa_handler = jcr_server_hangup;
  act_hup.sa_flags = 0;

  sigaction(SIGINT, &act, NULL);
  sigaction(SIGTERM, &act, NULL);
  sigaction(SIGKILL, &act, NULL);

  sigaction(SIGHUP, &act_hup, NULL);

#ifdef LIBIDN
  /* init the stringprep caches for jid manipulation */
  jid_init_cache();
#endif

  p = pool_new();
  jcr->jcr_i = (instance)pmalloc(p, sizeof(_instance));
  jcr->jcr_i->p = p;
  jcr->jcr_i->id = pstrdup(p, xmlnode_get_data(xmlnode_get_tag(jcr->config,"host")));

  /* The component call */
  conference(jcr->jcr_i, NULL);

  log_warn(JDBG, "Main loop starting.");
  jcr_main_new_stream();
  g_main_loop_run(gmain);
  log_warn(JDBG, "Main loop exiting.");

#ifdef LIBIDN
  /* free stringprep caches */
  jid_stop_caching();
#endif

  return 0;
}
