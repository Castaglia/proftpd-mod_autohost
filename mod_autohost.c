/*
 * ProFTPD: mod_autohost -- a module for mass virtual hosting
 * Copyright (c) 2004-2021 TJ Saunders
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307, USA.
 *
 * As a special exemption, TJ Saunders and other respective copyright holders
 * give permission to link this program with OpenSSL, and distribute the
 * resulting executable, without including the source code for OpenSSL in the
 * source distribution.
 *
 * This is mod_autohost, contrib software for proftpd 1.3.x and above.
 * For more information contact TJ Saunders <tj@castaglia.org>.
 */

#include "conf.h"
#include "privs.h"

#define MOD_AUTOHOST_VERSION		"mod_autohost/0.7"

#if PROFTPD_VERSION_NUMBER < 0x0001030604
# error "ProFTPD 1.3.6 or later required"
#endif

module autohost_module;

static const char *autohost_config = NULL;
static int autohost_engine = FALSE;
static int autohost_logfd = -1;
static pool *autohost_pool = NULL;
static xaset_t *autohost_server_list = NULL;

static const char *trace_channel = "autohost";

static char *autohost_get_config(conn_t *conn, const char *server_name) {
  char *ipstr, *portstr, *path = (char *) autohost_config;
  int family;

  family = pr_netaddr_get_family(conn->local_addr);
  ipstr = (char *) pr_netaddr_get_ipstr(conn->local_addr);

  if (family == AF_INET) {
    char *oct1str, *oct2str, *oct3str, *oct4str;
    char *start, *end;

    start = ipstr;
    end = strchr(start, '.');
    *end = '\0';
    oct1str = pstrdup(autohost_pool, start);

    start = end + 1;
    *end = '.';
    end = strchr(start, '.');
    *end = '\0';
    oct2str = pstrdup(autohost_pool, start);

    start = end + 1;
    *end = '.';
    end = strchr(start, '.');
    *end = '\0';
    oct3str = pstrdup(autohost_pool, start);

    start = end + 1;
    *end = '.';
    oct4str = pstrdup(autohost_pool, start);

    if (strstr(path, "%1") != NULL) {
      path = (char *) sreplace(autohost_pool, path, "%1", oct1str, NULL);
    }

    if (strstr(path, "%2") != NULL) {
      path = (char *) sreplace(autohost_pool, path, "%2", oct2str, NULL);
    }

    if (strstr(path, "%3") != NULL) {
      path = (char *) sreplace(autohost_pool, path, "%3", oct3str, NULL);
    }

    if (strstr(path, "%4") != NULL) {
      path = (char *) sreplace(autohost_pool, path, "%4", oct4str, NULL);
    }
  }

  portstr = pcalloc(autohost_pool, 10);
  snprintf(portstr, 10, "%u", conn->local_port);

  if (strstr(path, "%0") != NULL) {
    path = (char *) sreplace(autohost_pool, path, "%0", ipstr, NULL);
  }

  if (server_name != NULL) {
    /* Note: How to handle the case-insensitive name of SNI/HOST, and the
     * case-sensitive nature of paths.  Should we always downcase the entire
     * server name, for purposes of config file lookup?
     */
    if (strstr(path, "%n") != NULL) {
      path = (char *) sreplace(autohost_pool, path, "%n", server_name, NULL);
    }
  }

  if (strstr(path, "%p") != NULL) {
    path = (char *) sreplace(autohost_pool, path, "%p", portstr, NULL);
  }

  return path;
}

/* Largely borrowed/copied from src/bindings.c. */
static unsigned int process_serveralias(server_rec *s, pr_ipbind_t *ipbind) {
  unsigned namebind_count = 0;
  config_rec *c;

  /* If there is no ipbind already for this server, we cannot associate
   * any ServerAlias-based namebinds to it.
   *
   * Keep in mind that there may be multiple ipbinds pointed at this server:
   *
   *  <VirtualHost 1.2.3.4 5.6.7.8>
   *    ServerAlias alias
   *  </VirtualHost>
   */

  if (pr_ipbind_get_server(s->addr, s->ServerPort) == NULL) {
    return 0;
  }

  c = find_config(s->conf, CONF_PARAM, "ServerAlias", FALSE);
  while (c != NULL) {
    int res;

#if PROFTPD_VERSION_NUMBER < 0x0001030707
    res = pr_namebind_create(s, c->argv[0], s->addr, s->ServerPort);
#else
    res = pr_namebind_create(s, c->argv[0], ipbind, s->addr, s->ServerPort);
#endif /* ProFTPD 1.3.7b and later */
    if (res == 0) {
      namebind_count++;

      res = pr_namebind_open(c->argv[0], s->addr, s->ServerPort);
      if (res < 0) {
        pr_trace_msg(trace_channel, 2,
          "notice: unable to open namebind '%s': %s", (char *) c->argv[0],
          strerror(errno));
      }

    } else {
      if (errno != ENOENT) {
        pr_trace_msg(trace_channel, 3,
          "unable to create namebind for '%s' to %s#%u: %s",
          (char *) c->argv[0], pr_netaddr_get_ipstr(s->addr), s->ServerPort,
          strerror(errno));
      }
    }

    c = find_config_next(c, c->next, CONF_PARAM, "ServerAlias", FALSE);
  }

  return namebind_count;
}

static int autohost_parse_config(conn_t *conn, const char *path) {
  server_rec *s;
  pr_ipbind_t *ipbind;

  /* We use session.pool here, rather than autohost_pool, because
   * we'll be destroying autohost_pool once the server_rec has
   * been created and bound.
   */
  pr_parser_prepare(session.pool, &autohost_server_list);
  pr_parser_server_ctxt_open(pr_netaddr_get_ipstr(conn->local_addr));

  /* XXX: some things, like Port, <VirtualHost>, etc in the autohost.conf
   * file will be ignored.
   */

  if (pr_parser_parse_file(session.pool, path, NULL, 0) < 0) {
    return -1;
  }

  pr_parser_server_ctxt_close();
  pr_parser_cleanup();

  if (fixup_servers(autohost_server_list) < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(autohost_logfd, MOD_AUTOHOST_VERSION,
      "error fixing up autohost config '%s': %s", path, strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  s = (server_rec *) autohost_server_list->xas_list;
  s->ServerPort = conn->local_port;

  ipbind = pr_ipbind_find(conn->local_addr, conn->local_port, TRUE);

  /* Now that we have a valid server_rec, we need to bind it to
   * the address to which the client connected.  And yes, we _do_ want
   * to do this regardless of whether `ipbind` is NULL or not.
   */
  process_serveralias(s, ipbind);

  if (ipbind != NULL) {
    /* If we already have a binding in place, we need to replace the
     * server_rec to which that binding points with our new server_rec.
     */
    ipbind->ib_server = s;

    return 0;
  }

  if (pr_ipbind_create(s, conn->local_addr, conn->local_port) < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(autohost_logfd, MOD_AUTOHOST_VERSION,
      "error creating binding: %s", strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  if (pr_ipbind_open(conn->local_addr, conn->local_port, main_server->listen,
      TRUE, TRUE, FALSE) < 0) {
    int xerrno = errno;

    (void) pr_log_writefile(autohost_logfd, MOD_AUTOHOST_VERSION,
      "error opening binding for %s#%d: %s",
      pr_netaddr_get_ipstr(conn->local_addr), conn->local_port,
      strerror(xerrno));

    errno = xerrno;
    return -1;
  }

  return 0;
}

/* Configuration handlers
 */

/* usage: AutoHostConfig path */
MODRET set_autohostconfig(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (pr_fs_valid_path(cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", cmd->argv[1],
      "' is not a valid path", NULL));
  }

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: AutoHostEngine on|off */
MODRET set_autohostengine(cmd_rec *cmd) {
  int engine;
  config_rec *c;

  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  engine = get_boolean(cmd, 1);
  if (engine == -1) {
    CONF_ERROR(cmd, "expected Boolean parameter");
  }

  c = add_config_param(cmd->argv[0], 1, NULL);
  c->argv[0] = pcalloc(c->pool, sizeof(int));
  *((int *) c->argv[0]) = engine;

  return PR_HANDLED(cmd);
}

/* usage: AutoHostLog path */
MODRET set_autohostlog(cmd_rec *cmd) {
  CHECK_ARGS(cmd, 1);
  CHECK_CONF(cmd, CONF_ROOT);

  if (pr_fs_valid_path(cmd->argv[1]) < 0) {
    CONF_ERROR(cmd, pstrcat(cmd->tmp_pool, "'", cmd->argv[1],
      "' is not a valid path", NULL));
  }

  (void) add_config_param_str(cmd->argv[0], 1, cmd->argv[1]);
  return PR_HANDLED(cmd);
}

/* usage: AutoHostPorts port1 ... portN */
MODRET set_autohostports(cmd_rec *cmd) {
  register unsigned int i;
  config_rec *c;
  array_header *port_list;

  if (cmd->argc < 2)
    CONF_ERROR(cmd, "wrong number of parameters");
  CHECK_CONF(cmd, CONF_ROOT);

  /* First, scan all of the configured ports to make sure that they are
   * all valid port numbers.
   */
  for (i = 1; i < cmd->argc; i++) {
    int port;

    port = atoi(cmd->argv[i]);
    if (port < 1 ||
        port > 65535) {
      CONF_ERROR(cmd, "port must be between 1 and 65535");
    }
  }

  c = add_config_param(cmd->argv[0], 1, NULL);

  port_list = make_array(c->pool, cmd->argc - 1, sizeof(int));
  for (i = 1; i < cmd->argc; i++) {
    *((int *) push_array(port_list)) = atoi(cmd->argv[i]);
  }

  c->argv[0] = port_list;
  return PR_HANDLED(cmd);
}

/* Command handlers
 */

MODRET autohost_pre_host(cmd_rec *cmd) {
  const char *path, *server_name;
  struct stat st;

  if (autohost_engine == FALSE) {
    return PR_DECLINED(cmd);
  }

  server_name = (const char *) cmd->argv[1];
  path = autohost_get_config(session.c, server_name);
  pr_trace_msg(trace_channel, 4, "using AutoHostConfig path '%s' for '%s %s'",
    path, (const char *) cmd->argv[0], server_name);

  if (pr_fsio_stat(path, &st) < 0) {
    (void) pr_log_writefile(autohost_logfd, MOD_AUTOHOST_VERSION,
      "error checking for '%s': %s", path, strerror(errno));
    return PR_DECLINED(cmd);
  }

  if (autohost_parse_config(session.c, path) < 0) {
    (void) pr_log_writefile(autohost_logfd, MOD_AUTOHOST_VERSION,
      "error parsing '%s': %s", path, strerror(errno));
    return PR_DECLINED(cmd);
  }

  pr_trace_msg(trace_channel, 9, "'%s %s' found using autohost for %s#%u",
    (const char *) cmd->argv[0], server_name,
    pr_netaddr_get_ipstr(session.c->local_addr), session.c->local_port);

  return PR_DECLINED(cmd);
}

/* Event listeners
 */

static void autohost_connect_ev(const void *event_data, void *user_data) {
  const char *path;
  struct stat st;
  conn_t *conn = (conn_t *) event_data;

  if (autohost_engine == FALSE) {
    return;
  }

  /* Autohost config files, if found, will take precedence over a matching
   * server config found in the main config file.
   *
   * To avoid this precedence, we could see if there is a binding already
   * configured for the incoming connection, e.g.:
   *
   *  if (pr_ipbind_get_server(conn->local_addr, conn->local_port) != NULL)
   *
   * but this would preclude us from being able to create multiple bindings
   * for the different AutoHostPorts.
   */

  /* Note that we need not necessarily worry about not destroying autohost_pool.
   * It is allocated after the fork().
   */

  path = autohost_get_config(conn, NULL);
  pr_trace_msg(trace_channel, 4, "using AutoHostConfig path '%s'", path);

  if (pr_fsio_stat(path, &st) < 0) {
    int xerrno = errno;

    /* If the given path contains '%n', and the path is not found, do not log
     * the error.  The file in question may be intended for name-based vhosts,
     * which can only be resolved at SNI/HOST time, not at TCP connect time.
     */
    if (xerrno == ENOENT &&
        strstr(path, "%n") != NULL) {
      pr_trace_msg(trace_channel, 19,
        "ignoring connect-time check of name-based config file '%s'", path);

    } else {
      (void) pr_log_writefile(autohost_logfd, MOD_AUTOHOST_VERSION,
        "error checking for '%s': %s", path, strerror(xerrno));
    }

    return;
  }

  if (autohost_parse_config(conn, path) < 0) {
    (void) pr_log_writefile(autohost_logfd, MOD_AUTOHOST_VERSION,
      "error parsing '%s': %s", path, strerror(errno));
    return;
  }

  pr_trace_msg(trace_channel, 9, "found using autohost for %s#%u",
    pr_netaddr_get_ipstr(conn->local_addr), conn->local_port);
}

#if defined(PR_SHARED_MODULE)
static void autohost_mod_unload_ev(const void *event_data, void *user_data) {
  if (strcmp("mod_autohost.c", (const char *) event_data) != 0) {
    return;
  }

  pr_event_unregister(&autohost_module, NULL, NULL);

  if (autohost_pool != NULL) {
    destroy_pool(autohost_pool);
  }

  (void) close(autohost_logfd);
  autohost_logfd = -1;

  autohost_pool = NULL;
  autohost_server_list = NULL;
  autohost_config = NULL;
}
#endif /* PR_SHARED_MODULE */

static void autohost_sni_ev(const void *event_data, void *user_data) {
  const char *path, *server_name;
  struct stat st;

  if (autohost_engine == FALSE) {
    return;
  }

  server_name = (const char *) event_data;
  path = autohost_get_config(session.c, server_name);
  pr_trace_msg(trace_channel, 4,
    "using AutoHostConfig path '%s' for TLS SNI '%s'", path, server_name);

  if (pr_fsio_stat(path, &st) < 0) {
    (void) pr_log_writefile(autohost_logfd, MOD_AUTOHOST_VERSION,
      "error checking for '%s': %s", path, strerror(errno));
    return;
  }

  if (autohost_parse_config(session.c, path) < 0) {
    (void) pr_log_writefile(autohost_logfd, MOD_AUTOHOST_VERSION,
      "error parsing '%s': %s", path, strerror(errno));
    return;
  }

  pr_trace_msg(trace_channel, 9, "TLS SNI '%s' found using autohost for %s#%u",
    server_name, pr_netaddr_get_ipstr(session.c->local_addr),
    session.c->local_port);
}

static void autohost_postparse_ev(const void *event_data, void *user_data) {
  config_rec *c;

  c = find_config(main_server->conf, CONF_PARAM, "AutoHostEngine", FALSE);
  if (c != NULL) {
    autohost_engine = *((int *) c->argv[0]);
  }

  if (autohost_engine == FALSE) {
    return;
  }

  if (autohost_pool != NULL) {
    destroy_pool(autohost_pool);
    autohost_server_list = NULL;
  }

  autohost_pool = make_sub_pool(permanent_pool);
  pr_pool_tag(autohost_pool, MOD_AUTOHOST_VERSION);

  pr_event_register(&autohost_module, "core.connect", autohost_connect_ev,
    NULL);
  pr_event_register(&autohost_module, "mod_tls.sni", autohost_sni_ev, NULL);

  c = find_config(main_server->conf, CONF_PARAM, "AutoHostConfig", FALSE);
  if (c != NULL) {
    autohost_config = c->argv[0];

  } else {
    pr_log_debug(DEBUG0, MOD_AUTOHOST_VERSION
      ": missing required AutoHostConfig");
    pr_session_disconnect(&autohost_module, PR_SESS_DISCONNECT_BAD_CONFIG,
      "missing required AutoHostConfig directive");
  }

  c = find_config(main_server->conf, CONF_PARAM, "AutoHostLog", FALSE);
  if (c != NULL) {
    int res;
    char *autohost_log;

    autohost_log = c->argv[0];

    (void) close(autohost_logfd);
    autohost_logfd = -1;

    PRIVS_ROOT
    res = pr_log_openfile(autohost_log, &autohost_logfd, 0660);
    PRIVS_RELINQUISH

    switch (res) {
      case 0:
        break;

      case -1:
        pr_log_debug(DEBUG1, MOD_AUTOHOST_VERSION
          ": unable to open AutoHostLog '%s': %s", autohost_log,
          strerror(errno));
        break;

      case PR_LOG_SYMLINK:
        pr_log_debug(DEBUG1, MOD_AUTOHOST_VERSION
          ": unable to open AutoHostLog '%s': %s", autohost_log,
          "is a symlink");
        break;

      case PR_LOG_WRITABLE_DIR:
        pr_log_debug(DEBUG0, MOD_AUTOHOST_VERSION
          ": unable to open AutoHostLog '%s': %s", autohost_log,
          "parent directory is world-writable");
        break;
    }
  }

  autohost_server_list = xaset_create(autohost_pool, NULL);

  c = find_config(main_server->conf, CONF_PARAM, "AutoHostPorts", FALSE);
  if (c != NULL) {
    register unsigned int i;
    array_header *port_list;
    int *ports;

    port_list = c->argv[0];
    ports = port_list->elts;

    /* We need to open a binding for each of the specific ports, unless
     * such a binding already exists.
     */

    for (i = 0; i < port_list->nelts; i++) {
      /* If this port duplicates the existing Port, skip it. */
      if (ports[i] == main_server->ServerPort) {
        continue;
      }

      if (pr_ipbind_find(main_server->addr, ports[i], TRUE) == NULL) {
        int res;
        conn_t *listener;

        (void) pr_log_writefile(autohost_logfd, MOD_AUTOHOST_VERSION,
          "adding socket for AutoHostPort %d", ports[i]);

        res = pr_ipbind_create(main_server, main_server->addr, ports[i]);
        if (res < 0) {
          (void) pr_log_writefile(autohost_logfd, MOD_AUTOHOST_VERSION,
            "error creating binding for %s#%d: %s",
            pr_netaddr_get_ipstr(main_server->addr), ports[i], strerror(errno));
          continue;
        }

        /* Create a listening socket for this port. */
        listener = pr_inet_create_conn(autohost_pool, -1, main_server->addr,
          ports[i], FALSE);
        if (listener == NULL) {
          (void) pr_log_writefile(autohost_logfd, MOD_AUTOHOST_VERSION,
            "error opening new listening socket for port %d: %s", ports[i],
            strerror(errno));
          continue;
        }

        res = pr_ipbind_open(main_server->addr, ports[i], listener, FALSE,
          FALSE, TRUE);
        if (res < 0) {
          (void) pr_log_writefile(autohost_logfd, MOD_AUTOHOST_VERSION,
            "error opening binding for %s:%d: %s",
            pr_netaddr_get_ipstr(main_server->addr), ports[i], strerror(errno));
          continue;
        }

        (void) pr_log_writefile(autohost_logfd, MOD_AUTOHOST_VERSION,
          "opening listening socket for %s on AutoHostPort %d",
          pr_netaddr_get_ipstr(main_server->addr), ports[i]);
      }
    }
  }
}

/* Initialization routines
 */

static int autohost_init(void) {
#if defined(PR_SHARED_MODULE)
  pr_event_register(&autohost_module, "core.module-unload",
    autohost_mod_unload_ev, NULL);
#endif /* PR_SHARED_MODULE */

  pr_event_register(&autohost_module, "core.postparse", autohost_postparse_ev,
    NULL);

  return 0;
}

/* Module API tables
 */

static conftable autohost_conftab[] = {
  { "AutoHostConfig",	set_autohostconfig,	NULL },
  { "AutoHostEngine",	set_autohostengine,	NULL },
  { "AutoHostLog",	set_autohostlog,	NULL },
  { "AutoHostPorts",	set_autohostports,	NULL },
  { NULL }
};

static cmdtable autohost_cmdtab[] = {
#if defined(C_HOST)
  { PRE_CMD,	C_HOST,	G_NONE,	autohost_pre_host,	FALSE,	FALSE },
#endif /* FTP HOST support */
  { 0, NULL }
};

module autohost_module = {
  NULL, NULL,

  /* Module API version 2.0 */
  0x20,

  /* Module name */
  "autohost",

  /* Module configuration handler table */
  autohost_conftab,

  /* Module command handler table */
  autohost_cmdtab,

  /* Module authentication handler table */
  NULL,

  /* Module initialization function */
  autohost_init,

  /* Session initialization function */
  NULL,

  /* Module version */
  MOD_AUTOHOST_VERSION
};
