package ProFTPD::Tests::Modules::mod_autohost::sni;

use lib qw(t/lib);
use base qw(ProFTPD::TestSuite::Child);
use strict;

use Cwd;
use Digest::MD5;
use File::Path qw(mkpath);
use File::Spec;
use IO::Handle;
use IO::Socket::INET6;
use POSIX qw(:fcntl_h);

use ProFTPD::TestSuite::FTP;
use ProFTPD::TestSuite::Utils qw(:auth :config :running :test :testsuite);

$| = 1;

my $order = 0;

my $TESTS = {
  autohost_sni_config_ok => {
    order => ++$order,
    test_class => [qw(forking mod_tls)],
  },

  autohost_sni_config_missing => {
    order => ++$order,
    test_class => [qw(forking mod_tls)],
  },

  autohost_sni_config_no_serveralias => {
    order => ++$order,
    test_class => [qw(forking mod_tls)],
  },

  autohost_sni_config_mismatched_serveralias => {
    order => ++$order,
    test_class => [qw(forking mod_tls)],
  },

  autohost_sni_config_existing_serveralias => {
    order => ++$order,
    test_class => [qw(forking mod_tls)],
  },

  autohost_sni_config_ok_with_host => {
    order => ++$order,
    test_class => [qw(forking mod_tls)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  # Check for the required Perl modules:
  #
  #  Net-SSLeay
  #  IO-Socket-SSL
  #  Net-FTPSSL

  my $required = [qw(
    Net::SSLeay
    IO::Socket::SSL
    Net::FTPSSL
  )];

  foreach my $req (@$required) {
    eval "use $req";
    if ($@) {
      print STDERR "\nWARNING:\n + Module '$req' not found, skipping all tests\n";

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "Unable to load $req: $@\n";
      }

      return qw(testsuite_empty_test);
    }
  }

  return testsuite_get_runnable_tests($TESTS);
}

sub autohost_sni_config_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'autohost');

  my $host = 'castaglia';

  my $cert_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_tls/server-cert.pem");
  my $ca_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_tls/ca-cert.pem");

  mkpath("$tmpdir/conf.d");
  my $auto_config = File::Spec->rel2abs("$tmpdir/conf.d/127.0.0.1-$host.conf");
  if (open(my $fh, "> $auto_config")) {
    print $fh <<EOC;
ServerAlias $host
ServerName "AutoHost Server"
AuthUserFile $setup->{auth_user_file}
AuthGroupFile $setup->{auth_group_file}
ServerLog $setup->{log_file}
RequireValidShell off

<IfModule mod_tls.c>
  TLSEngine on
  TLSLog $setup->{log_file}
  TLSRequired on
  TLSRSACertificateFile $cert_file
  TLSCACertificateFile $ca_file
  TLSOptions EnableDiags
</IfModule>
EOC
    unless (close($fh)) {
      die("Can't write $auto_config: $!");
    }

  } else {
    die("Can't open $auto_config: $!");
  }

  my $test_root = File::Spec->rel2abs($tmpdir);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'autohost:20 binding:20 event:20 tls:20',

    IfModules => {
      'mod_autohost.c' => {
        AutoHostEngine => 'on',
        AutoHostLog => $setup->{log_file},
        AutoHostConfig => "$test_root/conf.d/%0-%n.conf",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_tls.c' => {
        TLSEngine => 'on',
        TLSLog => $setup->{log_file},
        TLSRequired => 'on',
        TLSRSACertificateFile => $cert_file,
        TLSCACertificateFile => $ca_file,
        TLSOptions => 'EnableDiags',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::FTPSSL;
  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Give the server a chance to start up
      sleep(2);

      my $ssl_opts = {
        Encryption => 'E',
        Port => $port,
        SSL_ca_file => $ca_file,
        SSL_hostname => $host,
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER(),
        SSL_verifycn_name => 'server-cert',
      };

      if ($ENV{TEST_VERBOSE}) {
        $ssl_opts->{Debug} = 2;
      }

      my $client = Net::FTPSSL->new('127.0.0.1', $ssl_opts);
      unless ($client) {
        die("Can't connect to FTPS server: " . IO::Socket::SSL::errstr());
      }

      # Our default server will not have the AuthUserFile configured with our
      # test user; only the name-based AutoHost config does.  So if login
      # succeeds, we will know that that name-based AutoHost config has been
      # loaded/used successfully.
      unless ($client->login($setup->{user}, $setup->{passwd})) {
        die("Login failed unexpectedly: ". $client->last_message());
      }

      $client->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub autohost_sni_config_missing {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'autohost');

  my $host = 'castaglia';

  my $cert_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_tls/server-cert.pem");
  my $ca_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_tls/ca-cert.pem");

  mkpath("$tmpdir/conf.d");
  my $auto_config = File::Spec->rel2abs("$tmpdir/conf.d/127.0.0.1-foo.conf");
  if (open(my $fh, "> $auto_config")) {
    print $fh <<EOC;
ServerAlias $host
ServerName "AutoHost Server"
AuthUserFile $setup->{auth_user_file}
AuthGroupFile $setup->{auth_group_file}
ServerLog $setup->{log_file}
RequireValidShell off

<IfModule mod_tls.c>
  TLSEngine on
  TLSLog $setup->{log_file}
  TLSRequired on
  TLSRSACertificateFile $cert_file
  TLSCACertificateFile $ca_file
  TLSOptions EnableDiags
</IfModule>
EOC
    unless (close($fh)) {
      die("Can't write $auto_config: $!");
    }

  } else {
    die("Can't open $auto_config: $!");
  }

  my $test_root = File::Spec->rel2abs($tmpdir);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'autohost:20 binding:20 event:20 tls:20',

    IfModules => {
      'mod_autohost.c' => {
        AutoHostEngine => 'on',
        AutoHostLog => $setup->{log_file},
        AutoHostConfig => "$test_root/conf.d/%0-%n.conf",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_tls.c' => {
        TLSEngine => 'on',
        TLSLog => $setup->{log_file},
        TLSRequired => 'on',
        TLSRSACertificateFile => $cert_file,
        TLSCACertificateFile => $ca_file,
        TLSOptions => 'EnableDiags',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::FTPSSL;
  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Give the server a chance to start up
      sleep(2);

      my $ssl_opts = {
        Encryption => 'E',
        Port => $port,
        SSL_ca_file => $ca_file,
        SSL_hostname => $host,
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER(),
        SSL_verifycn_name => 'server-cert',
      };

      if ($ENV{TEST_VERBOSE}) {
        $ssl_opts->{Debug} = 2;
      }

      # Although we are specifying an SNI which is not configured, we DO
      # expect the connection to succeed.  ProFTPD ignores unknown SNI,
      # so that existing configurations that lack ServerAlias do not break
      # unexpectedly.
      my $client = Net::FTPSSL->new('127.0.0.1', $ssl_opts);
      my $client = Net::FTPSSL->new('127.0.0.1', $ssl_opts);
      $client->login($setup->{user}, $setup->{passwd});
      $client->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub autohost_sni_config_no_serveralias {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'autohost');

  my $host = 'castaglia';

  my $cert_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_tls/server-cert.pem");
  my $ca_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_tls/ca-cert.pem");

  mkpath("$tmpdir/conf.d");
  my $auto_config = File::Spec->rel2abs("$tmpdir/conf.d/127.0.0.1-$host.conf");
  if (open(my $fh, "> $auto_config")) {
    print $fh <<EOC;
ServerName "AutoHost Server"
AuthUserFile $setup->{auth_user_file}
AuthGroupFile $setup->{auth_group_file}
ServerLog $setup->{log_file}
RequireValidShell off

<IfModule mod_tls.c>
  TLSEngine on
  TLSLog $setup->{log_file}
  TLSRequired on
  TLSRSACertificateFile $cert_file
  TLSCACertificateFile $ca_file
  TLSOptions EnableDiags
</IfModule>
EOC
    unless (close($fh)) {
      die("Can't write $auto_config: $!");
    }

  } else {
    die("Can't open $auto_config: $!");
  }

  my $test_root = File::Spec->rel2abs($tmpdir);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'autohost:20 binding:20 event:20 tls:20',

    IfModules => {
      'mod_autohost.c' => {
        AutoHostEngine => 'on',
        AutoHostLog => $setup->{log_file},
        AutoHostConfig => "$test_root/conf.d/%0-%n.conf",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_tls.c' => {
        TLSEngine => 'on',
        TLSLog => $setup->{log_file},
        TLSRequired => 'on',
        TLSRSACertificateFile => $cert_file,
        TLSCACertificateFile => $ca_file,
        TLSOptions => 'EnableDiags',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::FTPSSL;
  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Give the server a chance to start up
      sleep(2);

      my $ssl_opts = {
        Encryption => 'E',
        Port => $port,
        SSL_ca_file => $ca_file,
        SSL_hostname => $host,
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER(),
        SSL_verifycn_name => 'server-cert',
      };

      if ($ENV{TEST_VERBOSE}) {
        $ssl_opts->{Debug} = 2;
      }

      # Although we are specifying an SNI which is configured, that
      # configuration does NOT provide a matching ServerAlias. We DO
      # expect the connection to succeed.  ProFTPD ignores SNI that does
      # not match, so that existing configurations that lack ServerAlias do
      # not break unexpectedly.
      my $client = Net::FTPSSL->new('127.0.0.1', $ssl_opts);
      $client->login($setup->{user}, $setup->{passwd});
      $client->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub autohost_sni_config_mismatched_serveralias {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'autohost');

  my $host = 'castaglia';

  my $cert_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_tls/server-cert.pem");
  my $ca_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_tls/ca-cert.pem");

  mkpath("$tmpdir/conf.d");
  my $auto_config = File::Spec->rel2abs("$tmpdir/conf.d/127.0.0.1-$host.conf");
  if (open(my $fh, "> $auto_config")) {
    print $fh <<EOC;
ServerAlias ftp.example.com
ServerName "AutoHost Server"
AuthUserFile $setup->{auth_user_file}
AuthGroupFile $setup->{auth_group_file}
ServerLog $setup->{log_file}
RequireValidShell off

<IfModule mod_tls.c>
  TLSEngine on
  TLSLog $setup->{log_file}
  TLSRequired on
  TLSRSACertificateFile $cert_file
  TLSCACertificateFile $ca_file
  TLSOptions EnableDiags
</IfModule>
EOC
    unless (close($fh)) {
      die("Can't write $auto_config: $!");
    }

  } else {
    die("Can't open $auto_config: $!");
  }

  my $test_root = File::Spec->rel2abs($tmpdir);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'autohost:20 binding:20 event:20 tls:20',

    IfModules => {
      'mod_autohost.c' => {
        AutoHostEngine => 'on',
        AutoHostLog => $setup->{log_file},
        AutoHostConfig => "$test_root/conf.d/%0-%n.conf",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_tls.c' => {
        TLSEngine => 'on',
        TLSLog => $setup->{log_file},
        TLSRequired => 'on',
        TLSRSACertificateFile => $cert_file,
        TLSCACertificateFile => $ca_file,
        TLSOptions => 'EnableDiags',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::FTPSSL;
  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Give the server a chance to start up
      sleep(2);

      my $ssl_opts = {
        Encryption => 'E',
        Port => $port,
        SSL_ca_file => $ca_file,
        SSL_hostname => $host,
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER(),
        SSL_verifycn_name => 'server-cert',
      };

      if ($ENV{TEST_VERBOSE}) {
        $ssl_opts->{Debug} = 2;
      }

      my $client = Net::FTPSSL->new('127.0.0.1', $ssl_opts);
      if ($client) {
        die("Connected to FTPS server unexpectedly");
      }

      my $errstr = IO::Socket::SSL::errstr();
      my $expected = 'handshake failure|unrecognized name';
      $self->assert(qr/$expected/, $errstr,
        test_msg("Expected '$expected', got '$errstr'"));
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub autohost_sni_config_existing_serveralias {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'autohost');

  my $host = 'castaglia';

  my $cert_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_tls/server-cert.pem");
  my $ca_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_tls/ca-cert.pem");

  mkpath("$tmpdir/conf.d");
  my $auto_config = File::Spec->rel2abs("$tmpdir/conf.d/127.0.0.1-$host.conf");
  if (open(my $fh, "> $auto_config")) {
    print $fh <<EOC;
ServerAlias $host
ServerName "AutoHost Server"
AuthUserFile $setup->{auth_user_file}
AuthGroupFile $setup->{auth_group_file}
ServerLog $setup->{log_file}
RequireValidShell off

<IfModule mod_tls.c>
  TLSEngine on
  TLSLog $setup->{log_file}
  TLSRequired on
  TLSRSACertificateFile $cert_file
  TLSCACertificateFile $ca_file
  TLSOptions EnableDiags
</IfModule>
EOC
    unless (close($fh)) {
      die("Can't write $auto_config: $!");
    }

  } else {
    die("Can't open $auto_config: $!");
  }

  my $test_root = File::Spec->rel2abs($tmpdir);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'autohost:20 binding:20 event:20 tls:20',

    ServerAlias => $host,

    IfModules => {
      'mod_autohost.c' => {
        AutoHostEngine => 'on',
        AutoHostLog => $setup->{log_file},
        AutoHostConfig => "$test_root/conf.d/%0-%n.conf",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_tls.c' => {
        TLSEngine => 'on',
        TLSLog => $setup->{log_file},
        TLSRequired => 'on',
        TLSRSACertificateFile => $cert_file,
        TLSCACertificateFile => $ca_file,
        TLSOptions => 'EnableDiags',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::FTPSSL;
  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Give the server a chance to start up
      sleep(2);

      my $ssl_opts = {
        Encryption => 'E',
        Port => $port,
        SSL_ca_file => $ca_file,
        SSL_hostname => $host,
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER(),
        SSL_verifycn_name => 'server-cert',
      };

      if ($ENV{TEST_VERBOSE}) {
        $ssl_opts->{Debug} = 2;
      }

      my $client = Net::FTPSSL->new('127.0.0.1', $ssl_opts);
      unless ($client) {
        die("Can't connect to FTPS server: " . IO::Socket::SSL::errstr());
      }

      # Our default server will not have the AuthUserFile configured with our
      # test user; only the name-based AutoHost config does.  So if login
      # succeeds, we will know that that name-based AutoHost config has been
      # loaded/used successfully.
      unless ($client->login($setup->{user}, $setup->{passwd})) {
        die("Login failed unexpectedly: ". $client->last_message());
      }

      $client->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

sub autohost_sni_config_ok_with_host {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'autohost');

  my $host = 'castaglia';

  my $cert_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_tls/server-cert.pem");
  my $ca_file = File::Spec->rel2abs("$ENV{PROFTPD_TEST_DIR}/tests/t/etc/modules/mod_tls/ca-cert.pem");

  mkpath("$tmpdir/conf.d");
  my $auto_config = File::Spec->rel2abs("$tmpdir/conf.d/127.0.0.1-$host.conf");
  if (open(my $fh, "> $auto_config")) {
    print $fh <<EOC;
ServerAlias $host
ServerName "AutoHost Server"
AuthUserFile $setup->{auth_user_file}
AuthGroupFile $setup->{auth_group_file}
ServerLog $setup->{log_file}
RequireValidShell off

<IfModule mod_tls.c>
  TLSEngine on
  TLSLog $setup->{log_file}
  TLSRequired on
  TLSRSACertificateFile $cert_file
  TLSCACertificateFile $ca_file
  TLSOptions EnableDiags
</IfModule>
EOC
    unless (close($fh)) {
      die("Can't write $auto_config: $!");
    }

  } else {
    die("Can't open $auto_config: $!");
  }

  my $test_root = File::Spec->rel2abs($tmpdir);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'autohost:20 binding:20 event:20 tls:20',

    IfModules => {
      'mod_autohost.c' => {
        AutoHostEngine => 'on',
        AutoHostLog => $setup->{log_file},
        AutoHostConfig => "$test_root/conf.d/%0-%n.conf",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },

      'mod_tls.c' => {
        TLSEngine => 'on',
        TLSLog => $setup->{log_file},
        TLSRequired => 'on',
        TLSRSACertificateFile => $cert_file,
        TLSCACertificateFile => $ca_file,
        TLSOptions => 'EnableDiags',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  require Net::FTPSSL;
  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      # Give the server a chance to start up
      sleep(2);

      my $ssl_opts = {
        Encryption => 'E',
        Port => $port,
        SSL_ca_file => $ca_file,
        SSL_hostname => $host,
        SSL_verify_mode => IO::Socket::SSL::SSL_VERIFY_PEER(),
        SSL_verifycn_name => 'server-cert',
      };

      if ($ENV{TEST_VERBOSE}) {
        $ssl_opts->{Debug} = 2;
      }

      my $client = Net::FTPSSL->new('127.0.0.1', $ssl_opts);
      unless ($client) {
        die("Can't connect to FTPS server: " . IO::Socket::SSL::errstr());
      }

      unless ($client->quot('HOST', $host)) {
        die("HOST failed unexpectedly: ". $client->last_message());
      }

      my $resp_msg = $client->last_message();
      my $expected = 'AutoHost Server';
      $self->assert(qr/$expected/, $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

      # Our default server will not have the AuthUserFile configured with our
      # test user; only the name-based AutoHost config does.  So if login
      # succeeds, we will know that that name-based AutoHost config has been
      # loaded/used successfully.
      unless ($client->login($setup->{user}, $setup->{passwd})) {
        die("Login failed unexpectedly: ". $client->last_message());
      }

      $client->quit();
    };
    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($setup->{config_file}, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($setup->{pid_file});
  $self->assert_child_ok($pid);

  test_cleanup($setup->{log_file}, $ex);
}

1;
