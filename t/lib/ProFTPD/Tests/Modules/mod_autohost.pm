package ProFTPD::Tests::Modules::mod_autohost;

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
  autohost_config => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  autohost_config_ipv6 => {
    order => ++$order,
    test_class => [qw(features_ipv6 forking)],
  },

  autohost_ports => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  autohost_extlog_var_p => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  # XXX mod_autohost does not picking up <Global> sections from proftpd.conf
  # yet; requires a fair amount of reworking, since fixup_globals() removes
  # the <Global> sections from the config tree.
  autohost_global_config => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },

  autohost_sighup_issue10 => {
    order => ++$order,
    test_class => [qw(bug forking)],
  },
};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub autohost_config {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'autohost');

  mkpath("$tmpdir/conf.d");
  my $auto_config = File::Spec->rel2abs("$tmpdir/conf.d/127.0.0.1.conf");
  if (open(my $fh, "> $auto_config")) {
    print $fh <<EOC;
ServerName "AutoHost Server"
AuthUserFile $setup->{auth_user_file}
AuthGroupFile $setup->{auth_group_file}
ServerLog $setup->{log_file}
RequireValidShell off
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
    Trace => 'DEFAULT:10 autohost:20',

    IfModules => {
      'mod_autohost.c' => {
        AutoHostEngine => 'on',
        AutoHostLog => $setup->{log_file},
        AutoHostConfig => "$test_root/conf.d/%0.conf",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
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

sub autohost_config_ipv6 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'autohost');

  mkpath("$tmpdir/conf.d");
  my $auto_config = File::Spec->rel2abs("$tmpdir/conf.d/::1.conf");
  if (open(my $fh, "> $auto_config")) {
    print $fh <<EOC;
ServerName "AutoHost IPv6 Server"
AuthUserFile $setup->{auth_user_file}
AuthGroupFile $setup->{auth_group_file}
ServerLog $setup->{log_file}
RequireValidShell off
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
    Trace => 'binding:10 autohost:20',

    UseIPv6 => 'on',
    DefaultAddress => '::1',

    IfModules => {
      'mod_autohost.c' => {
        AutoHostEngine => 'on',
        AutoHostLog => $setup->{log_file},
        AutoHostConfig => "$test_root/conf.d/%0.conf",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
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

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      sleep(1);

      my $client = IO::Socket::INET6->new(
        PeerAddr => '::1',
        PeerPort => $port,
        Proto => 'tcp',
        Timeout => 5,
        Blocking => 1,
      );
      unless ($client) {
        die("Can't connect to ::1: $!");
      }

      # Read the banner
      my $banner = <$client>;
      chomp($banner);
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# <<< $banner\n";
      }

      # Send the USER command
      my $cmd = "USER $setup->{user}";
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# >>> $cmd\n";
      }
      $client->print("$cmd\r\n");
      $client->flush();

      # Read USER response
      my $resp = <$client>;
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# <<< $resp";
      }

      my $expected = "331 Password required for $setup->{user}\r\n";
      $self->assert($expected eq $resp,
        test_msg("Expected response '$expected', got '$resp'"));

      # Send the PASS command
      $cmd = "PASS $setup->{passwd}";
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# >>> PASS ******\r\n";
      }
      $client->print("$cmd\r\n");
      $client->flush();

      # Read PASS response
      $resp = <$client>;
      if ($ENV{TEST_VERBOSE}) {
        print STDERR "<<< $resp";
      }

      $expected = "230 User $setup->{user} logged in\r\n";
      $self->assert($expected eq $resp,
        test_msg("Expected response '$expected', got '$resp'"));

      $client->close();
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

sub autohost_ports {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'autohost');

  my $test_root = File::Spec->rel2abs($tmpdir);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'DEFAULT:10 binding:20 autohost:20',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $autohost_port = $port + 21;
  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh <<EOC;
<IfModule mod_autohost.c>
  AutoHostEngine on
  AutoHostLog $setup->{log_file}
  AutoHostConfig $test_root/conf.d/%0:%p.conf
  AutoHostPorts $autohost_port
</IfModule>
EOC
    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

  mkpath("$tmpdir/conf.d");
  my $auto_config = File::Spec->rel2abs("$tmpdir/conf.d/127.0.0.1:$autohost_port.conf");
  if (open(my $fh, "> $auto_config")) {
    print $fh <<EOC;
ServerName "AutoHost Server"
AuthUserFile $setup->{auth_user_file}
AuthGroupFile $setup->{auth_group_file}
RequireValidShell off
ServerLog $setup->{log_file}
EOC
    unless (close($fh)) {
      die("Can't write $auto_config: $!");
    }

  } else {
    die("Can't open $auto_config: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $autohost_port);
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

sub autohost_extlog_var_p {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'autohost');

  my $test_root = File::Spec->rel2abs($tmpdir);
  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'DEFAULT:10 autohost:20',

    LogFormat => 'custom "%p"',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $autohost_port = $port + 11;

  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh <<EOC;
<IfModule mod_autohost.c>
  AutoHostEngine on
  AutoHostLog $setup->{log_file}
  AutoHostConfig $test_root/conf.d/%0:%p.conf
  AutoHostPorts $autohost_port
</IfModule>
EOC
    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

  mkpath("$tmpdir/conf.d");
  my $auto_config = File::Spec->rel2abs("$tmpdir/conf.d/127.0.0.1:$autohost_port.conf");
  if (open(my $fh, "> $auto_config")) {
    print $fh <<EOC;
ServerName "AutoHost Server"
AuthUserFile $setup->{auth_user_file}
AuthGroupFile $setup->{auth_group_file}
ServerLog $setup->{log_file}
RequireValidShell off
ExtendedLog $ext_log ALL custom
EOC
    unless (close($fh)) {
      die("Can't write $auto_config: $!");
    }

  } else {
    die("Can't open $auto_config: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $autohost_port);
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

  if ($ex) {
    test_cleanup($setup->{log_file}, $ex);
    return;
  }

  # Now, read in the ExtendedLog, and see whether the %p variable was
  # properly written out.
  eval {
    if (open(my $fh, "< $ext_log")) {
      my $line = <$fh>;
      chomp($line);
      close($fh);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# $line\n";
      }

      $self->assert($autohost_port eq $line,
        test_msg("Expected '$autohost_port', got '$line'"));

    } else {
      die("Can't read $ext_log: $!");
    }
  };
  if ($@) {
    $ex = $@;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub autohost_global_config {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'autohost');

  my $test_root = File::Spec->rel2abs($tmpdir);
  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'DEFAULT:10 autohost:20',

    LogFormat => 'custom "%p"',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },

    Global => {
      ExtendedLog => "$ext_log ALL custom",
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $autohost_port = $port + 7;

  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh <<EOC;
<IfModule mod_autohost.c>
  AutoHostEngine on
  AutoHostLog $setup->{log_file}
  AutoHostConfig $test_root/conf.d/%0:%p.conf
  AutoHostPorts $autohost_port
</IfModule>
EOC
    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

  mkpath("$tmpdir/conf.d");
  my $auto_config = File::Spec->rel2abs("$tmpdir/conf.d/127.0.0.1:$autohost_port.conf");
  if (open(my $fh, "> $auto_config")) {
    print $fh <<EOC;
ServerName "AutoHost Server"
AuthUserFile $setup->{auth_user_file}
AuthGroupFile $setup->{auth_group_file}
ServerLog $setup->{log_file}
RequireValidShell off
EOC
    unless (close($fh)) {
      die("Can't write $auto_config: $!");
    }

  } else {
    die("Can't open $auto_config: $!");
  }

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $autohost_port);
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

  if ($ex) {
    test_cleanup($setup->{log_file}, $ex);
    return;
  }

  eval {
    # Now, read in the ExtendedLog, and see whether the %p variable was
    # properly written out.
    if (open(my $fh, "< $ext_log")) {
      my $line = <$fh>;
      chomp($line);
      close($fh);

      if ($ENV{TEST_VERBOSE}) {
        print STDERR "# $line\n";
      }

      $self->assert($autohost_port eq $line,
        test_msg("Expected '$autohost_port', got '$line'"));

    } else {
      die("Can't read $ext_log: $!");
    }
  };
  if ($@) {
    $ex;
  }

  test_cleanup($setup->{log_file}, $ex);
}

sub autohost_sighup_issue10 {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'autohost');

  my $test_root = File::Spec->rel2abs($tmpdir);

  my $config = {
    PidFile => $setup->{pid_file},
    ScoreboardFile => $setup->{scoreboard_file},
    SystemLog => $setup->{log_file},
    TraceLog => $setup->{log_file},
    Trace => 'DEFAULT:10 autohost:20',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($setup->{config_file},
    $config);

  my $autohost_port = $port + 9;
  if (open(my $fh, ">> $setup->{config_file}")) {
    print $fh <<EOC;
<IfModule mod_autohost.c>
  AutoHostEngine on
  AutoHostLog $setup->{log_file}
  AutoHostConfig $test_root/conf.d/%0:%p.conf
  AutoHostPorts $autohost_port
</IfModule>
EOC
    unless (close($fh)) {
      die("Can't write $setup->{config_file}: $!");
    }

  } else {
    die("Can't open $setup->{config_file}: $!");
  }

  mkpath("$tmpdir/conf.d");
  my $auto_config = File::Spec->rel2abs("$tmpdir/conf.d/127.0.0.1:$autohost_port.conf");
  if (open(my $fh, "> $auto_config")) {
    print $fh <<EOC;
ServerName "AutoHost Server"
AuthUserFile $setup->{auth_user_file}
AuthGroupFile $setup->{auth_group_file}
RequireValidShell off
ServerLog $setup->{log_file}
EOC
    unless (close($fh)) {
      die("Can't write $auto_config: $!");
    }

  } else {
    die("Can't open $auto_config: $!");
  }

  # Start the server
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Starting daemon\n";
  }
  server_start($setup->{config_file});
  sleep(1);

  # Restart the server
  if ($ENV{TEST_VERBOSE}) {
    print STDERR "# Restarting daemon via SIGHUP\n";
  }
  server_restart($setup->{pid_file});
  sleep(1);

  # Open pipes, for use between the parent and child processes.  Specifically,
  # the child will indicate when it's done with its test by writing a message
  # to the parent.
  my ($rfh, $wfh);
  unless (pipe($rfh, $wfh)) {
    die("Can't open pipe: $!");
  }

  my $ex;

  # Fork child
  $self->handle_sigchld();
  defined(my $pid = fork()) or die("Can't fork: $!");
  if ($pid) {
    eval {
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $autohost_port);
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

1;
