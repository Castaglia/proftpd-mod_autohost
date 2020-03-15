package ProFTPD::Tests::Modules::mod_autohost::host;

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
  autohost_host_config_ok => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  autohost_host_config_missing => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  autohost_host_config_no_serveralias => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  autohost_host_config_mismatched_serveralias => {
    order => ++$order,
    test_class => [qw(forking)],
  },

  autohost_host_config_existing_serveralias => {
    order => ++$order,
    test_class => [qw(forking)],
  },

};

sub new {
  return shift()->SUPER::new(@_);
}

sub list_tests {
  return testsuite_get_runnable_tests($TESTS);
}

sub autohost_host_config_ok {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'autohost');

  my $host = 'castaglia';

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
    Trace => 'autohost:20 binding:20 event:20',

    IfModules => {
      'mod_autohost.c' => {
        AutoHostEngine => 'on',
        AutoHostLog => $setup->{log_file},
        AutoHostConfig => "$test_root/conf.d/%0-%n.conf",
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
      $client->host($host);

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 'AutoHost Server';
      $self->assert(qr/$expected/, $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

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

sub autohost_host_config_missing {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'autohost');

  my $host = 'castaglia';

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
    Trace => 'autohost:20 binding:20 event:20',

    IfModules => {
      'mod_autohost.c' => {
        AutoHostEngine => 'on',
        AutoHostLog => $setup->{log_file},
        AutoHostConfig => "$test_root/conf.d/%0-%n.conf",
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
      eval { $client->host($host) };
      unless ($@) {
        die("HOST $host succeeded unexpectedly");
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

sub autohost_host_config_no_serveralias {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'autohost');

  my $host = 'castaglia';

  mkpath("$tmpdir/conf.d");
  my $auto_config = File::Spec->rel2abs("$tmpdir/conf.d/127.0.0.1-$host.conf");
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
    Trace => 'autohost:20 binding:20 event:20',

    IfModules => {
      'mod_autohost.c' => {
        AutoHostEngine => 'on',
        AutoHostLog => $setup->{log_file},
        AutoHostConfig => "$test_root/conf.d/%0-%n.conf",
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
      eval { $client->host($host) };
      unless ($@) {
        die("HOST $host succeeded unexpectedly");
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

sub autohost_host_config_mismatched_serveralias {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'autohost');

  my $host = 'castaglia';

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
    Trace => 'autohost:20 binding:20 event:20',

    IfModules => {
      'mod_autohost.c' => {
        AutoHostEngine => 'on',
        AutoHostLog => $setup->{log_file},
        AutoHostConfig => "$test_root/conf.d/%0-%n.conf",
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
      eval { $client->host($host) };
      unless ($@) {
        die("HOST $host succeeded unexpectedly");
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

sub autohost_host_config_existing_serveralias {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};
  my $setup = test_setup($tmpdir, 'autohost');

  my $host = 'castaglia';

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
    Trace => 'autohost:20 binding:20 event:20',

    ServerAlias => $host,
    ServerName => '"Default Server"',

    IfModules => {
      'mod_autohost.c' => {
        AutoHostEngine => 'on',
        AutoHostLog => $setup->{log_file},
        AutoHostConfig => "$test_root/conf.d/%0-%n.conf",
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
      $client->host($host);

      my $resp_code = $client->response_code();
      my $resp_msg = $client->response_msg();

      my $expected = 'AutoHost Server';
      $self->assert(qr/$expected/, $resp_msg,
        test_msg("Expected response message '$expected', got '$resp_msg'"));

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
