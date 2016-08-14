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

  my $config_file = "$tmpdir/autohost.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/autohost.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/autohost.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/autohost.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/autohost.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs("$tmpdir/home");
  mkpath($home_dir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  mkpath("$tmpdir/conf.d");
  my $auto_config = File::Spec->rel2abs("$tmpdir/conf.d/127.0.0.1.conf");
  if (open(my $fh, "> $auto_config")) {
    print $fh <<EOC;
ServerName "AutoHost Server"
AuthUserFile $auth_user_file
AuthGroupFile $auth_group_file
ServerLog $log_file
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
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10',

    IfModules => {
      'mod_autohost.c' => {
        AutoHostEngine => 'on',
        AutoHostLog => $log_file,
        AutoHostConfig => "$test_root/conf.d/%0.conf",
      },

      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

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

      $client->login($user, $passwd);
      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
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

  my $config_file = "$tmpdir/autohost.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/autohost.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/autohost.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/autohost.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/autohost.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs("$tmpdir/home");
  mkpath($home_dir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_root = File::Spec->rel2abs($tmpdir);

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<IfModule mod_autohost.c>
  AutoHostEngine on
  AutoHostLog $log_file
  AutoHostConfig $test_root/conf.d/%0:%p.conf
  AutoHostPorts $port
</IfModule>
EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  mkpath("$tmpdir/conf.d");
  my $auto_config = File::Spec->rel2abs("$tmpdir/conf.d/127.0.0.1:$port.conf");
  if (open(my $fh, "> $auto_config")) {
    print $fh <<EOC;
ServerName "AutoHost Server"
AuthUserFile $auth_user_file
AuthGroupFile $auth_group_file
ServerLog $log_file
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);

      $client->login($user, $passwd);
      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  unlink($log_file);
}

sub autohost_extlog_var_p {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/autohost.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/autohost.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/autohost.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/autohost.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/autohost.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs("$tmpdir/home");
  mkpath($home_dir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_root = File::Spec->rel2abs($tmpdir);
  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10',

    LogFormat => 'custom "%p"',

    IfModules => {
      'mod_delay.c' => {
        DelayEngine => 'off',
      },
    },
  };

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<IfModule mod_autohost.c>
  AutoHostEngine on
  AutoHostLog $log_file
  AutoHostConfig $test_root/conf.d/%0:%p.conf
  AutoHostPorts $port
</IfModule>
EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  mkpath("$tmpdir/conf.d");
  my $auto_config = File::Spec->rel2abs("$tmpdir/conf.d/127.0.0.1:$port.conf");
  if (open(my $fh, "> $auto_config")) {
    print $fh <<EOC;
ServerName "AutoHost Server"
AuthUserFile $auth_user_file
AuthGroupFile $auth_group_file
ServerLog $log_file
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);
      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  # Now, read in the ExtendedLog, and see whether the %p variable was
  # properly written out.
  if (open(my $fh, "< $ext_log")) {
    my $line = <$fh>;
    chomp($line);
    close($fh);

    $self->assert($port eq $line,
      test_msg("Expected '$port', got '$line'"));

  } else {
    die("Can't read $ext_log: $!");
  }

  unlink($log_file);
}

sub autohost_global_config {
  my $self = shift;
  my $tmpdir = $self->{tmpdir};

  my $config_file = "$tmpdir/autohost.conf";
  my $pid_file = File::Spec->rel2abs("$tmpdir/autohost.pid");
  my $scoreboard_file = File::Spec->rel2abs("$tmpdir/autohost.scoreboard");

  my $log_file = File::Spec->rel2abs('tests.log');

  my $auth_user_file = File::Spec->rel2abs("$tmpdir/autohost.passwd");
  my $auth_group_file = File::Spec->rel2abs("$tmpdir/autohost.group");

  my $user = 'proftpd';
  my $passwd = 'test';
  my $group = 'ftpd';
  my $home_dir = File::Spec->rel2abs("$tmpdir/home");
  mkpath($home_dir);
  my $uid = 500;
  my $gid = 500;

  # Make sure that, if we're running as root, that the home directory has
  # permissions/privs set for the account we create
  if ($< == 0) {
    unless (chmod(0755, $home_dir)) {
      die("Can't set perms on $home_dir to 0755: $!");
    }

    unless (chown($uid, $gid, $home_dir)) {
      die("Can't set owner of $home_dir to $uid/$gid: $!");
    }
  }

  auth_user_write($auth_user_file, $user, $passwd, $uid, $gid, $home_dir,
    '/bin/bash');
  auth_group_write($auth_group_file, $group, $gid, $user);

  my $test_root = File::Spec->rel2abs($tmpdir);
  my $ext_log = File::Spec->rel2abs("$tmpdir/custom.log");

  my $config = {
    PidFile => $pid_file,
    ScoreboardFile => $scoreboard_file,
    SystemLog => $log_file,
    TraceLog => $log_file,
    Trace => 'DEFAULT:10',

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

  my ($port, $config_user, $config_group) = config_write($config_file, $config);

  if (open(my $fh, ">> $config_file")) {
    print $fh <<EOC;
<IfModule mod_autohost.c>
  AutoHostEngine on
  AutoHostLog $log_file
  AutoHostConfig $test_root/conf.d/%0:%p.conf
  AutoHostPorts $port
</IfModule>
EOC
    unless (close($fh)) {
      die("Can't write $config_file: $!");
    }

  } else {
    die("Can't open $config_file: $!");
  }

  mkpath("$tmpdir/conf.d");
  my $auto_config = File::Spec->rel2abs("$tmpdir/conf.d/127.0.0.1:$port.conf");
  if (open(my $fh, "> $auto_config")) {
    print $fh <<EOC;
ServerName "AutoHost Server"
AuthUserFile $auth_user_file
AuthGroupFile $auth_group_file
ServerLog $log_file
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
      my $client = ProFTPD::TestSuite::FTP->new('127.0.0.1', $port);
      $client->login($user, $passwd);
      $client->quit();
    };

    if ($@) {
      $ex = $@;
    }

    $wfh->print("done\n");
    $wfh->flush();

  } else {
    eval { server_wait($config_file, $rfh) };
    if ($@) {
      warn($@);
      exit 1;
    }

    exit 0;
  }

  # Stop server
  server_stop($pid_file);

  $self->assert_child_ok($pid);

  if ($ex) {
    die($ex);
  }

  # Now, read in the ExtendedLog, and see whether the %p variable was
  # properly written out.
  if (open(my $fh, "< $ext_log")) {
    my $line = <$fh>;
    chomp($line);
    close($fh);

    $self->assert($port eq $line,
      test_msg("Expected '$port', got '$line'"));

  } else {
    die("Can't read $ext_log: $!");
  }

  unlink($log_file);
}

1;
