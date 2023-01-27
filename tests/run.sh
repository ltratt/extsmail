#! /bin/sh

set -euf

t=`mktemp -d`

mkdir -p $t/spool_dir/msgs
cat << EOF > $t/spool_dir/msgs/1
v1
6
4
-oem
3
-oi
2
-f
17
email@example.com
2
--
17
email@example.com
Date: Sat, 17 Sep 2022 08:55:41 +0100
From: email@example.com
To: email@example.com
Subject: test
Message-ID: <20220917075541.j42vuhpkgoc7qamo@example.com>
User-Agent: mutt
MIME-Version: 1.0
Content-Type: text/plain; charset=us-ascii
Content-Disposition: inline

test
EOF

cat << EOF > $t/extsmail.conf
spool_dir = "$t/spool_dir/"
EOF

echo -n "test_stderr_write... "
cat << EOF > $t/externals
group {
    external test {
        sendmail = "$t/test_stderr_write"
    }
}
EOF
chown :`id -g` $t/externals
chmod 700 $t/spool_dir
chmod 700 $t/spool_dir/msgs
cc -Wall -o $t/test_stderr_write test_stderr_write.c
../extsmaild -m batch -c $t/extsmail.conf -e $t/externals 2>&1 | grep -q "extsmaild.*test$"
jot 10000 >> $t/spool_dir/msgs/1
../extsmaild -m batch -c $t/extsmail.conf -e $t/externals 2>&1 | grep -q "extsmaild.*test$"
echo OK

echo -n "test_stderr_big_write... "
cat << EOF > $t/externals
group {
    external test {
        sendmail = "$t/test_stderr_big_write"
    }
}
EOF
chown :`id -g` $t/externals
cc -Wall -o $t/test_stderr_big_write test_stderr_big_write.c
sz=$(../extsmaild -m batch -c $t/extsmail.conf -e $t/externals 2>&1 | wc -c)
test $sz -gt 4096
echo OK

echo -n "test_read_all_fail... "
cat << EOF > $t/externals
group {
    external test {
        sendmail = "$t/test_read_all_fail"
    }
}
EOF
chown :`id -g` $t/externals
cc -Wall -o $t/test_read_all_fail test_read_all_fail.c
../extsmaild -m batch -c $t/extsmail.conf -e $t/externals 2>&1 | grep -q "^extsmaild: test: Received error 1 when executing"
echo OK

echo -n "read_all_stall... "
cat << EOF > $t/externals
group {
    external test {
        sendmail = "$t/test_read_all_stall"
    }
}
EOF
chown :`id -g` $t/externals
cc -Wall -o $t/test_read_all_stall test_read_all_stall.c
../extsmaild -m batch -c $t/extsmail.conf -e $t/externals 2>&1 | grep -q "^extsmaild: test: Timeout when executing"
echo OK

echo -n "read_all_stall (kill by signal)... "
# The next test is potentially flaky as it relies on timing.
t2=`mktemp`
../extsmaild -m batch -c $t/extsmail.conf -e $t/externals 2>$t2 &
pid=$!
sleep 3
# For reasons I don't understand, `pkill` on Linux only matches 15 character
# process names unless `-f` is specified.
pkill -SIGKILL -P $pid -f test_read_all_stall
wait $pid || true
# For reasons I don't understand, Linux can report the wrong signal number as
# being the cause of the signal's termination.
grep -q "extsmaild: test: Received signal 9" $t2
rm $t2
echo OK

echo -n "test_too_slow... "
cat << EOF > $t/externals
group {
    external test {
        sendmail = "$t/test_too_slow"
    }
}
EOF
chown :`id -g` $t/externals
cc -Wall -o $t/test_too_slow test_too_slow.c
../extsmaild -m batch -c $t/extsmail.conf -e $t/externals 2>&1 | grep -q "^extsmaild: test: .*Timeout$"
echo OK

echo -n "test_too_slow2... "
cat << EOF > $t/externals
group {
    external test {
        sendmail = "$t/test_too_slow2"
    }
}
EOF
chown :`id -g` $t/externals
cc -Wall -o $t/test_too_slow2 test_too_slow2.c
../extsmaild -m batch -c $t/extsmail.conf -e $t/externals 2>&1 | grep -q "^extsmaild: test: .*Timeout$"
echo OK

echo -n "test_slow_read... "
cat << EOF > $t/externals
group {
    external test {
        sendmail = "$t/test_slow_read"
    }
}
EOF
chown :`id -g` $t/externals
cc -Wall -o $t/test_slow_read test_slow_read.c
../extsmaild -m batch -c $t/extsmail.conf -e $t/externals
echo OK

rm -rf $t
