#!/bin/sh

if [ "$OPENCONNECT_DIR" = "" ]; then
    OPENCONNECT_DIR=../openconnect
fi
if [ "$OPENCONNECT_BUILD_DIR"  = "" ]; then
    OPENCONNECT_BUILD_DIR="$OPENCONNECT_DIR"
fi

# The openconnect.pot file is made available by a cron job on this server, along
# with the project's web site which is also held in the git repository. There's
# race condition here, if the server is updating as we run this script. But it's
# unlikely that the string in question would move far, so it should be good enough.
COMMIT="$(cd $OPENCONNECT_DIR && git rev-parse HEAD)"
if ! echo $COMMIT | egrep -q "[a-f0-9]{40}"; then
    echo "Error: Failed to fetch commit ID from $OPENCONNECT_DIR"
    exit 1
fi

pushd $OPENCONNECT_BUILD_DIR
make po/openconnect.pot || exit 1
popd

COMMIT=$(echo $COMMIT | cut -c1-10)
GITWEB=http://git.infradead.org/users/dwmw2/openconnect.git/blob/${COMMIT}:/
OUTFILE=openconnect-strings-$COMMIT.txt

cat >$OUTFILE <<EOF
This file contains strings from the OpenConnect VPN client, found at
http://www.infradead.org/openconnect/ and browseable in gitweb at
http://git.infradead.org/users/dwmw2/openconnect.git

We do this because NetworkManager-openconnect authentication dialog
uses a lot of strings from libopenconnect, which also need to be
translated too if the user is to have a fully localised experience.

For translators looking to see source comments in their original context
in order to translate them properly, the URLs by each one will give a
link to the original source code.
EOF

cat $OPENCONNECT_BUILD_DIR/po/openconnect.pot |
while read -r a b; do
    case "$a" in
	"#:")
	    echo >>$OUTFILE
	    for src in $b; do
		echo "// ${GITWEB}${src%%:*}#l${src##*:}" >>$OUTFILE
	    done
	    real_strings=yes
	    ;;
	"msgid")
	    if [ "$real_strings" = "yes" ]; then
		echo -n "_($b" >>$OUTFILE
		in_msgid=yes
	    fi
	    ;;
	"msgstr"|"")
	    if [ "$in_msgid" = "yes" ]; then
		in_msgid=no
		echo ");" >>$OUTFILE
	    fi
	    ;;
	*)
	    if [ "$in_msgid" = "yes" ]; then
		echo >>$OUTFILE
		echo -n "$a $b" >>$OUTFILE
	    fi
	    ;;
   esac
done

MESSAGES=$(grep -c "^_(" openconnect-strings-$COMMIT.txt)

echo "Got $MESSAGES messages from openconnect upstream"

if [ "$MESSAGES" -lt 100 ]; then
    echo "Fewer than 100 messages? Something went wrong"
    rm openconnect-strings-$COMMIT.txt
    exit 1
fi

mv openconnect-strings-$COMMIT.txt openconnect-strings.txt

make -C po NetworkManager-openconnect.pot || exit 1
for a in po/*.po ; do
    if [ -r $OPENCONNECT_DIR/$a ]; then
	msgmerge -N -F $a -C $OPENCONNECT_DIR/$a po/NetworkManager-openconnect.pot > $a.new && mv $a.new $a
	msgmerge -N -F $OPENCONNECT_DIR/$a -C $a $OPENCONNECT_BUILD_DIR/po/openconnect.pot > $OPENCONNECT_DIR/$a.new && mv $OPENCONNECT_DIR/$a.new $OPENCONNECT_DIR/$a
    fi
done

