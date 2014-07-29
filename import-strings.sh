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
while read -r line; do
    case "$line" in
	"#:"*)
	    echo >>$OUTFILE
	    # FIXME: If it was already in openconnect-strings.txt can we keep the
	    #   previous URL instead of using the latest commit, to reduce churn?
	    for src in ${line###: }; do
		echo "// ${GITWEB}${src%%:*}#l${src##*:}" >>$OUTFILE
	    done
	    real_strings=yes
	    ;;
	"msgid "*)
	    if [ "$real_strings" = "yes" ]; then
		echo -n "_(${line##msgid }" >>$OUTFILE
		in_msgid=yes
	    fi
	    ;;
	"msgstr "*|"")
	    if [ "$in_msgid" = "yes" ]; then
		in_msgid=no
		echo ");" >>$OUTFILE
	    fi
	    ;;
	*)
	    if [ "$in_msgid" = "yes" ]; then
		echo >>$OUTFILE
		echo -n "$line" >>$OUTFILE
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
NEWSHA=$(grep -v ^// openconnect-strings-$COMMIT.txt | sha1sum)
OLDSHA=$(grep -v ^// openconnect-strings.txt | sha1sum)
if [ "$NEWSHA" != "$OLDSHA" ]; then
    echo New strings
    mv openconnect-strings-$COMMIT.txt openconnect-strings.txt
else
    echo No new strings. Not changing openconnect-strings.txt
    rm openconnect-strings-$COMMIT.txt
fi

make -C po NetworkManager-openconnect.pot || exit 1
for a in po/*.po ; do
    echo Comparing $a...
    if [ -r $OPENCONNECT_DIR/$a ]; then
	msgattrib -F --no-fuzzy $OPENCONNECT_DIR/$a > $a.openconnect 2>/dev/null
	msgmerge -q -N -F $a -C $a.openconnect po/NetworkManager-openconnect.pot > $a.merged
	msgmerge -q -N -F $a po/NetworkManager-openconnect.pot > $a.unmerged
	if ! cmp $a.merged $a.unmerged; then
	    echo New changes for $a
	    mv $a.merged $a
	fi
	rm -f $a.openconnect $a.merged $a.unmerged
	msgattrib -F --no-fuzzy $a > $a.nmo
	msgmerge -q -N -F $OPENCONNECT_DIR/$a -C $a.nmo $OPENCONNECT_BUILD_DIR/po/openconnect.pot > $OPENCONNECT_DIR/$a.merged
	msgmerge -q -N -F $OPENCONNECT_DIR/$a $OPENCONNECT_BUILD_DIR/po/openconnect.pot > $OPENCONNECT_DIR/$a.unmerged
	if ! cmp $OPENCONNECT_DIR/$a.merged $OPENCONNECT_DIR/$a.unmerged; then
	    echo New changes for OpenConnect $a
	    mv $OPENCONNECT_DIR/$a.merged $OPENCONNECT_DIR/$a
	fi
	rm -f $OPENCONNECT_DIR/$a.merged $OPENCONNECT_DIR/$a.unmerged $a.nmo
    fi
done

