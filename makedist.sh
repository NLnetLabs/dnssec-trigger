# makedist.sh: makes distributable tarball.

# Abort script on unexpected errors.
set -e

# Remember the current working directory.
cwd=`pwd`

# Utility functions.
usage () {
    cat >&2 <<EOF
Usage $0: [-h] [-s] [-d SVN_root] [-l ldns_path] [-w ...args...]
Generate a distribution tar file for dnssec-trigger.

    -h           This usage information.
    -s           Build a snapshot distribution file.  The current date is
                 automatically appended to the current version number.
    -rc <nr>     Build a release candidate, the given string will be added
                 to the version number 
                 (which will then be dnssec-trigger-<version>rc<number>)
    -d SVN_root  Retrieve the source from the specified repository.
                 Detected from svn working copy if not specified.
    -l ldnsdir   Directory where ldns resides. Detected from Makefile.
    -wssl openssl.xx.tar.gz Also build openssl from tarball for windows dist.
    -wldns ldns.xx.tar.gz Also build libldns from tarball for windows dist.
    -wunbound unbound.xx.tar.gz Also build unbound from tarball for windows dist.
        The windows subbuilds are cached in ./..tar.gz-win32-store-dir, remove
	that dir to rebuild the package.
    -w ...       Build windows binary dist. last args passed to configure.
    -m ...       Build mac binary dist. last args passed to configure.
    		 use -wldns and -wunbound with it.
EOF
    exit 1
}

info () {
    echo "$0: info: $1"
}

error () {
    echo "$0: error: $1" >&2
    exit 1
}

question () {
    printf "%s (y/n) " "$*"
    read answer
    case "$answer" in
        [Yy]|[Yy][Ee][Ss])
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

replace_text () {
    (cp "$1" "$1".orig && \
        sed -e "s/$2/$3/g" < "$1".orig > "$1" && \
        rm "$1".orig) || error_cleanup "Replacement for $1 failed."
}

# Only use cleanup and error_cleanup after generating the temporary
# working directory.
cleanup () {
    info "Deleting temporary working directory."
    cd $cwd && rm -rf $temp_dir
}

error_cleanup () {
    echo "$0: error: $1" >&2
    cleanup
    exit 1
}

check_svn_root () {
    # Check if SVNROOT is specified.
    if [ -z "$SVNROOT" ]; then
	if svn info 2>&1 | grep "not a working copy" >/dev/null; then
		if test -z "$SVNROOT"; then
			error "SVNROOT must be specified (using -d)"
		fi
	else
		eval `svn info | grep 'URL:' | sed -e 's/URL: /url=/' | head -1`
		SVNROOT="$url"
	fi
    fi
}

create_temp_dir () {
    # Creating temp directory
    info "Creating temporary working directory"
    temp_dir=`mktemp -d makedist-XXXXXX`
    info "Directory '$temp_dir' created."
    cd $temp_dir
}

# pass filename as $1 arg.
# creates file.sha1 and file.sha256
storehash () {
    case $OSTYPE in
        linux*)
                sha=`sha1sum $1 |  awk '{ print $1 }'`
                sha256=`sha256sum $1 |  awk '{ print $1 }'`
                ;;
        freebsd*)
                sha=`sha1 $1 |  awk '{ print $5 }'`
                sha256=`sha256 $1 |  awk '{ print $5 }'`
                ;;
	[dD]arwin*)
                sha=`shasum -a 1 $1 |  awk '{ print $1 }'`
                sha256=`shasum -a 256 $1 |  awk '{ print $1 }'`
		;;
	*)
		# in case $OSTYPE is gone.
		case `uname` in
		Linux*)
		  sha=`sha1sum $1 |  awk '{ print $1 }'`
		  sha256=`sha256sum $1 |  awk '{ print $1 }'`
		  ;;
		FreeBSD*)
		  sha=`sha1 $1 |  awk '{ print $5 }'`
		  sha256=`sha256 $1 |  awk '{ print $5 }'`
		  ;;
		[dD]arwin*)
		  sha=`shasum -a 1 $1 |  awk '{ print $1 }'`
		  sha256=`shasum -a 256 $1 |  awk '{ print $1 }'`
		  ;;
		*)
		  sha=`sha1sum $1 |  awk '{ print $1 }'`
		  sha256=`sha256sum $1 |  awk '{ print $1 }'`
		  ;;
		esac
                ;;
    esac
    echo $sha > $1.sha1
    echo $sha256 > $1.sha256
    echo "hash of $1.{sha1,sha256}"
    echo "sha1 $sha"
    echo "sha256 $sha256"
}


SNAPSHOT="no"
RC="no"
LDNSDIR=""
DOWIN="no"
WINSSL=""
WINLDNS=""
WINUNBOUND=""
DOMAC="no"

# Parse the command line arguments.
while [ "$1" ]; do
    case "$1" in
        "-h")
            usage
            ;;
        "-d")
            SVNROOT="$2"
            shift
            ;;
        "-s")
            SNAPSHOT="yes"
            ;;
        "-wldns")
            WINLDNS="$2"
            shift
            ;;
        "-wunbound")
            WINUNBOUND="$2"
            shift
            ;;
        "-wssl")
            WINSSL="$2"
            shift
            ;;
        "-w")
            DOWIN="yes"
	    if test -n "$WINLDNS"; then
	    	WINLDNS_STORE_DIR=`pwd`/`basename $WINLDNS`"-win32-store-dir"
	    fi
	    if test -n "$WINUNBOUND"; then
	    	WINUNBOUND_STORE_DIR=`pwd`/`basename $WINUNBOUND`"-win32-store-dir"
	    fi
	    if test -n "$WINSSL"; then
	    	WINSSL_STORE_DIR=`pwd`/`basename $WINSSL`"-win32-store-dir"
	    fi
            shift
            break
            ;;
        "-m")
            DOMAC="yes"
	    if test -n "$WINLDNS"; then
	    	WINLDNS_STORE_DIR=`pwd`/`basename $WINLDNS`"-osx-store-dir"
	    fi
	    if test -n "$WINUNBOUND"; then
	    	WINUNBOUND_STORE_DIR=`pwd`/`basename $WINUNBOUND`"-osx-store-dir"
	    fi
	    if test -n "$WINSSL"; then
	    	WINSSL_STORE_DIR=`pwd`/`basename $WINSSL`"-osx-store-dir"
	    fi
            shift
            break
            ;;
        "-l")
            LDNSDIR="$2"
            shift
            ;;
        "-rc")
            RC="$2"
            shift
            ;;
        *)
            error "Unrecognized argument -- $1"
            ;;
    esac
    shift
done

change_configure_version() {
    version=`./configure --version | head -1 | awk '{ print $3 }'` \
        || error_cleanup "Cannot determine version number."
    if [ "$RC" != "no" -o "$SNAPSHOT" != "no" ]; then
        if [ "$RC" != "no" ]; then
                version2=`echo $version | sed -e 's/rc.*$//' -e 's/_20.*$//'`
                version2=`echo $version2 | sed -e 's/rc.*//'`"rc$RC"
        fi
        if [ "$SNAPSHOT" != "no" ]; then
                version2=`echo $version | sed -e 's/rc.*$//' -e 's/_20.*$//'`
                version2="${version2}_`date +%Y%m%d`"
        fi
        replace_text "configure.ac" "AC_INIT(dnssec-trigger, $version" "AC_INIT(dnssec-trigger, $version2"
        version="$version2"
        info "Rebuilding configure script (autoconf) snapshot."
        autoconf || error_cleanup "Autoconf failed."
        autoheader || error_cleanup "Autoheader failed."
        rm -r autom4te* || echo "ignored"
    fi
}

if [ "$DOWIN" = "yes" ]; then
    # detect crosscompile, from Fedora13 at this point.
    if test "`uname`" = "Linux"; then
        info "Crosscompile windows dist"
        cross="yes"
        configure="mingw32-configure"
	strip="i686-w64-mingw32-strip"
        makensis="makensis"     # from mingw32-nsis package
        # flags for crosscompiled dependency libraries
        cross_flag=""

        check_svn_root
        create_temp_dir

        # crosscompile openssl for windows.
        if test -n "$WINSSL" -a -d "$WINSSL_STORE_DIR"; then
		info "Cross compile $WINSSL have $WINSSL_STORE_DIR"
		sslinstall="$WINSSL_STORE_DIR"
                cross_flag="$cross_flag --with-ssl=$sslinstall"
	elif test -n "$WINSSL"; then
                info "Cross compile $WINSSL"
                info "winssl tar unpack"
                (cd ..; gzip -cd $WINSSL) | tar xf - || error_cleanup "tar unpack of $WINSSL failed"
		sslinstall="$WINSSL_STORE_DIR"
                cd openssl-* || error_cleanup "no openssl-X dir in tarball"
                # configure for crosscompile, without CAPI because it fails
                # cross-compilation and it is not used anyway
                sslflags="shared --cross-compile-prefix=i686-w64-mingw32- -DOPENSSL_NO_CAPIENG mingw"
                info "winssl: Configure $sslflags"
                ./Configure --prefix="$sslinstall" $sslflags || error_cleanup "OpenSSL Configure failed"
                info "winssl: make"
                make || error_cleanup "OpenSSL crosscompile failed"
                # only install sw not docs, which take a long time.
                info "winssl: make install_sw"
                make install_sw || error_cleanup "OpenSSL install failed"
                cross_flag="$cross_flag --with-ssl=$sslinstall"
                cd ..
        fi

	ldnsdir=""
        if test -n "$WINLDNS" -a -d "$WINLDNS_STORE_DIR"; then
		info "Cross compile $WINLDNS have $WINLDNS_STORE_DIR"
		ldnsdir="$WINLDNS_STORE_DIR"
                cross_flag="$cross_flag --with-ldns=$WINLDNS_STORE_DIR"
        elif test -n "$WINLDNS"; then
                info "Cross compile $WINLDNS"
                info "ldns tar unpack"
                (cd ..; gzip -cd $WINLDNS) | tar xf - || error_cleanup "tar unpack of $WINLDNS failed"
		mv ldns-* $WINLDNS_STORE_DIR || error_cleanup "cannot move or no ldns-X dir in tarball"
		backdir=`pwd`
		cd $WINLDNS_STORE_DIR || error_cleanup "cannot cd ldnsdir"
                # we can use the cross_flag with openssl in it
                info "ldns: Configure $cross_flag"
                mingw32-configure  $cross_flag || error_cleanup "ldns configure failed"
                info "ldns: make"
                make || error_cleanup "ldns crosscompile failed"
    		$strip lib/*.dll || error_cleanup "cannot strip ldns dll"
                # use from the build directory.
		ldnsdir=`pwd`
                cross_flag="$cross_flag --with-ldns=`pwd`"
		cd $backdir
        fi

	unbounddir=""
        if test -n "$WINUNBOUND" -a -d "$WINUNBOUND_STORE_DIR"; then
		info "Cross compile $WINUNBOUND have $WINUNBOUND_STORE_DIR"
		unbounddir="$WINUNBOUND_STORE_DIR"
        elif test -n "$WINUNBOUND"; then
                info "Cross compile $WINUNBOUND"
                info "unbound tar unpack"
                (cd ..; gzip -cd $WINUNBOUND) | tar xf - || error_cleanup "tar unpack of $WINUNBOUND failed"
		mv unbound-* $WINUNBOUND_STORE_DIR || error_cleanup "cannot move or no unbound-X dir in tarball"
		backdir=`pwd`
		cd $WINUNBOUND_STORE_DIR || error_cleanup "cannot cd unbounddir"
                # we can use the cross_flag with openssl and ldns in it
                info "unbound: Configure $cross_flag"
		# enable allsymbols because unbound-anchor wants wsa_strerror
		# from util/log.c
                mingw32-configure --enable-allsymbols --enable-debug $cross_flag || error_cleanup "unbound configure failed"
                info "unbound: make"
                make || error_cleanup "unbound crosscompile failed"
		make strip || error_cleanup "unbound make strip failed"
		$strip .libs/*.dll .libs/*.exe || error_cleanup "cannot strip"
                # use from the build directory.
		unbounddir=`pwd`
		cd $backdir
	fi

        info "Exporting source from SVN."
        svn export "$SVNROOT" dnssec-trigger || error_cleanup "SVN command failed"
        cd dnssec-trigger || error_cleanup "Not exported correctly from SVN"

        # on a re-configure the cache may no longer be valid...
        if test -f mingw32-config.cache; then rm mingw32-config.cache; fi
    else
        cross="no"      # mingw and msys
        cross_flag=""
        configure="./configure"
        strip="strip"
        makensis="c:/Program Files/NSIS/makensis.exe" # http://nsis.sf.net
    fi

    # version gets compiled into source, edit the configure to set  it
    change_configure_version
    # procedure for making installer on mingw. 
    info "Creating windows dist dnssec-trigger $version"
    info "Calling configure"
    echo "$configure"' --enable-debug '"$* $cross_flag"
    destdir='C:\Program Files\DnssecTrigger'
    $configure --enable-debug --with-keydir="$destdir" --with-uidir="$destdir" \
    	--with-configfile="$destdir\\dnssec-trigger.conf" --with-pidfile="$destdir\\dnssec-trigger.pid" $* $cross_flag \
    	|| error_cleanup "Could not configure"
    info "Calling make"
    make || error_cleanup "Could not make"
    info "Make complete"

    info "dnssec-trigger version: $version"
    #file="dnssec-trigger-$version.zip"
    #rm -f $file
    #info "Creating $file"
    make strip || error_cleanup "could not strip"
    mkdir tmp.collect
    cd tmp.collect
    # files and crosscompile
    # DLLs linked with the panel on windows (ship DLLs:)
    # libldns, libcrypto, libssl
    # openssl dlls
    findpath="$sslinstall/bin $sslinstall/lib/engines $ldnsdir/lib $unbounddir/.libs /usr/bin /usr/i686-w64-mingw32/sys-root/mingw/bin /usr/i686-w64-mingw32/sys-root/mingw/lib/engines"
    # find a dll and copy it to local dir. $1 searchpath $2 name
    function find_dll () {
	    for i in $1; do
		    if test -f "$i/$2"; then
			    echo "dll $i/$2"
			    cp $i/$2 .
			    return 0
		    fi
	    done
	    echo "no $2"
	    return 1
    }
    find_dll "$findpath" "libeay32.dll" || error_cleanup "no crypto dll"
    find_dll "$findpath" "ssleay32.dll" || error_cleanup "no ssl dll"
    find_dll "$findpath" "gosteay32.dll" || echo "*** WARNING NO GOST DLL ***"
    find_dll "$findpath" "libldns-1.dll" || error_cleanup "no ldns dll"
    find_dll "$findpath" "libexpat-1.dll" || error_cleanup "no expat dll"
    find_dll "$findpath" "libunbound-2.dll" || error_cleanup "no unbound dll"
    find_dll "$findpath" "libgcc_s_sjlj-1.dll" || error_cleanup "no libgcc_s_sjlj dll"
    find_dll "$findpath" "libwinpthread-1.dll" || error_cleanup "no libwinpthread-1.dll"
    info "put cr's in readme"
    sed -e 's/$/\r/' < ../README > README.txt
    info "copy unbound exe"
    cp $unbounddir/.libs/unbound.exe . || error_cleanup "cannot get unbound"
    cp $unbounddir/.libs/unbound-control.exe . || error_cleanup "cannot get unbound"
    cp $unbounddir/.libs/unbound-anchor.exe . || error_cleanup "cannot get unbound"
    cp $unbounddir/.libs/unbound-checkconf.exe . || error_cleanup "cannot get unbound"
    cp $unbounddir/.libs/unbound-host.exe . || error_cleanup "cannot get unbound"
    cp $unbounddir/doc/example.conf unbound.conf || error_cleanup "cannot get unbound example.conf"

    cp ../winrc/proc.dll .
    #cp ../example.conf example.conf
    #cp ../panel/pui.xml ../panel/status-icon.png ../panel/status-icon-alert.png .
    #cp ../dnssec-triggerd.exe ../dnssec-trigger-control.exe ../dnssec-trigger-panel.exe ../dnssec-trigger-keygen.exe .
    # zipfile
    #zip ../$file README LICENSE example.conf dnssec-triggerd.exe dnssec-trigger-control.exe dnssec-trigger-panel.exe dnssec-trigger-keygen.exe pui.xml status-icon.png status-icon-alert.png *.dll
    #info "Testing $file"
    #(cd .. ; zip -T $file )
    # installer
    info "Creating installer"
    quadversion=`cat ../config.h | grep RSRC_PACKAGE_VERSION | sed -e 's/#define RSRC_PACKAGE_VERSION //' -e 's/,/\\./g'`
    cat ../winrc/setup.nsi | sed -e 's/define VERSION.*$/define VERSION "'$version'"/' -e 's/define QUADVERSION.*$/define QUADVERSION "'$quadversion'"/' > ../winrc/setup_ed.nsi
    "$makensis" ../winrc/setup_ed.nsi
    info "Created installer"
    cd ..
    rm -rf tmp.collect
    mv winrc/dnssec_trigger_setup_$version.exe .
    if test "$cross" = "yes"; then
            mv dnssec_trigger_setup_$version.exe $cwd/.
            #mv $file $cwd/.
            cleanup
    fi
    storehash dnssec_trigger_setup_$version.exe
    ls -lG dnssec_trigger_setup_$version.exe
    #ls -lG $file
    info "Done"
    exit 0
fi  # end of DOWIN

if [ "$DOMAC" = "yes" ]; then
    info "MacOSX compile and package"
    check_svn_root
    create_temp_dir
    destdir="osx/pkg/DEST"
    cnf_flag=""
    ldns_flag="--disable-gost --disable-static"
    unbound_flag="--sysconfdir=/usr/local/etc --with-libexpat=/usr --enable-allsymbols --disable-gost --disable-static --disable-flto"
    dnssectrigger_flag="--sysconfdir=/usr/local/etc/dnssec-trigger --with-keydir=/usr/local/etc/dnssec-trigger --with-unbound-control=/usr/local/sbin/unbound-control"

    if test `uname` != "Darwin"; then
	error_cleanup "Must make mac package on OSX"
    fi

    info "Exporting source from SVN."
    svn export "$SVNROOT" dnssec-trigger || error_cleanup "SVN command failed"
    rm -rf "dnssec-trigger/$destdir"
    mkdir -p dnssec-trigger/$destdir || error_cleanup "cannot create destdir"

    # openssl
    if test -n "$WINSSL" -a -d "$WINSSL_STORE_DIR"; then
	info "Compile $WINSSL have $WINSSL_STORE_DIR"
	sslinstall="$WINSSL_STORE_DIR"
	cnf_flag="$cnf_flag --with-ssl=$sslinstall"
    elif test -n "$WINSSL"; then
	info "Cross compile $WINSSL"
	info "winssl tar unpack"
	(cd ..; gzip -cd $WINSSL) | tar xf - || error_cleanup "tar unpack of $WINSSL failed"
	sslinstall="$WINSSL_STORE_DIR"
	cd openssl-* || error_cleanup "no openssl-X dir in tarball"
	# configure for OSX, must call Configure directly because ./config
	# fails.  Only build static, because dynamic is trouble with
	# user-installed dylibs and apples dylibs.  This causes the linker
	# to pull in the static libraries for crypto and ssl
	# configure for crosscompile, without CAPI because it fails
	# cross-compilation and it is not used anyway
	sslflags="no-shared no-asm darwin64-x86_64-cc"
	info "winssl: Configure $sslflags"
	./Configure --prefix="$sslinstall" $sslflags || error_cleanup "OpenSSL Configure failed"
	info "winssl: make"
	make || error_cleanup "OpenSSL crosscompile failed"
	# only install sw not docs, which take a long time.
	info "winssl: make install_sw"
	make install_sw || error_cleanup "OpenSSL install failed"
	cnf_flag="$cnf_flag --with-ssl=$sslinstall"
	cd ..
    fi

    # ldns
    ldnsdir=""
    if test -n "$WINLDNS" -a -d "$WINLDNS_STORE_DIR"; then
	info "compile $WINLDNS have $WINLDNS_STORE_DIR"
	ldnsdir="$WINLDNS_STORE_DIR"
	cnf_flag="$cnf_flag --with-ldns=$WINLDNS_STORE_DIR"
    elif test -n "$WINLDNS"; then
	info "compile $WINLDNS"
	info "ldns tar unpack"
	(cd ..; gzip -cd $WINLDNS) | tar xf - || error_cleanup "tar unpack of $WINLDNS failed"
	mv ldns-* $WINLDNS_STORE_DIR || error_cleanup "cannot move or no ldns-X dir in tarball"
	backdir=`pwd`
	cd $WINLDNS_STORE_DIR || error_cleanup "cannot cd ldnsdir"
	info "ldns: Configure $cnf_flag $ldns_flag"
	./configure $cnf_flag $ldns_flag || error_cleanup "ldns configure failed"
	info "ldns: make"
	make || error_cleanup "ldns compile failed"
	ldnsdir=`pwd`
	cnf_flag="$cnf_flag --with-ldns=$ldnsdir"
	cd $backdir
    fi
    if test -n "$WINLDNS"; then
	backdir=`pwd`
	cd $ldnsdir
	info "ldns make install"
	make install DESTDIR=$backdir/dnssec-trigger/$destdir || error_cleanup "cannot make install ldns"
	cd $backdir
    fi

    # unbound
    unbounddir=""
    if test -n "$WINUNBOUND" -a -d "$WINUNBOUND_STORE_DIR"; then
	    info "compile $WINUNBOUND have $WINUNBOUND_STORE_DIR"
	    unbounddir="$WINUNBOUND_STORE_DIR"
    elif test -n "$WINUNBOUND"; then
    	info "compile $WINUNBOUND"
	info "unbound tar unpack"
	(cd ..; gzip -cd $WINUNBOUND) | tar xf - || error_cleanup "tar unpack of $WINUNBOUND failed"
	mv unbound-* $WINUNBOUND_STORE_DIR || error_cleanup "cannot move or no unbound-X dir in tarball"
	backdir=`pwd`
	cd $WINUNBOUND_STORE_DIR || error_cleanup "cannot cd unbounddir"
	info "unbound: Configure $cnf_flag $unbound_flag"
	./configure $cnf_flag $unbound_flag || error_cleanup "unbound configure failed"
	info "unbound: make"
	make || error_cleanup "unbound compile failed"
	make strip || error_cleanup "unbound make strip failed"
	# use from the build directory.
	unbounddir=`pwd`
	cd $backdir
    fi
    if test -n "$WINUNBOUND"; then
	backdir=`pwd`
	cd $unbounddir
	info "unbound make install"
	make install DESTDIR=$backdir/dnssec-trigger/$destdir || error_cleanup "cannot make install unbound"
	cd $backdir
    fi

    # dnssec-trigger
    cd dnssec-trigger || error_cleanup "Not exported correctly from SVN"

    # version gets compiled into source, edit the configure to set  it
    change_configure_version
    info "Creating mac dist dnssec-trigger $version"
    info "Calling configure $cnf_flag $dnssectrigger_flag $*"
    ./configure $cnf_flag $dnssectrigger_flag $* || error_cleanup "Could not configure"
    info "Calling make"
    make || error_cleanup "Could not make"
    make strip || error_cleanup "make strip failed"
    info "make install"
    make install DESTDIR=$destdir || error_cleanup "make install failed"
    
    mv $destdir/usr/local/etc/unbound/unbound.conf $destdir/usr/local/etc/unbound/unbound.conf-default
    mv $destdir/usr/local/etc/dnssec-trigger/dnssec-trigger.conf $destdir/usr/local/etc/dnssec-trigger/dnssec-trigger.conf-default

    info "dnssec-trigger version: $version"
    rm -f osx/pkg/makepackage_ed
    sed -e 's/^VERSION=/VERSION='"$version"'/' < osx/pkg/makepackage > osx/pkg/makepackage_ed || error_cleanup "Could not edit makepackage"
    info "running makepackage"
    (cd osx/pkg; ./makepackage) || error_cleanup "makepackage failed"

    # see tar gz for debug
    mv osx/pkg/*.tar.gz ../../.
    # the dmg package
    mv osx/pkg/dnssec*$version*.dmg ../../dnssectrigger-$version.dmg
    cd ..
    cleanup
    storehash dnssectrigger-$version.dmg
    ls -lhG dnssectrigger-$version.dmg

    info "Done"
    exit 0
fi # end of DOMAC

check_svn_root

# Start the packaging process.
info "SVNROOT  is $SVNROOT"
info "SNAPSHOT is $SNAPSHOT"

create_temp_dir

info "Exporting source from SVN."
svn export "$SVNROOT" dnssec-trigger || error_cleanup "SVN command failed"

cd dnssec-trigger || error_cleanup "Not exported correctly from SVN"

find . -name .c-mode-rc.el -exec rm {} \;
find . -name .cvsignore -exec rm {} \;
rm makedist.sh || error_cleanup "Failed to remove makedist.sh."
rm -rf osx/pkg || error_cleanup "Failed to remove osx/pkg"

info "Determining version."
version=`./configure --version | head -1 | awk '{ print $3 }'` || \
    error_cleanup "Cannot determine version number."

info "version: $version"

RECONFIGURE="no"

if [ "$RC" != "no" ]; then
    info "Building release candidate $RC."
    version2="${version}rc$RC"
    info "Version number: $version2"

    replace_text "configure.ac" "AC_INIT(dnssec-trigger, $version" "AC_INIT(dnssec-trigger, $version2"
    version="$version2"
    RECONFIGURE="yes"
fi

if [ "$SNAPSHOT" = "yes" ]; then
    info "Building snapshot."
    version2="${version}_`date +%Y%m%d`"
    info "Snapshot version number: $version2"

    replace_text "configure.ac" "AC_INIT(dnssec-trigger, $version" "AC_INIT(dnssec-trigger, $version2"
    version="$version2"
    RECONFIGURE="yes"
fi

if [ "$RECONFIGURE" = "yes" ]; then
    info "Rebuilding configure script (autoconf) snapshot."
    autoconf || error_cleanup "Autoconf failed."
    autoheader || error_cleanup "Autoheader failed."
    rm -r autom4te* || error_cleanup "Failed to remove autoconf cache directory."
fi

# fix date at date of tarball release.
replace_text "dnssec-trigger.8.in" "[@]DATE[@]" "`date +%F -r Changelog`"

info "Renaming directory to dnssec-trigger-$version."
cd ..
mv dnssec-trigger dnssec-trigger-$version || error_cleanup "Failed to rename directory."

tarfile="dnssec-trigger-$version.tar.gz"

if [ -f ../$tarfile ]; then
    (question "The file ../$tarfile already exists.  Overwrite?" \
        && rm -f ../$tarfile) || error_cleanup "User abort."
fi

info "Creating tar dnssec-trigger-$version.tar.gz"
tar czf ../$tarfile dnssec-trigger-$version || error_cleanup "Failed to create tar file."

cleanup

echo "create dnssec-trigger-$version.tar.gz.asc with:"
echo "    gpg --armor --detach-sign dnssec-trigger-$version.tar.gz"
storehash $tarfile

info "dnssec-trigger distribution created successfully."

