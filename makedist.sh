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
    -w ...       Build windows binary dist. last args passed to configure.
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
        if test -f .svn/entries; then
              eval `svn info | grep 'URL:' | sed -e 's/URL: /url=/' | head -1`
              SVNROOT="$url"
        fi
        if test -z "$SVNROOT"; then
            error "SVNROOT must be specified (using -d)"
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


SNAPSHOT="no"
RC="no"
LDNSDIR=""
DOWIN="no"
WINSSL=""
WINLDNS=""

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
        "-wssl")
            WINSSL="$2"
            shift
            ;;
        "-w")
            DOWIN="yes"
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

if [ "$DOWIN" = "yes" ]; then
    # detect crosscompile, from Fedora13 at this point.
    if test "`uname`" = "Linux"; then
        info "Crosscompile windows dist"
        cross="yes"
        configure="mingw32-configure"
        strip="i686-pc-mingw32-strip"
        makensis="makensis"     # from mingw32-nsis package
        # flags for crosscompiled dependency libraries
        cross_flag=""

        check_svn_root
        create_temp_dir

        # crosscompile openssl for windows.
        if test -n "$WINSSL"; then
                info "Cross compile $WINSSL"
                info "winssl tar unpack"
                (cd ..; gzip -cd $WINSSL) | tar xf - || error_cleanup "tar unpack of $WINSSL failed"
                sslinstall="`pwd`/sslinstall"
                cd openssl-* || error_cleanup "no openssl-X dir in tarball"
                # configure for crosscompile, without CAPI because it fails
                # cross-compilation and it is not used anyway
                sslflags="shared --cross-compile-prefix=i686-pc-mingw32- -DOPENSSL_NO_CAPIENG mingw"
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
        if test -n "$WINLDNS"; then
                info "Cross compile $WINLDNS"
                info "ldns tar unpack"
                (cd ..; gzip -cd $WINLDNS) | tar xf - || error_cleanup "tar unpack of $WINLDNS failed"
                cd ldns-* || error_cleanup "no ldns-X dir in tarball"
                # we can use the cross_flag with openssl in it
                info "ldns: Configure $cross_flag"
                mingw32-configure  $cross_flag || error_cleanup "ldns configure failed"
                info "ldns: make"
                make || error_cleanup "ldns crosscompile failed"
                # use from the build directory.
		ldnsdir=`pwd`
                cross_flag="$cross_flag --with-ldns=`pwd`"
                cd ..
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
    # TODO files and crosscompile
    # DLLs linked with the panel on windows (ship DLLs:)
    # libldns, libcrypto, libssl
    # openssl dlls
    findpath="../../sslinstall/bin ../../sslinstall/lib/engines $ldnsdir/lib /usr/bin /usr/i686-pc-mingw32/sys-root/mingw/bin /usr/i686-pc-mingw32/sys-root/mingw/lib/engines"
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
    # these dlls have different names.
    find_dll "$findpath" "intl.dll" || \
    	find_dll "$findpath" "libintl-8.dll" || \
	error_cleanup "no intl dll"
    find_dll "$findpath" "freetype6.dll" || \
    	find_dll "$findpath" "libfreetype-6.dll" \
    	|| error_cleanup "no freetype dll"
    # these dlls are not always present (include if they are)
    find_dll "$findpath" "libiconv-2.dll"
    find_dll "$findpath" "libpixman-1-0.dll"

    for j in libgdk-win32-2.0-0.dll libgdk_pixbuf-2.0-0.dll libglib-2.0-0.dll \
	libgobject-2.0-0.dll libgthread-2.0-0.dll libgtk-win32-2.0-0.dll \
	libatk-1.0-0.dll libcairo-2.dll libgio-2.0-0.dll libgmodule-2.0-0.dll \
	libpango-1.0-0.dll libpangocairo-1.0-0.dll libpangowin32-1.0-0.dll \
	libpng14-14.dll zlib1.dll libpangoft2-1.0-0.dll libfontconfig-1.dll \
	libexpat-1.dll; do
	find_dll "$findpath" "$j" || error_cleanup "no $j found"
    done

    pixloadpath="/usr/lib/gdk-pixbuf-2.0/2.10.0/loaders /opt/gtk/lib/gdk-pixbuf-2.0/2.10.0/loaders /usr/i686-pc-mingw32/sys-root/mingw/lib/gdk-pixbuf-2.0/2.10.0/loaders"
    echo "# GdkPixbuf Image Loader Modules file" > loaders.cache
    find_dll "$pixloadpath" "libpixbufloader-png.dll" &&
    	cat >>loaders.cache <<EOF
"libpixbufloader-png.dll"
"png" 5 "gdk-pixbuf" "The PNG image format" "LGPL"
"image/png" ""
"png" ""
"\211PNG\r\n\032\n" "" 100
EOF
    find_dll "$pixloadpath" "libpixbufloader-gdip-wmf.dll" &&
    	cat >>loaders.cache <<EOF
"libpixbufloader-gdip-wmf.dll"
"wmf" 4 "gdk-pixbuf" "Het WMF-bestandsformaat" "LGPL"
"image/x-wmf" ""
"wmf" "apm" ""
"\327\315\306\232" "" 100
"\001" "" 100
EOF
    find_dll "$pixloadpath" "libpixbufloader-gdip-ico.dll" &&
    	cat >>loaders.cache <<EOF
"libpixbufloader-gdip-ico.dll"
"ico" 4 "gdk-pixbuf" "Het ICO-bestandsformaat" "LGPL"
"image/x-icon" "image/x-ico" ""
"ico" "cur" ""
"  \001   " "zz znz" 100
"  \002   " "zz znz" 100
EOF
    find_dll "$pixloadpath" "libpixbufloader-gdip-bmp.dll" &&
    	cat >>loaders.cache <<EOF
"libpixbufloader-gdip-bmp.dll"
"bmp" 5 "gdk-pixbuf" "Het BMP-bestandsformaat" "LGPL"
"image/bmp" "image/x-bmp" "image/x-MS-bmp" ""
"bmp" ""
"BM" "" 100
EOF
    find_dll "$pixloadpath" "libpixbufloader-gdip-wbmp.dll" &&
    	cat >>loaders.cache <<EOF
"libpixbufloader-wbmp.dll"
"wbmp" 4 "gdk-pixbuf" "The WBMP image format" "LGPL"
"image/vnd.wap.wbmp" ""
"wbmp" ""
"  " "zz" 1
" `" "z " 1
" @" "z " 1
"  " "z " 1
EOF

    echo "[Pango]" > pangorc
    echo "ModuleFiles = pango.modules" >> pangorc
    echo "# Pango modules file" > pango.modules
    pangoloadpath="/usr/lib/pango/1.6.0/modules /opt/gtk/lib/pango/1.6.0/modules /usr/i686-pc-mingw32/sys-root/mingw/lib/pango/1.6.0/modules"
    find_dll "$pangoloadpath" "pango-basic-win32.dll" &&
    	cat >>pango.modules <<EOF
"pango-basic-win32.dll" BasicScriptEngineWin32 PangoEngineShape PangoRenderWin32 common:
EOF

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
    ls -lG dnssec_trigger_setup_$version.exe
    #ls -lG $file
    info "Done"
    exit 0
fi

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
replace_text "dnssec-trigger.8.in" "0DATE0" "`date +%F`"

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

case `uname 2>&1` in
    Linux|linux) 
        sha=`sha1sum $tarfile |  awk '{ print $1 }'`
        sha256=`sha256sum $tarfile |  awk '{ print $1 }'`
    ;;
    FreeBSD|freebsd)
        sha=`sha1 $tarfile |  awk '{ print $5 }'`
        sha256=`sha256 $tarfile |  awk '{ print $5 }'`
    ;;
    *)
        sha=`sha1sum $tarfile |  awk '{ print $1 }'`
        sha256=`sha256sum $tarfile |  awk '{ print $1 }'`
    ;;
esac

echo $sha > $tarfile.sha1
echo $sha256 > $tarfile.sha256

info "dnssec-trigger distribution created successfully."
info "sha1   $sha"
info "sha256 $sha256"

