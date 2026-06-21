#! /bin/sh

# Library of functions.
# Intended to be sourced by scripts (or interactive shells if you want).
# Must be compliant across all supported operating systems.

set -u
set -e


# Test which flag works on the current system.

if stat -c "%a" . >/dev/null 2>&1
then
	STAT_FMT_FLAG="-c"
	STAT_MTIME="%Y"
	STAT_SIZE="%s"
	STAT_FILE_SHORT="%A %U %G"
	STAT_FILE="$STAT_FILE_SHORT %N"
else
	STAT_FMT_FLAG="-f"
	STAT_MTIME="%m"
	STAT_SIZE="%z"
	STAT_FILE_SHORT="%Sp %Su %Sg"
	STAT_FILE="$STAT_FILE_SHORT %N"
fi

genfile_stdout_16m()
{
	seq -f%015g 1048576
}

genfile_stdout_1m()
{
	seq -f%015g 65536
}

genfile()
{
	#touch "$1"
	genfile_stdout_1m > "$1"
}

# Makes a directory path and optionally a file in it.
# if you want the last element to be a directory, add / at the end
mkdirfile()
{
	case "$1" in
	'')
		error that cannot work
		;;
	*/)
		mkdir -p "$1"
		;;
	*/*)
		mkdir -p "${1%/*}"
		genfile "$1"
		;;
	*)
		genfile "$1"
		;;
	esac
}

mkdirsymlink()
{
	(
		mkdir -p "$1"
		cd "$1"
		ln -sf "$2" "$3"
	)
}

# Make a first interesting tree.
generate_tree_1()
{
	mkdirfile foo/bar/baz/one.txt
	mkdirfile foo/bar/baz/one2.txt
	mkdirfile 'foo/bar/baz/  two.txt'
	mkdirfile 'foo/bar/baz/two  2.txt'
	mkdirfile 'foo/bar/baz/two3.txt  '
	mkdirsymlink foo/baz/ ../bar/baz/one.txt three.txt
	mkdirfile one/two/three/four.txt
	mkdirfile foo/five/one/two/five/blah.txt
	mkdirfile foo/one/two/five/blah.txt
}

# A frontend for find
# First argument is a dir to chdir to.
findme()
{
	local stat_fmt dirs
	OPTIND=1

	dirs=0

	stat_fmt=$STAT_FILE

	while getopts dt flag
	do
		case "$flag" in
		d)
			dirs=1
			;;
		t)
			stat_fmt="${stat_fmt} ${STAT_MTIME}"
			;;
		esac
	done

	shift $((OPTIND - 1))

	if [ $# -lt 2 ]
	then
		echo usage: different 1>&2
		return 1
	fi

	(
		cd "$1"
		shift
		if [ ${dirs} -ne 0 ]
		then
			find "$@" -type d -print0 | \
				xargs -0 stat $STAT_FMT_FLAG "$stat_fmt" | \
				sort
		else
			find "$@" ! -type d -print0 | \
				xargs -0 stat $STAT_FMT_FLAG "$stat_fmt $STAT_SIZE" | \
				sort
		fi
	)
}

# compare two trees.  This will later be modular to pick between:
# - diff
# - find . -print0 | sort --zero-terminated | xargs -0 tar fc foo.tar
# - mtree
compare_trees ()
{
	local need_time

	need_time="--"
	OPTIND=1

	while getopts t flag; do
		case "$flag" in
		t)
			need_time="-t"
			;;
		esac
	done

	shift $((OPTIND - 1))

	if [ $# -ne 2 ]
	then
		echo usage: different 1>&2
		return 1
	fi

	# files_and_permissions

	findme "$need_time" "$1" . > find1
	findme "$need_time" "$2" . > find2
	diff -u find[12] 1>&2

	# dirs_and_permissions

	findme "-d" "$need_time" "$1" . > find1d
	findme "-d" "$need_time" "$2" . > find2d
	diff -u find[12]d 1>&2

	# file contents

	diff -ru "$1" "$2"
}
