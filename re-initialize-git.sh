#!/bin/bash

LOCK_FILE="/var/run/update-ipsets.lock"
[ ! "${UID}" = "0" ] && LOCK_FILE="${HOME}/.update-upsets.lock"
[ "${UPDATE_IPSETS_LOCKER}" != "${0}" ] && exec env UPDATE_IPSETS_LOCKER="$0" flock -en "${LOCK_FILE}" "${0}" "${@}" || :

[ -d .git.old ] && rm -rf .git.old
echo
echo "Backing up .git"
mv .git .git.old || exit 1

echo
echo "Initializing new .git"
git init || exit 1

echo
echo "Creating new gh-pages branch"
git checkout --orphan gh-pages || exit 1

echo
echo "Adding files to new gh-pages"
git add *.csv *.json *.xml *.html *.png *.txt *.css *.sh CNAME *.ico *.icns .gitignore || exit 1

echo
echo "Restoring old git config"
mv .git.old/config .git/config || exit 1

echo
echo "Committing all files"
git commit -a -m 'restarted' || exit 1

echo
echo "Pushing git"
git push -f origin gh-pages || exit 1

echo
echo "Removing backup"
rm -rf .git.old/
