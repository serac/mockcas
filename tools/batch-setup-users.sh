#!/bin/bash

data_dir=$1
user_file=$2

userScript="$(dirname $0)/setup-user.sh"
if [ ! -x $userScript ]; then
  echo "Unable to find user script $userScript"
  exit 1
fi

usage() {
  cat <<EOF
Usage: $(basename $0) <data-dir> <user-file

data-dir - the directory to place the user information
user-file - the list of users

Format of user-file is:
user1:uid1
user2:uid2
...

Or alternatively including the udc id:
user1:uid1:udc1
user2:uid2:udc2
...
EOF
  exit 1
}

[ -z "$user_file" ] && usage
[ ! -r $user_file ] && usage

for row in $(cat $user_file); do
  user=$(echo $row |cut -d: -f1)
  uid=$(echo $row | cut -d: -f2)
  udc=$(echo $row | cut -d: -f3)
  $userScript $data_dir $user $uid $udc
done
