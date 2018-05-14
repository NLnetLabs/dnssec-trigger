#!/bin/bash

if [ $# -eq 3 ]
then
	if [ $1 = "local_zone" ] && [ $2 = "test" ] && [ $3 = "static" ]
	then
		echo ok
	else
		echo fail
	fi
elif [ $# -eq 2 ]
then
	if [ $1 = "local_zone_remove" ] && [ $2 = "test" ]
	then
		echo ok
	else
		echo fail
	fi
else
	echo fail
fi

