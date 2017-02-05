# This scripts is requires the knockd package which can be installed with: apt-get install knockd

#!/bin/bash
CONFIG_DIR="knockd_configs"
INTERFACE="wlan0"


# start knockd
if [[ $1 == "start" ]]; then

	# make sure the directory with our config files exists
	if [ -d $CONFIG_DIR ]; then

		for file in `ls $CONFIG_DIR`; do
			echo "Starting knockd instance with config file $file on interface $INTERFACE"
			# echo $CONFIG_DIR/$file
			sudo knockd -d --interface $INTERFACE --config $CONFIG_DIR/$file
		done


	else
		echo $CONFIG_DIR "not found."
fi

# stop knockd
elif [[ $1 == "stop" ]]; then
	sudo killall knockd

# print help message
else
	echo -e "Start knockd like this:\n" $0 "start"
	echo -e "Stop knockd like this:\n" $0 "stop"
fi
