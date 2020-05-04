rm -f ./sigs
read -p "Enter path to signature file: " SIGPATH
ln -s "$SIGPATH" ./sigs