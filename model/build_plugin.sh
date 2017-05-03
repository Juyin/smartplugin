####################
# Build the plugin
####################

#!/bin/bash 

make

cd ../..
make 

cd -

make install
