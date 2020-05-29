################## Sandbox ##################
# Parameters: 1 - File to analyze           #
#############################################

# Variables

FILE=''
OUTPUT_FILE=''

# Execution

FILE=$1
OUTPUT_FILE=$1.trace

# If file don't exist, exit
if [ ! -f "$FILE" ]; then
    exit 1
fi

./analyzer.sh $1 $OUTPUT_FILE

./evaluator.py