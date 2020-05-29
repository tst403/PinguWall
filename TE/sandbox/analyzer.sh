################## Sandbox ##################
# Parameters: 1 - File to analyze           #
# Parameters: 2 - Output file               #
#############################################

# Variables

TIME_PERIOD=7
TRACE_FILE=''
PROG_NAME=''
TRANSLATE_PROG='./syscallTranslator.py'

# Execution

PROG_NAME=`echo $1 | cut -d ' ' -f1`
TRACE_FILE=$PROG_NAME.trace

# Generate strace log
(strace $1 > /dev/null 2> $TRACE_FILE)&PID=$!; sleep $TIME_PERIOD; kill $PID

# Generate strace log insolate syscalls
cat $TRACE_FILE | grep -o -E "[a-zA-Z]+[(]" | tr -d '(' > $PROG_NAME.syscalls

$TRANSLATE_PROG $PROG_NAME.syscalls $PROG_NAME.nums
rm $TRACE_FILE $PROG_NAME.syscalls