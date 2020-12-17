import os
import sys
import subprocess

def measure(cmd):
    # Run command
    out = subprocess.Popen(cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)

    # Get output
    stdout, _ = out.communicate()

    # Get running time in ms
    return float(stdout.split(b';')[0])

# Get current working directory path
path = os.getcwd()

iterations = int(sys.argv[1]) # Scaling factor. Number of loop iterations
fib = int(sys.argv[2]) # Number of recursions in target fibonacci function

# Set arguments
args = [str(iterations), str(fib)]

# Set up commands
perf_cmd = ['perf', 'stat', '-x', ';']
target_cmd = path+'/bin/t6'
cmd = perf_cmd+[target_cmd]+args
trace_cmd = perf_cmd+[path+'/bin/tracer',
    '-q',
    ' '.join([target_cmd]+args),
    'main']

# Measure runtime with and without tracing
mean_notrace = measure(cmd)
mean_trace = measure(trace_cmd)

print(str(iterations)+';'
    +str(fib)+';'
    +str(mean_notrace)+';'
    +str(mean_trace)+';'
    +str(mean_trace/mean_notrace))