# Generates the shortest unique signature for a function
# @author Frederox
# @category Bedrock

from ghidra.program.model.lang import OperandType
from ghidra.program.flatapi import FlatProgramAPI
import time
import math

start = time.time()
function_manager = currentProgram.getFunctionManager()
listing = currentProgram.getListing()
flat_api = FlatProgramAPI(currentProgram)

func = function_manager.getFunctionAt(currentAddress)
func_body = func.getBody()
signature = []

if func == None:
    print("No currently selected function!")
    exit(1)

def is_signature_unique(sig):
    sig = "".join(sig)
    matches = flat_api.findBytes(None, sig, 2)
    return len(matches) <= 1

instructions = map(lambda addr: listing.getInstructionAt(addr), func_body.getAddresses(True))
instructions = filter(lambda addr: addr != None, instructions)

for instruction in instructions:
    bytes = instruction.getBytes()

    for i in range(len(bytes)):
        op_type = instruction.getOperandType(i)
        is_op_dynamic = (op_type & OperandType.DYNAMIC) == OperandType.DYNAMIC

        if is_op_dynamic: 
            signature.append(".")

        else: 
            signature.append("\\x{:02X}".format(bytes[i] & 0xFF))

low = 0
high = len(signature) - 1
iteration_count = 0

last_signature = signature

monitor.initialize(int(math.log(high, 2)) + 1)

# Binary Search Like approach to find the sig quickly
while low <= high:
    mid = (high + low) // 2
    iteration_count += 1

    monitor.setMessage("Iteration: {}, Low: {}, High: {}".format(iteration_count, low, high))

    if is_signature_unique(signature[0:mid]):
        high = mid - 1
        last_signature = signature[0:mid]

    else:
        low = mid + 1

    monitor.setProgress(iteration_count)

ida_signature = "".join(last_signature).replace("\\", "").replace("x", " ").replace(".", " ?").strip()

print("Time Elapsed: " + str(time.time() - start) + " seconds")
print(" --- " + func.getName() + " --- (" + str(iteration_count) + " Iterations)")
print(ida_signature)