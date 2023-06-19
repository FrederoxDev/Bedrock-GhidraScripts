# Generates the shortest unique signature for a function
# @author Frederox
# @category Bedrock

from ghidra.program.model.lang import OperandType
from ghidra.program.flatapi import FlatProgramAPI
import time
import math

# Settings
first_check = 20

# Ghidra vscode
currentAddress = currentAddress
monitor = monitor
currentProgram = currentProgram

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

def get_signature(instructions):
    signature = []
    for instruction in instructions:
        if instruction is None:
            continue

        bytes = instruction.getBytes()

        for i in range(len(bytes)):
            op_type = instruction.getOperandType(i)
            is_op_dynamic = (op_type & OperandType.DYNAMIC) == OperandType.DYNAMIC

            if is_op_dynamic: 
                signature.append(".")

            else: 
                signature.append("\\x{:02X}".format(bytes[i] & 0xFF))

    return signature

instructions = map(lambda addr: listing.getInstructionAt(addr), func_body.getAddresses(True))
instructions = filter(lambda addr: addr != None, instructions)

signature = get_signature(instructions)

low = 0
high = len(signature) - 1
iteration_count = 0

last_unique = signature
last_not_unique = None

need_binary_search = True

if high >= first_check:
    if not is_signature_unique(signature[0:first_check]):
        last_not_unique = "".join(signature[0:first_check])
        need_binary_search = False
    
    else:
        high = first_check

# It probably wont be unique, but do a binary search anyway
if need_binary_search:
    monitor.initialize(int(math.log(high, 2)) + 1)

    while low <= high:
        mid = (high + low) // 2
        iteration_count += 1

        monitor.setMessage("Iteration: {}, Low: {}, High: {}".format(iteration_count, low, high))

        if is_signature_unique(signature[0:mid]):
            high = mid - 1
            last_unique = "".join(signature[0:mid])

        else:
            last_not_unique = "".join(signature[0:mid])
            break

        monitor.setProgress(iteration_count)

if last_not_unique == None:
    print("Could not find a unique signature!")
    exit(0)

not_unique_matches = list(flat_api.findBytes(None, last_not_unique, 0))
not_unique_matches = filter(lambda m: m != currentAddress, not_unique_matches)
not_unique_matches = map(lambda addr: function_manager.getFunctionAt(addr), not_unique_matches)
not_unique_matches = filter(lambda f: f != None, not_unique_matches)
not_unique_matches = map(lambda func: func.getBody().getAddresses(True), not_unique_matches)

not_unique_signatures = []

for match in not_unique_matches:
    instructions = map(lambda a: listing.getInstructionAt(a), match)
    not_unique_signatures.append(get_signature(instructions))


for i in range(low, high):
    real_byte = signature[i]
    is_i_unique = True

    for match in not_unique_signatures:
        match_byte = match[i]

        if real_byte == match_byte:
            is_i_unique = False
            break

        else:
            # Remove it from the array and continue
            pass

    if is_i_unique:
        break


ida_signature = "".join("".join(signature[0:i + 1])).replace("\\", "").replace("x", " ").replace(".", " ?").strip()

print("Time Elapsed: " + str(time.time() - start) + " seconds")
print(" --- " + func.getName() + " --- (" + str(iteration_count) + " Iterations)")
print(ida_signature)