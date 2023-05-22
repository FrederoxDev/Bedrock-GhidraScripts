from ghidra.program.model.symbol import SymbolType
import re
import subprocess


def find_labels_of_class(currentProgram, monitor, class_name):
    """
    Filters through all labels to find mangled names for functions belonging to the class
    """
    symbolTable = currentProgram.getSymbolTable()

    labels = list(symbolTable.getAllSymbols(True))
    labels = filter(lambda s: s.getSymbolType() == SymbolType.LABEL, labels)

    label_pattern = re.compile(r"\??\?([A-Za-z_]*)@@?" + class_name + r"@.*")
    dtor_pattern = re.compile(r"\?\?1" + class_name + r"@.*")

    monitor.initialize(len(labels))
    monitor.setMessage("Filtering all BDS labels")
    filtered_labels = []

    for label in labels:
        monitor.incrementProgress(1)

        if label_pattern.match(label.name) is not None:
            filtered_labels.append(label.name)

        elif dtor_pattern.match(label.name) is not None:
            filtered_labels.append(label.name)

            
    return filtered_labels


def demangle(symbol):
    """
    Demangles a mangled function name using undname.exe from Visual Studio
    """
    undname_path = "C:\\Program Files\\Microsoft Visual Studio\\2022\\Community\\VC\\Tools\\MSVC\\14.35.32215\\bin\\Hostx86\\arm\\undname.exe"

    # Run undname with the arg as the symbol name
    process = subprocess.Popen(
        [undname_path, symbol], stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    output, error = process.communicate()
    output = output.decode("utf-8").strip()

    # Crash completely on error
    if not output:
        print("An error occurred:", error.decode("utf-8"))
        exit(1)

    # Filter out unnecessary text
    return output.split('is :- "')[1].replace('"', "")


def batch_demangle(monitor, symbols):
    """
    Demangles an array of mangled symbols
    """
    demangled = []

    monitor.initialize(len(symbols))
    monitor.setMessage("Demangling symbols")

    for symbol in symbols:
        monitor.incrementProgress(1)
        demangled.append(demangle(symbol))

    return demangled
