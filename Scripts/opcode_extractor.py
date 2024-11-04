# Extract opcodes from binary files using Ghidra
#@category Analysis
#@author Ardee
#@menupath Analysis.ExtractOpcodes
#@keybinding 
#@toolbar 
#@tool 

import os
import sys
from ghidra.program.model.listing import CodeUnit
from ghidra.program.flatapi import FlatProgramAPI
from ghidra.app.decompiler import DecompileOptions, DecompInterface
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import CodeUnitFormat
from ghidra.program.model.listing import CodeUnitFormatOptions
from java.io import File

def normalize_windows_path(path):
    """Normalize path for Windows"""
    if path.startswith('/'):
        path = path[1:]
    return path.replace('/', os.sep)

def extract_opcodes():
    try:
        # Get current program
        program = currentProgram
        if not program:
            print("ERROR: No program loaded")
            return False
            
        # Get program information
        program_name = program.getName()
        program_path = program.getExecutablePath()
        
        # Normalize the path for Windows
        program_path = normalize_windows_path(program_path)
        
        print("\nProcessing program: {}".format(program_name))
        print("Program path: {}".format(program_path))
        
        # Extract paths
        temp_dir = os.path.dirname(program_path)
        base_dir = os.path.dirname(temp_dir)  # "Sub 3" directory
        unpacked_samples_dir = os.path.join(base_dir, "Unpacked_Samples")
        
        # Read the temp file to get its hash (for matching)
        temp_file_path = os.path.join(temp_dir, program_name)
        with open(temp_file_path, 'rb') as f:
            temp_file_content = f.read()
            
        # Find matching file in APT folders
        apt_group = None
        original_file = None
        
        for apt_folder in os.listdir(unpacked_samples_dir):
            if not apt_group:  # Continue only if we haven't found a match
                apt_path = os.path.join(unpacked_samples_dir, apt_folder)
                if os.path.isdir(apt_path):
                    exe_path = os.path.join(apt_path, "exe")
                    if os.path.exists(exe_path):
                        for filename in os.listdir(exe_path):
                            file_path = os.path.join(exe_path, filename)
                            if os.path.isfile(file_path):
                                with open(file_path, 'rb') as f:
                                    content = f.read()
                                    if content == temp_file_content:
                                        apt_group = apt_folder
                                        original_file = filename
                                        print("Found matching file in: {}".format(apt_folder))
                                        break
        
        if not apt_group or not original_file:
            print("ERROR: Could not find original malware location")
            return False
            
        # Create output directory in the correct APT folder
        output_dir = os.path.join(unpacked_samples_dir, apt_group, "opcodes")
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
            print("Created output directory: {}".format(output_dir))
            
        # Create output file using the original hash name
        output_file = os.path.join(output_dir, "{}.opcode".format(original_file))
        
        print("APT Directory: {}".format(apt_group))
        print("Malware hash: {}".format(original_file))
        print("Output directory: {}".format(output_dir))
        print("Writing opcodes to: {}".format(output_file))
        
        # Get listing and monitor
        listing = program.getListing()
        monitor = ConsoleTaskMonitor()
        
        with open(output_file, 'w') as f:
            # Write header information
            f.write("# Opcode extraction for malware analysis\n")
            f.write("# APT Group: {}\n".format(apt_group))
            f.write("# Malware Hash: {}\n".format(original_file))
            f.write("# Executable format: {}\n".format(program.getExecutableFormat()))
            f.write("# Processor: {}\n".format(program.getLanguage().getProcessor().toString()))
            f.write("# Creation date: {}\n".format(program.getCreationDate()))
            f.write("# Format: <Address> | <Bytes> | <Mnemonic> | <Full Instruction>\n\n")
            
            # Process all instructions
            print("Starting instruction processing...")
            instruction_count = 0
            instructions = listing.getInstructions(True)
            while instructions.hasNext() and not monitor.isCancelled():
                insn = instructions.next()
                if insn:
                    # Get instruction components
                    addr = insn.getAddress()
                    bytes_str = " ".join([format(b & 0xFF, '02x') for b in insn.getBytes()])
                    mnemonic = insn.getMnemonicString()
                    full_insn = insn.toString()
                    
                    # Write formatted instruction
                    f.write("{} | {} | {} | {}\n".format(addr, bytes_str, mnemonic, full_insn))
                    instruction_count += 1
                    
                    # Progress indicator every 1000 instructions
                    if instruction_count % 1000 == 0:
                        print("Processed {} instructions...".format(instruction_count))
        
        print("Successfully extracted {} opcodes to {}".format(instruction_count, output_file))
        return True
        
    except Exception as e:
        print("ERROR: Exception during opcode extraction: {}".format(str(e)))
        import traceback
        traceback.print_exc()
        return False

# Main execution
if __name__ == '__main__':
    print("Starting opcode extraction...")
    if extract_opcodes():
        print("Opcode extraction completed successfully")
    else:
        print("Opcode extraction failed")
        sys.exit(1)