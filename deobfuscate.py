#!/usr/bin/env python3
"""
Deobfuscation tool for files with backspace/overwrite obfuscation.
Removes backspace escape sequences and reconstructs the original text.
"""
import sys
import os

def deobfuscate_file(input_path, output_path=None):
    """
    Deobfuscate a file by processing backspace characters.
    Each character followed by \b is removed (overwritten).
    """
    if output_path is None:
        output_path = input_path + '.clean'
    
    print(f"[*] Deobfuscating: {input_path}")
    print(f"[*] Output: {output_path}")
    
    with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
        text = f.read()
    
    # Process backspace characters using a result list
    result = []
    bs_count = 0
    i = 0
    
    while i < len(text):
        char = text[i]
        
        if char == '\b':  # Backspace
            bs_count += 1
            # Remove the previous character if exists
            if result:
                result.pop()
            i += 1
        elif char == '\x1b':  # ANSI escape sequence
            # Skip ANSI escape sequences
            if i + 1 < len(text) and text[i+1] == '[':
                # Find 'm' terminator for SGR sequences
                j = i + 2
                while j < len(text) and text[j] != 'm':
                    j += 1
                if j < len(text):
                    i = j + 1
                    continue
            result.append(char)
            i += 1
        else:
            result.append(char)
            i += 1
    
    clean_text = ''.join(result)
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(clean_text)
    
    print(f"[+] Deobfuscated successfully!")
    print(f"[+] Backspace sequences processed: {bs_count}")
    
    # Show a preview
    preview = clean_text[:500]
    print("\n--- Preview (first 500 chars) ---")
    print(preview)
    print("--- End Preview ---\n")

def main():
    if len(sys.argv) < 2:
        print("Usage: deobfuscate.py <file> [output_file]")
        print("\nDeobfuscates files with backspace/overwrite obfuscation.")
        print("\nExamples:")
        print("  deobfuscate.py ults.jsonl                    # Creates ults.jsonl.clean")
        print("  deobfuscate.py ults.jsonl clean_output.jsonl # Creates clean_output.jsonl")
        sys.exit(1)
    
    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None
    
    if not os.path.exists(input_path):
        print(f"Error: File not found: {input_path}")
        sys.exit(1)
    
    try:
        deobfuscate_file(input_path, output_path)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()