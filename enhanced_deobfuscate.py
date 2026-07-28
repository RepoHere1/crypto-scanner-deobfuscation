#!/usr/bin/env python3
"""
Enhanced Deobfuscation Tool for Crypto Scanner

Advanced deobfuscation techniques for detecting and decoding obfuscated secrets,
including base64, character substitution, and reverse string techniques.
"""

import sys
import os
import re
import base64
import binascii
from typing import List, Tuple, Dict, Optional
import json

class AdvancedDeobfuscator:
    def __init__(self):
        # Regex patterns for various secret types
        self.secret_patterns = {
            'bitcoin_address': re.compile(r'\b(1[A-HJ-NP-Za-km-z1-9]{25,34}|3[A-HJ-NP-Za-km-z1-9]{33}|bc1[0-9A-Za-z]{39,59})\b'),
            'ethereum_address': re.compile(r'\b0x[a-fA-F0-9]{40}\b'),
            'private_key_hex': re.compile(r'\b[a-fA-F0-9]{64}\b'),
            'mnemonic_phrase': re.compile(r'\b(?:[a-z]{3,10}\s){11,23}[a-z]{3,10}\b'),
            'api_key': re.compile(r'\b[A-Za-z0-9_-]{32,}\b'),
            'access_token': re.compile(r'\b[A-Za-z0-9_-]{20,}\b'),
            'rpc_endpoint': re.compile(r'\bhttps?://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?::\d{2,5})?(?:/[a-zA-Z0-9._-]*)*\b'),
        }
        
        # Character substitution mappings
        self.char_substitutions = {
            '0': ['o', 'O'],
            '1': ['i', 'l', 'I', 'L'],
            '3': ['e', 'E'],
            '4': ['a', 'A'],
            '5': ['s', 'S'],
            '8': ['b', 'B'],
            '@': ['a', 'A'],
            '$': ['s', 'S'],
            '!': ['i', 'I', 'l', 'L'],
        }

    def deobfuscate_file(self, input_path: str, output_path: str = None) -> str:
        """
        Deobfuscate a file with advanced techniques.
        """
        if output_path is None:
            output_path = input_path + '.enhanced'

        print(f"[*] Enhanced deobfuscating: {input_path}")
        print(f"[*] Output: {output_path}")

        with open(input_path, 'r', encoding='utf-8', errors='ignore') as f:
            text = f.read()

        # Apply multiple deobfuscation techniques
        clean_text = self._apply_backspace_processing(text)
        clean_text = self._apply_character_replacements(clean_text)
        clean_text = self._decode_base64_strings(clean_text)
        clean_text = self._reverse_strings_if_needed(clean_text)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(clean_text)

        print(f"[+] Enhanced deobfuscation completed!")
        
        # Show detected secrets
        detected_secrets = self._detect_secrets(clean_text)
        if detected_secrets:
            print(f"[+] Detected {len(detected_secrets)} potential secrets:")
            for secret_type, matches in detected_secrets.items():
                for match in matches:
                    print(f"  {secret_type}: {match}")

        return clean_text

    def _apply_backspace_processing(self, text: str) -> str:
        """Process backspace characters as in the original."""
        result = []
        i = 0
        
        while i < len(text):
            char = text[i]
            
            if char == '\b':  # Backspace
                # Remove the previous character if exists
                if result:
                    result.pop()
                i += 1
            elif char == '\x1b':  # ANSI escape sequence
                # Skip ANSI escape sequences
                if i + 1 < len(text) and text[i+1] == '[':
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
        
        return ''.join(result)

    def _apply_character_replacements(self, text: str) -> str:
        """Apply character substitution deobfuscation."""
        # Replace common substitutions (like 0->o, 1->i, etc.)
        temp_text = text
        
        # Multiple passes to handle complex substitutions
        for _ in range(3):  # Up to 3 passes for complex cases
            for real_char, subs in self.char_substitutions.items():
                for sub_char in subs:
                    # Replace single characters
                    temp_text = temp_text.replace(sub_char, real_char)
                    
                    # Also handle common patterns like 'p@ssw0rd' -> 'password'
                    # This is more complex and would need more sophisticated handling
        
        return temp_text

    def _decode_base64_strings(self, text: str) -> str:
        """Decode potential base64-encoded strings."""
        # Find potential base64 strings
        # Base64 strings usually have length that's multiple of 4 and contain valid base64 chars
        b64_pattern = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
        matches = b64_pattern.findall(text)
        
        result = text
        for match in matches:
            try:
                decoded = base64.b64decode(match).decode('utf-8', errors='ignore')
                # Only replace if decoded content looks meaningful
                if len(decoded) > 5 and any(c.isalnum() for c in decoded):
                    result = result.replace(match, decoded)
            except (binascii.Error, ValueError):
                # Not a valid base64 string
                continue
        
        return result

    def _reverse_strings_if_needed(self, text: str) -> str:
        """Detect and reverse reversed strings."""
        # Look for patterns that might be reversed (like reversed API keys)
        # This is heuristic-based and might need refinement
        words = text.split()
        result_words = []
        
        for word in words:
            # Check if reversing makes it look more like a valid secret
            reversed_word = word[::-1]
            if self._looks_like_secret(reversed_word) and not self._looks_like_secret(word):
                result_words.append(reversed_word)
            else:
                result_words.append(word)
        
        return ' '.join(result_words)

    def _looks_like_secret(self, text: str) -> bool:
        """Heuristic to determine if text looks like a secret."""
        if len(text) < 10:
            return False
            
        # Check against known patterns
        for pattern in self.secret_patterns.values():
            if pattern.search(text):
                return True
                
        # Heuristic: mix of letters and numbers, length appropriate
        if re.match(r'^[A-Za-z0-9_/-]+$', text) and len(text) >= 20:
            return True
            
        return False

    def _detect_secrets(self, text: str) -> Dict[str, List[str]]:
        """Detect various types of secrets in the text."""
        detected = {}
        
        for secret_type, pattern in self.secret_patterns.items():
            matches = pattern.findall(text)
            if matches:
                detected[secret_type] = matches
                
        return detected

    def deobfuscate_text(self, text: str) -> str:
        """Deobfuscate text using all techniques."""
        text = self._apply_backspace_processing(text)
        text = self._apply_character_replacements(text)
        text = self._decode_base64_strings(text)
        text = self._reverse_strings_if_needed(text)
        return text

def main():
    if len(sys.argv) < 2:
        print("Usage: enhanced_deobfuscate.py <file> [output_file]")
        print("\nEnhanced deobfuscation with advanced techniques.")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2] if len(sys.argv) > 2 else None

    if not os.path.exists(input_path):
        print(f"Error: File not found: {input_path}")
        sys.exit(1)

    deobfuscator = AdvancedDeobfuscator()
    
    try:
        deobfuscator.deobfuscate_file(input_path, output_path)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
