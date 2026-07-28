#!/usr/bin/env python3
"""
Result Verification Module for Crypto Scanner

Validates and verifies detected secrets before adding them to results,
reducing false positives and improving signal quality.
"""

import json
import re
import requests
import hashlib
import time
from typing import Dict, List, Tuple, Optional, Any
from pathlib import Path
import base58
import ecdsa
from mnemonic import Mnemonic

class ResultVerifier:
    def __init__(self):
        self.home = Path.home()
        self.verification_cache_file = self.home / ".verification_cache.json"
        self.load_verification_cache()
    
    def load_verification_cache(self):
        """Load verification cache from file."""
        try:
            with open(self.verification_cache_file, 'r') as f:
                self.verification_cache = json.load(f)
        except FileNotFoundError:
            self.verification_cache = {}
    
    def save_verification_cache(self):
        """Save verification cache to file."""
        with open(self.verification_cache_file, 'w') as f:
            json.dump(self.verification_cache, f, indent=2)
    
    def validate_bitcoin_address(self, address: str) -> bool:
        """Validate Bitcoin address using checksum."""
        try:
            # Check if it's a valid Bitcoin address format
            if re.match(r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$', address):
                # For P2PKH and P2SH addresses
                decoded = base58.b58decode_check(address)
                return len(decoded) == 21  # version byte + 20 bytes hash
            elif address.startswith('bc1'):
                # Bech32 address validation
                return self.validate_bech32_address(address)
            return False
        except Exception:
            return False
    
    def validate_bech32_address(self, address: str) -> bool:
        """Validate Bech32 Bitcoin address."""
        # Simplified validation - in practice, implement full Bech32 validation
        if not address.lower().startswith('bc1'):
            return False
        # Length check for segwit addresses
        return 42 <= len(address) <= 62
    
    def validate_ethereum_address(self, address: str) -> bool:
        """Validate Ethereum address using checksum."""
        if not re.match(r'^0x[a-fA-F0-9]{40}$', address):
            return False
        
        # Convert to lowercase and check checksum
        raw_addr = address[2:].lower()
        checksum = self.ethereum_checksum(raw_addr)
        return address == '0x' + checksum
    
    def ethereum_checksum(self, addr: str) -> str:
        """Generate Ethereum address checksum."""
        # Convert address to hex and hash it
        hashed = hashlib.keccak_256(addr.encode('ascii')).hexdigest()
        result = ''
        for i in range(len(addr)):
            if hashed[i] >= '8':
                result += addr[i].upper()
            else:
                result += addr[i].lower()
        return result
    
    def validate_private_key(self, private_key: str) -> bool:
        """Validate private key format."""
        try:
            # Hex private key validation (should be 64 hex chars)
            if re.match(r'^[a-fA-F0-9]{64}$', private_key):
                # Convert to integer and check if it's in valid range
                pk_int = int(private_key, 16)
                # Valid range is 1 to 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
                max_val = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140
                return 1 <= pk_int < max_val
            return False
        except Exception:
            return False
    
    def validate_mnemonic(self, mnemonic: str) -> bool:
        """Validate BIP-39 mnemonic phrase."""
        try:
            # Split into words and check length
            words = mnemonic.split()
            if len(words) not in [12, 15, 18, 21, 24]:
                return False
            
            # Use mnemonic library to validate
            mnemo = Mnemonic("english")
            return mnemo.check(mnemonic)
        except Exception:
            return False
    
    def validate_api_key_format(self, api_key: str) -> bool:
        """Basic validation for API key formats."""
        # Check if it looks like a typical API key (alphanumeric with possible special chars)
        if len(api_key) < 20:
            return False
        
        # Should contain mostly alphanumeric characters
        alphanum_ratio = sum(1 for c in api_key if c.isalnum()) / len(api_key)
        return alphanum_ratio >= 0.7
    
    def cross_reference_blacklist(self, item: str) -> bool:
        """Check if item is in known blacklist to eliminate false positives."""
        # Hash the item to compare with stored hashes
        item_hash = hashlib.sha256(item.encode()).hexdigest()
        
        # Known blacklisted hashes (these are example values)
        blacklisted_hashes = [
            # These would be actual hashes of known invalid items
            # In practice, this would come from a maintained blacklist
        ]
        
        return item_hash in blacklisted_hashes
    
    def verify_result(self, result_item: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Verify a single result item.
        
        Returns: (is_valid, reason)
        """
        item_value = result_item.get('value', '')
        item_type = result_item.get('type', 'unknown')
        
        # Check cache first
        item_hash = hashlib.sha256(f"{item_type}:{item_value}".encode()).hexdigest()
        if item_hash in self.verification_cache:
            cached_result = self.verification_cache[item_hash]
            return cached_result['valid'], cached_result['reason']
        
        # Cross-reference with blacklist first
        if self.cross_reference_blacklist(item_value):
            result = (False, "Blacklisted item")
            self.cache_verification(item_hash, result)
            return result
        
        # Validate based on type
        if item_type == 'bitcoin_address':
            is_valid = self.validate_bitcoin_address(item_value)
            reason = "Valid Bitcoin address" if is_valid else "Invalid Bitcoin address format/checksum"
        elif item_type == 'ethereum_address':
            is_valid = self.validate_ethereum_address(item_value)
            reason = "Valid Ethereum address" if is_valid else "Invalid Ethereum address format/checksum"
        elif item_type == 'private_key':
            is_valid = self.validate_private_key(item_value)
            reason = "Valid private key format" if is_valid else "Invalid private key format/range"
        elif item_type == 'mnemonic':
            is_valid = self.validate_mnemonic(item_value)
            reason = "Valid mnemonic phrase" if is_valid else "Invalid mnemonic phrase"
        elif item_type == 'api_key':
            is_valid = self.validate_api_key_format(item_value)
            reason = "Valid API key format" if is_valid else "Invalid API key format"
        else:
            # For unknown types, apply general validation
            is_valid = len(item_value) > 5
            reason = "Valid format" if is_valid else "Too short"
        
        result = (is_valid, reason)
        self.cache_verification(item_hash, result)
        return result
    
    def cache_verification(self, item_hash: str, result: Tuple[bool, str]):
        """Cache verification result."""
        self.verification_cache[item_hash] = {
            'valid': result[0],
            'reason': result[1],
            'timestamp': time.time()
        }
        # Save cache periodically
        if len(self.verification_cache) % 10 == 0:  # Every 10 verifications
            self.save_verification_cache()
    
    def verify_results_batch(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Verify a batch of results."""
        verified_results = []
        
        for result in results:
            is_valid, reason = self.verify_result(result)
            
            if is_valid:
                # Add verification metadata
                verified_result = result.copy()
                verified_result['verified'] = True
                verified_result['verification_reason'] = reason
                verified_result['confidence_score'] = self.calculate_confidence_score(result)
                verified_results.append(verified_result)
            else:
                print(f"[Verification] Skipping invalid item: {result.get('value', '')[:50]}... ({reason})")
        
        # Save cache at the end
        self.save_verification_cache()
        return verified_results
    
    def calculate_confidence_score(self, result: Dict[str, Any]) -> float:
        """Calculate confidence score for a verified result."""
        score = 0.5  # Base score
        
        # Boost for validated types
        item_type = result.get('type', 'unknown')
        if item_type in ['bitcoin_address', 'ethereum_address', 'private_key']:
            score += 0.3
        elif item_type == 'mnemonic':
            score += 0.4
        elif item_type == 'api_key':
            score += 0.2
        
        # Context-based boosting
        context = result.get('context', '')
        crypto_keywords = ['crypto', 'bitcoin', 'ethereum', 'wallet', 'token', 'defi', 'nft', 'blockchain']
        for keyword in crypto_keywords:
            if keyword.lower() in context.lower():
                score += 0.1
                break
        
        # Cap the score
        return min(score, 1.0)

def main():
    verifier = ResultVerifier()
    
    # Example results to verify
    example_results = [
        {'type': 'bitcoin_address', 'value': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa', 'context': 'Bitcoin genesis address'},
        {'type': 'ethereum_address', 'value': '0x742d35Cc6634C0532925a3b8D4C9db96590b5c8e', 'context': 'Ethereum wallet'},
        {'type': 'private_key', 'value': 'a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456', 'context': 'Private key'},
        {'type': 'api_key', 'value': 'sk_test_1234567890abcdef1234567890abcdef', 'context': 'Stripe API key'},
        {'type': 'unknown', 'value': 'short', 'context': 'too short item'}
    ]
    
    print("Verifying results...")
    verified_results = verifier.verify_results_batch(example_results)
    
    print(f"\nVerified {len(verified_results)} out of {len(example_results)} results:")
    for result in verified_results:
        print(f"  {result['type']}: {result['value'][:30]}... (confidence: {result['confidence_score']:.2f})")

if __name__ == '__main__':
    main()
