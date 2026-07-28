#!/usr/bin/env python3
"""
Enhanced Target Intelligence System for Crypto Scanner

Implements dynamic target scoring based on historical success rates,
real-time availability checks, and contextual indicators.
"""

import json
import time
import requests
import hashlib
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Tuple, Optional
import re


class TargetIntelligence:
    def __init__(self):
        self.home = Path.home()
        self.target_scores_file = self.home / ".target_scores.json"
        self.platform_stats_file = self.home / ".platform_stats.json"
        self.load_target_scores()
        self.load_platform_stats()
    
    def load_target_scores(self):
        """Load target scoring data from file."""
        try:
            with open(self.target_scores_file, 'r') as f:
                self.target_scores = json.load(f)
        except FileNotFoundError:
            self.target_scores = {}
    
    def save_target_scores(self):
        """Save target scoring data to file."""
        with open(self.target_scores_file, 'w') as f:
            json.dump(self.target_scores, f, indent=2)
    
    def load_platform_stats(self):
        """Load platform statistics from file."""
        try:
            with open(self.platform_stats_file, 'r') as f:
                self.platform_stats = json.load(f)
        except FileNotFoundError:
            self.platform_stats = {
                'github': {'success_rate': 0.05, 'last_checked': None},
                'gitlab': {'success_rate': 0.03, 'last_checked': None},
                'huggingface': {'success_rate': 0.02, 'last_checked': None},
                'docker': {'success_rate': 0.01, 'last_checked': None},
                'circleci': {'success_rate': 0.04, 'last_checked': None},
                'postman': {'success_rate': 0.03, 'last_checked': None},
                'aws_s3': {'success_rate': 0.07, 'last_checked': None},
                'gcs': {'success_rate': 0.06, 'last_checked': None},
                'jenkins': {'success_rate': 0.02, 'last_checked': None},
                'elasticsearch': {'success_rate': 0.01, 'last_checked': None},
                'syslog': {'success_rate': 0.01, 'last_checked': None},
            }
    
    def save_platform_stats(self):
        """Save platform statistics to file."""
        with open(self.platform_stats_file, 'w') as f:
            json.dump(self.platform_stats, f, indent=2)
    
    def calculate_target_score(self, target: str, platform: str) -> float:
        """Calculate score for a target based on multiple factors."""
        # Base score from historical success rate
        base_score = self.platform_stats.get(platform, {}).get('success_rate', 0.01)
        
        # Contextual indicators
        crypto_indicators = [
            r'crypto',
            r'bitcoin',
            r'ethereum', 
            r'wallet',
            r'coin',
            r'token',
            r'nft',
            r'defi',
            r'blockchain',
            r'web3',
            r'bitcoin',
            r'btc',
            r'eth',
            r'solana',
            r'sol',
            r'polygon',
            r'matic'
        ]
        
        context_bonus = 0
        target_lower = target.lower()
        for indicator in crypto_indicators:
            if re.search(indicator, target_lower, re.IGNORECASE):
                context_bonus += 0.1
        
        # Recency bonus (recently successful platforms get higher scores)
        recency_bonus = 0
        last_checked = self.platform_stats.get(platform, {}).get('last_checked')
        if last_checked:
            days_since_check = (datetime.now() - datetime.fromisoformat(last_checked)).days
            if days_since_check < 7:  # Less than a week since last check
                recency_bonus = 0.05
        
        # Calculate final score
        final_score = base_score + context_bonus + recency_bonus
        
        # Store score for this specific target
        target_hash = hashlib.sha256(target.encode()).hexdigest()[:16]
        self.target_scores[target_hash] = {
            'score': final_score,
            'platform': platform,
            'last_updated': datetime.now().isoformat(),
            'context_bonus': context_bonus
        }
        
        return final_score
    
    def prioritize_targets(self, targets: List[Tuple[str, str]]) -> List[Tuple[str, float]]:
        """Prioritize targets based on calculated scores."""
        scored_targets = []
        for target, platform in targets:
            score = self.calculate_target_score(target, platform)
            scored_targets.append((target, score))
        
        # Sort by score in descending order
        scored_targets.sort(key=lambda x: x[1], reverse=True)
        
        # Update platform stats
        if targets:
            platform = targets[0][1]  # Assuming all targets in this batch are from same platform
            self.platform_stats[platform]['last_checked'] = datetime.now().isoformat()
            self.save_platform_stats()
            self.save_target_scores()
        
        return scored_targets
    
    def update_success_rate(self, platform: str, success: bool):
        """Update platform success rate based on scan results."""
        stats = self.platform_stats.get(platform, {})
        current_success_rate = stats.get('success_rate', 0.01)
        
        # Simple moving average - adjust based on whether this was a success or failure
        if success:
            # Increase success rate (but cap it)
            new_rate = min(current_success_rate * 1.1, 0.5)
        else:
            # Decrease success rate (but floor it)
            new_rate = max(current_success_rate * 0.95, 0.001)
        
        self.platform_stats[platform]['success_rate'] = new_rate
        self.save_platform_stats()


# Example usage
def main():
    ti = TargetIntelligence()
    
    # Example targets with platforms
    example_targets = [
        ("https://github.com/bitcoin/bitcoin", "github"),
        ("https://github.com/ethereum/smart-contracts", "github"),
        ("https://github.com/cool-project/app", "github"),
        ("https://gitlab.com/blockchain-tool", "gitlab"),
        ("https://huggingface.co/crypto-models", "huggingface")
    ]
    
    print("Original targets:", [t[0] for t in example_targets])
    
    # Prioritize targets
    prioritized = ti.prioritize_targets(example_targets)
    
    print("\nPrioritized targets:")
    for target, score in prioritized:
        print(f"  {target}: {score:.4f}")
    
    # Simulate updating success rates
    ti.update_success_rate("github", True)
    ti.update_success_rate("gitlab", False)


if __name__ == "__main__":
    main()