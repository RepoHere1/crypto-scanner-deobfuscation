#!/bin/bash

githubTokens=(
    "YOUR_GITHUB_TOKEN_HERE"
)

topics=(
    "machine-learning" "deep-learning" "llm" "large-language-models" "artificial-intelligence"
    "transformers" "pytorch" "tensorflow" "blockchain" "bitcoin" "ethereum" "crypto"
    "smart-contracts" "solidity" "web3" "reddit-clone" "discourse" "forum" "message-board"
    "compiler" "interpreter" "algorithms"
)

outputFile="github_repositories.csv"
echo "URL,ORG,REPO,TOPIC" > "$outputFile"

totalCount=0
targetCount=7000
tokenIndex=0

echo "Starting API sweep for $targetCount repos..."

for topic in "${topics[@]}"; do
    if [ $totalCount -ge $targetCount ]; then
        break
    fi

    echo ""
    echo "[Topic] Searching: '$topic'"

    for ((page=1; page<=10; page++)); do
        if [ $totalCount -ge $targetCount ]; then
            break
        fi

        rawToken="${githubTokens[$tokenIndex]}"
        tokenIndex=$(( (tokenIndex + 1) % ${#githubTokens[@]} ))

        encodedTopic=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${topic} in:name,description'))")
        uri="https://api.github.com/search/repositories?q=${encodedTopic}&sort=stars&order=desc&per_page=100&page=${page}"

        response=$(curl -s -H "Authorization: Bearer ${rawToken}" \
            -H "Accept: application/vnd.github+json" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            -H "User-Agent: PowerShellScraper" \
            "$uri")

        added=$(echo "$response" | python3 -c "
import json, sys
data = json.load(sys.stdin)
items = data.get('items', [])
if not items:
    print('DONE')
else:
    for item in items:
        print(f\"{item['html_url']},{item['owner']['login']},{item['name']},$topic\")
" 2>/dev/null)

        if [ "$added" = "DONE" ]; then
            echo "   No items returned on page $page for $topic"
            break
        fi

        echo "$added" >> "$outputFile"
        count=$(echo "$added" | wc -l)
        totalCount=$((totalCount + count))
        echo "   Page $page saved. Total progress: $totalCount / $targetCount"
        sleep 2
    done
done

echo ""
echo "Completed."
echo "Total repositories exported: $totalCount"
echo "Output CSV saved to: $(pwd)/$outputFile"