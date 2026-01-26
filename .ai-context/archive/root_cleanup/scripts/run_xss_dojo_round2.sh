#!/bin/bash
# Dojo Launcher Script - Round 2 (Levels 7 & 10 Focus)

# 1. Start Dojo Server
python3 xss_dojo_server.py > dojo.log 2>&1 &
DOJO_PID=$!
echo "🥋 Dojo Server started (PID: $DOJO_PID)"
sleep 3

# 2. Define Difficult Levels
LEVELS=(
    "http://127.0.0.1:5001/level7?q="
    "http://127.0.0.1:5001/level10?q="
)

PARAMS=(
    "test"
    "test"
)

# 3. Run Agent
for i in "${!LEVELS[@]}"; do
    LEVEL_URL="${LEVELS[$i]}${PARAMS[$i]}"
    echo "---------------------------------------------------"
    echo "⚔️  Attacking Level (High Difficulty): $LEVEL_URL"
    echo "---------------------------------------------------"
    
    START_TIME=$(date +%s)
    
    python3 -m bugtrace.cli "$LEVEL_URL" --xss --param q
    
    END_TIME=$(date +%s)
    DURATION=$(($END_TIME - $START_TIME))
    
    echo "⏱️  Level completed in ${DURATION}s"
done

kill $DOJO_PID
rm dojo.log
