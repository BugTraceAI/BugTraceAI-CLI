#!/bin/bash
# Dojo Launcher Script

# 1. Start Dojo Server
python3 xss_dojo_server.py > dojo.log 2>&1 &
DOJO_PID=$!
echo "🥋 Dojo Server started (PID: $DOJO_PID)"
sleep 3 # Wait for startup

# 2. Define Levels
LEVELS=(
    "http://127.0.0.1:5001/level1?q="
    "http://127.0.0.1:5001/level4?q="
    "http://127.0.0.1:5001/level7?q="
    "http://127.0.0.1:5001/level10?q="
)

# 3. Define Clean Parameters
PARAMS=(
    "test"
    "test"
    "test"
    "test"
)

# 4. Run Agent against each level
for i in "${!LEVELS[@]}"; do
    LEVEL_URL="${LEVELS[$i]}${PARAMS[$i]}"
    echo "---------------------------------------------------"
    echo "⚔️  Attacking Level $(($i+1)): $LEVEL_URL"
    echo "---------------------------------------------------"
    
    START_TIME=$(date +%s)
    
    # Run CLI in focused mode using 'python -m bugtrace.cli <URL> --xss --param q'
    # This bypasses the 'scan' subcommand which doesn't exist in the current cli.py structure
    
    python3 -m bugtrace.cli "$LEVEL_URL" --xss --param q
    
    END_TIME=$(date +%s)
    DURATION=$(($END_TIME - $START_TIME))
    
    echo "⏱️  Level $(($i+1)) completed in ${DURATION}s"
done

# 5. Cleanup
kill $DOJO_PID
rm dojo.log
echo "🥋 Dojo Closed."
