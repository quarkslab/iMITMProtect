#!/bin/bash

cat > ~/Library/LaunchAgents/com.quarkslab.apple.imessages.defense.iMITMProtect.plist << EOT
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.quarkslab.apple.imessages.defense.iMITMProtect</string>
    <key>ProgramArguments</key>
    <array>
        <string>/Applications/iMITMProtect.app/Contents/MacOS/iMITMProtect</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
EOT

open -a $2/iMITMProtect.app
