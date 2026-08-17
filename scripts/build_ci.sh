#!/bin/bash
chmod +x build-go-lib.sh
chmod +x build_client.sh
bash build_client.sh && bash build_apk.sh
