#!/usr/bin/env bash
mkdir deploy

set -x

cp target/release/otpcli "deploy/otpcli-$DEPLOY_NAME"
tar -cJf "deploy/otpcli.$DEPLOY_NAME.tar.xz" "deploy/otpcli-$DEPLOY_NAME"