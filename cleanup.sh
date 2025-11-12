#!/bin/bash
# Deletes all VPCs recorded in ~/.vpcctl
for file in ~/.vpcctl/*.json; do
    [[ -e "$file" ]] || continue
    vpc_name=$(basename "$file" .json)
    echo "[INFO] Deleting VPC $vpc_name"
    sudo python3 vpcctl.py delete --name "$vpc_name"
done
echo "[INFO] All VPCs deleted."

