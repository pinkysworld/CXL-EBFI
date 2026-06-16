#!/usr/bin/env bash
set -euo pipefail

mkdir -p build results

iverilog -g2012 -Wall \
  -s tb_ebfi_metadata_ctrl \
  -o build/tb_ebfi_metadata_ctrl.vvp \
  ebfi_metadata_ctrl.sv tb_ebfi_metadata_ctrl.sv
vvp build/tb_ebfi_metadata_ctrl.vvp | tee results/simulation.log

yosys -s synth.ys | tee results/synthesis.log

echo "RTL simulation and generic synthesis completed."
