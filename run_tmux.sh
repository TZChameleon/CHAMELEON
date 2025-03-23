#!/bin/bash

tmux new-session -s chameleon 'tmux new-window -n "Secure Wolrd" "nc -kl 54321"; tmux new-window -n "Normal World" "nc -kl 54320"; tmux new-window -n "QEMU Monitor" "make run-only"; tmux attatch -t chameleon'

