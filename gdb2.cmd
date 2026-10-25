set pagination off
set confirm off
set architecture aarch64
target remote 127.0.0.1:1234
break *0xffffffc00875b324
continue
printf "=== BUG HIT ===\n"
info registers pc lr sp x0 x1 x2 x3 x19 x20 x21 x22 x23 x24 x25 x26
printf "--- around ctmr (x22) ---\n"
x/40gx $x22-0x80
printf "--- new (x0) ---\n"
x/12gx $x0-0x10
detach
quit
