#make clean
#riscv64-unknown-linux-gnu-gcc -Wall -Werror -fPIC -fno-builtin -DUSE_FREEMEM -I../../lib/edge/include -I ./tmplib -c chacha20_asm.S
make -j8
cp eyrie-rt ../../../build/overlay/root
echo "Runtime copied"
