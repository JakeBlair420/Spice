# this is a fucked up makefile for stage 2 because I suck at building right Makefiles so the Makefile in root is outdated (can only be used to build the app and not stage 2)
cd ../../submodules/libjake/
make PLATFORM=ios
cd ../../src/untether/

xcrun -sdk iphoneos clang -arch arm64 -DUSE_COMMONCRYPTO=1 -I../../submodules/libjake/img4lib/ -I../../submodules/libjake/img4lib/lzfse/src/ -c ../../submodules/libjake/img4lib/lzss.c -o ../../submodules/libjake/img4lib/lzss.o
#vfs_enc.c	vfs_file.c	vfs_img4.c	vfs_lzfse.c	vfs_lzss.c	vfs_mem.c	vfs_sub.c
xcrun -sdk iphoneos clang -arch arm64 -DUSE_COMMONCRYPTO=1 -DDER_MULTIBYTE_TAGS=1 -DDER_TAG_SIZE=8 -I../../submodules/libjake/img4lib/ -I../../submodules/libjake/img4lib/lzfse/src/ -c ../../submodules/libjake/img4lib/libvfs/vfs_enc.c -o ../../submodules/libjake/img4lib/libvfs/vfs_enc.o
xcrun -sdk iphoneos clang -arch arm64 -DUSE_COMMONCRYPTO=1 -DDER_MULTIBYTE_TAGS=1 -DDER_TAG_SIZE=8 -I../../submodules/libjake/img4lib/ -I../../submodules/libjake/img4lib/lzfse/src/ -c ../../submodules/libjake/img4lib/libvfs/vfs_file.c -o ../../submodules/libjake/img4lib/libvfs/vfs_file.o
xcrun -sdk iphoneos clang -arch arm64 -DUSE_COMMONCRYPTO=1 -DDER_MULTIBYTE_TAGS=1 -DDER_TAG_SIZE=8 -I../../submodules/libjake/img4lib/ -I../../submodules/libjake/img4lib/lzfse/src/ -c ../../submodules/libjake/img4lib/libvfs/vfs_img4.c -o ../../submodules/libjake/img4lib/libvfs/vfs_img4.o
xcrun -sdk iphoneos clang -arch arm64 -DUSE_COMMONCRYPTO=1 -DDER_MULTIBYTE_TAGS=1 -DDER_TAG_SIZE=8 -I../../submodules/libjake/img4lib/ -I../../submodules/libjake/img4lib/lzfse/src/ -c ../../submodules/libjake/img4lib/libvfs/vfs_lzfse.c -o ../../submodules/libjake/img4lib/libvfs/vfs_lzfse.o
xcrun -sdk iphoneos clang -arch arm64 -DUSE_COMMONCRYPTO=1 -DDER_MULTIBYTE_TAGS=1 -DDER_TAG_SIZE=8 -I../../submodules/libjake/img4lib/ -I../../submodules/libjake/img4lib/lzfse/src/ -c ../../submodules/libjake/img4lib/libvfs/vfs_lzss.c -o ../../submodules/libjake/img4lib/libvfs/vfs_lzss.o
xcrun -sdk iphoneos clang -arch arm64 -DUSE_COMMONCRYPTO=1 -DDER_MULTIBYTE_TAGS=1 -DDER_TAG_SIZE=8 -I../../submodules/libjake/img4lib/ -I../../submodules/libjake/img4lib/lzfse/src/ -c ../../submodules/libjake/img4lib/libvfs/vfs_mem.c -o ../../submodules/libjake/img4lib/libvfs/vfs_mem.o
xcrun -sdk iphoneos clang -arch arm64 -DUSE_COMMONCRYPTO=1 -DDER_MULTIBYTE_TAGS=1 -DDER_TAG_SIZE=8 -I../../submodules/libjake/img4lib/ -I../../submodules/libjake/img4lib/lzfse/src/ -c ../../submodules/libjake/img4lib/libvfs/vfs_sub.c -o ../../submodules/libjake/img4lib/libvfs/vfs_sub.o

xcrun -sdk iphoneos clang -arch arm64 -DUSE_COMMONCRYPTO=1 -DDER_MULTIBYTE_TAGS=1 -DDER_TAG_SIZE=8 -I../../submodules/libjake/img4lib/ -I../../submodules/libjake/img4lib/libDER/ -c ../../submodules/libjake/img4lib/libDER/DER_Encode.c -o ../../submodules/libjake/img4lib/libDER/DER_Encode.o
xcrun -sdk iphoneos clang -arch arm64 -DUSE_COMMONCRYPTO=1 -DDER_MULTIBYTE_TAGS=1 -DDER_TAG_SIZE=8 -I../../submodules/libjake/img4lib/ -I../../submodules/libjake/img4lib/libDER/ -c ../../submodules/libjake/img4lib/libDER/DER_Decode.c -o ../../submodules/libjake/img4lib/libDER/DER_Decode.o
xcrun -sdk iphoneos clang -arch arm64 -DUSE_COMMONCRYPTO=1 -DDER_MULTIBYTE_TAGS=1 -DDER_TAG_SIZE=8 -I../../submodules/libjake/img4lib/ -I../../submodules/libjake/img4lib/libDER/ -c ../../submodules/libjake/img4lib/libDER/oids.c -o ../../submodules/libjake/img4lib/libDER/oids.o
libtool -o ../../submodules/libjake/img4lib/libimg4.a ../../submodules/libjake/img4lib/lzss.o ../../submodules/libjake/img4lib/libvfs/*.o ../../submodules/libjake/img4lib/libDER/*.o

xcrun -sdk iphoneos clang -arch arm64 ../../submodules/libjake/img4lib/libimg4.a ../../submodules/libjake/lib/libjake.a ../shared/realsym.c generator.m install.m stage1.m racoon_www.m uland_offsetfinder.m a64.c stage2.m -I ../ -I ../../submodules/libjake/src/ -I ../../submodules/libjake/img4lib/libvfs/ -o test -framework Security -framework IOKit -framework CoreFoundation -framework Foundation -L../../submodules/libjake/img4lib/ -L../../submodules/libjake/lib/ && ldid -S../../lailo/lightspeed/Ent.plist test
