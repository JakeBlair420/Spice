# Makefile for stage 4 as the Makefile in the root dir is outdated (because I suck at Makefiles)
xcrun -sdk iphoneos clang -arch arm64 -I../../include -larchive -framework IOKit stage4.m ../shared/*.m -framework Foundation -I../  -o stage4 && ~/Downloads/jtool --sign --inplace stage4 && ~/Downloads/jtool --sig stage4
