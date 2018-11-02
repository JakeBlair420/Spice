TARGET_GUI       = Spice
TARGET_CLI       = spice
PACKAGE          = lol.spyware.spicy
VERSION          = 1.0.0

BIN              = bin
RES              = res
APP              = $(BIN)/Payload/$(TARGET_GUI).app
SRC_GUI          = src/app
SRC_CLI          = src/untether
SRC_ALL          = src/shared
ifdef RELEASE
IPA              = $(TARGET_GUI).ipa
else
IPA              = $(TARGET_GUI)-DEV.ipa
endif
UNTETHER         = lib$(TARGET_CLI).dylib
TRAMP            = trampoline
ICONS           := $(wildcard $(RES)/Icon-*.png)
FILES           := $(TARGET_GUI) Info.plist Base.lproj/LaunchScreen.storyboardc $(ICONS:$(RES)/%=%)
IGCC            ?= xcrun -sdk iphoneos gcc
ARCH_GUI        ?= -arch arm64
ARCH_CLI        ?= -arch armv7 -arch arm64
IGCC_FLAGS      ?= -Wall -O3 -I$(SRC_ALL) -fmodules -framework IOKit $(CFLAGS)
ifdef RELEASE
IGCC_FLAGS      += -DRELEASE=1
endif
IBTOOL          ?= xcrun -sdk iphoneos ibtool
IBTOOL_FLAGS    ?= --output-format human-readable-text --errors --warnings --notices --target-device iphone --target-device ipad $(IBFLAGS)
STRIP           ?= xcrun -sdk iphoneos strip
SIGN            ?= codesign
SIGN_FLAGS      ?= -s -

.PHONY: all ipa untether clean

all: $(IPA) $(UNTETHER) $(TRAMP)

ipa: $(IPA)

untether: $(UNTETHER) $(TRAMP)

$(IPA): $(addprefix $(APP)/, $(FILES))
	cd $(BIN) && zip -x .DS_Store -qr9 ../$@ Payload

$(APP)/$(TARGET_GUI): $(SRC_GUI)/*.m $(SRC_ALL)/*.m | $(APP)
	$(IGCC) $(ARCH_GUI) -o $@ $(IGCC_FLAGS) $^
	$(STRIP) $@

$(APP)/Info.plist: $(RES)/Info.plist | $(APP)
	sed 's/$$(TARGET)/$(TARGET_GUI)/g;s/$$(PACKAGE)/$(PACKAGE)/g;s/$$(VERSION)/$(VERSION)/g' $(RES)/Info.plist > $@

$(APP)/Icon-%.png: $(RES)/$(@F) | $(APP)
	cp $(RES)/$(@F) $@

$(APP)/Base.lproj/%.storyboardc: $(RES)/%.storyboard | $(APP)/Base.lproj
	$(IBTOOL) $(IBTOOL_FLAGS) --compilation-directory $(APP)/Base.lproj $<

$(APP):
	mkdir -p $@

$(APP)/Base.lproj:
	mkdir -p $@

$(UNTETHER): $(SRC_CLI)/*.m $(SRC_ALL)/*.m
	$(IGCC) $(ARCH_CLI) -shared -o $@ $(IGCC_FLAGS) $^
	$(STRIP) -s res/syms.txt $@
	$(SIGN) $(SIGN_FLAGS) $@

$(TRAMP):
	$(IGCC) $(ARCH_CLI) -o $@ -L. -l$(TARGET_CLI) $(IGCC_FLAGS) -xc <<<''
	$(STRIP) $@
	$(SIGN) $(SIGN_FLAGS) $@

clean:
	rm -rf $(BIN)
	rm -f *.ipa *.dylib $(TRAMP)
