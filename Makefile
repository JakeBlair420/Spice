TARGET = Spice
PACKAGE = lol.spyware.spicy
VERSION = 1.0.0

BIN = bin
SRC = src
RES = res
APP = $(BIN)/Payload/$(TARGET).app
ifdef RELEASE
IPA = $(TARGET).ipa
else
IPA = $(TARGET)-INTERNAL.ipa
endif
ICONS := $(wildcard $(RES)/Icon-*.png)
FILES := $(TARGET) Info.plist Base.lproj/LaunchScreen.storyboardc $(ICONS:$(RES)/%=%)
IGCC ?= xcrun -sdk iphoneos gcc
ARCH ?= -arch arm64
IGCC_FLAGS ?= -Wall -O3 -fmodules -framework IOKit $(CFLAGS)
ifdef RELEASE
IGCC_FLAGS += -DRELEASE=1
endif
IBTOOL ?= xcrun -sdk iphoneos ibtool
IBTOOL_FLAGS ?= --output-format human-readable-text --errors --warnings --notices --target-device iphone --target-device ipad $(IBFLAGS)
STRIP ?= xcrun -sdk iphoneos strip

.PHONY: all clean

all: $(IPA)

$(IPA): $(addprefix $(APP)/, $(FILES))
	cd $(BIN) && zip -x .DS_Store -qr9 ../$@ Payload

$(APP)/$(TARGET): $(SRC)/*.m | $(APP)
	$(IGCC) $(ARCH) -o $@ $(IGCC_FLAGS) $^
	$(STRIP) $@

$(APP)/Info.plist: $(RES)/Info.plist | $(APP)
	sed 's/$$(TARGET)/$(TARGET)/g;s/$$(PACKAGE)/$(PACKAGE)/g;s/$$(VERSION)/$(VERSION)/g' $(RES)/Info.plist > $@

$(APP)/Icon-%.png: $(RES)/$(@F) | $(APP)
	cp $(RES)/$(@F) $@

$(APP)/Base.lproj/%.storyboardc: $(RES)/%.storyboard | $(APP)/Base.lproj
	$(IBTOOL) $(IBTOOL_FLAGS) --compilation-directory $(APP)/Base.lproj $<

$(APP):
	mkdir -p $@

$(APP)/%.lproj:
	mkdir -p $@

clean:
	rm -rf $(BIN) *.ipa
