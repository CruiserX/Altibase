include ulEnv.mk
include $(DEV_DIR)/alticore.mk

DIRS = msg ulu uln ulc uls ula ulx lib ulp ulm
include $(ALTIDEV_HOME)/makefiles/moddep-common.mk
include moddep.mk

DIRS += cdbc
DIRS += ulsd

ifeq "$(NEED_BUILD_JDBC)" "yes"
	DIRS += $(UL_DIR_JDBC)
endif

all: compile
.PHONY: $(DIRS)
$(DIRS):
	$(MAKE) -C $@ $(SUBDIR_TARGET)

compile:
	@echo "DIRS is ${DIRS}";
	$(MAKE) $(DIRS) SUBDIR_TARGET=

alint:
	$(MAKE) $(DIRS) SUBDIR_TARGET=alint;

clean:
	$(RM) $(TARGET_DIR)/src/ul core .dependency *~
	$(MAKE) $(DIRS) SUBDIR_TARGET=clean
	$(MAKE) -C lib clean
	$(MAKE) clean_ut

build_ut:

clean_ut:

